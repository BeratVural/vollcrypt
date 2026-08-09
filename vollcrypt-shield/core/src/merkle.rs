use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Result, ShieldError};
use crate::model::{IntegrityEntry, NormalizedPath};

const EMPTY_LEAF_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMPTY-LEAF-v1\0";
const NODE_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-NODE-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NodePosition {
    depth: u16,
    prefix: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityProof {
    pub key: [u8; 32],
    pub leaf_digest: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    entries: BTreeMap<[u8; 32], IntegrityEntry>,
    nodes: HashMap<NodePosition, [u8; 32]>,
    defaults: Vec<[u8; 32]>,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            nodes: HashMap::new(),
            defaults: default_hashes(),
        }
    }

    pub fn from_entries(entries: impl IntoIterator<Item = IntegrityEntry>) -> Result<Self> {
        let mut tree = Self::new();
        for entry in entries {
            tree.upsert(entry)?;
        }
        Ok(tree)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        self.node_hash(0, [0; 32])
    }

    pub fn entries(&self) -> impl Iterator<Item = &IntegrityEntry> {
        self.entries.values()
    }

    pub fn get(&self, path: &NormalizedPath) -> Option<&IntegrityEntry> {
        self.entries.get(&path.key_digest())
    }

    pub fn upsert(&mut self, entry: IntegrityEntry) -> Result<Option<IntegrityEntry>> {
        let key = entry.key_digest();
        if let Some(existing) = self.entries.get(&key)
            && existing.path != entry.path
        {
            return Err(ShieldError::DuplicatePath(entry.path.to_string()));
        }

        let old = self.entries.insert(key, entry.clone());
        self.set_leaf(key, entry.leaf_digest());
        Ok(old)
    }

    pub fn remove(&mut self, path: &NormalizedPath) -> Option<IntegrityEntry> {
        let key = path.key_digest();
        let removed = self.entries.remove(&key)?;
        self.set_leaf(key, self.defaults[256]);
        Some(removed)
    }

    pub fn proof(&self, path: &NormalizedPath) -> Option<IntegrityProof> {
        let key = path.key_digest();
        let entry = self.entries.get(&key)?;
        let mut siblings = Vec::with_capacity(256);
        for depth in (1..=256).rev() {
            let sibling = sibling_prefix(key, depth);
            siblings.push(self.node_hash(depth, sibling));
        }
        Some(IntegrityProof {
            key,
            leaf_digest: entry.leaf_digest(),
            siblings,
        })
    }

    pub fn verify_proof(proof: &IntegrityProof, expected_root: &[u8; 32]) -> bool {
        if proof.siblings.len() != 256 {
            return false;
        }
        let mut current = proof.leaf_digest;
        for (offset, sibling) in proof.siblings.iter().enumerate() {
            let depth = 256 - offset;
            let bit = bit_at(&proof.key, depth - 1);
            current = if bit == 0 {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
        }
        current.ct_eq(expected_root).into()
    }

    fn set_leaf(&mut self, key: [u8; 32], leaf_hash: [u8; 32]) {
        self.store_node(256, key, leaf_hash);
        let mut current = leaf_hash;

        for depth in (1..=256).rev() {
            let sibling_prefix = sibling_prefix(key, depth);
            let sibling = self.node_hash(depth, sibling_prefix);
            let bit = bit_at(&key, depth - 1);
            current = if bit == 0 {
                hash_node(&current, &sibling)
            } else {
                hash_node(&sibling, &current)
            };
            self.store_node(depth - 1, masked_prefix(key, depth - 1), current);
        }
    }

    fn node_hash(&self, depth: usize, prefix: [u8; 32]) -> [u8; 32] {
        self.nodes
            .get(&NodePosition {
                depth: depth as u16,
                prefix: masked_prefix(prefix, depth),
            })
            .copied()
            .unwrap_or(self.defaults[depth])
    }

    fn store_node(&mut self, depth: usize, prefix: [u8; 32], hash: [u8; 32]) {
        let position = NodePosition {
            depth: depth as u16,
            prefix: masked_prefix(prefix, depth),
        };
        if hash == self.defaults[depth] {
            self.nodes.remove(&position);
        } else {
            self.nodes.insert(position, hash);
        }
    }
}

fn default_hashes() -> Vec<[u8; 32]> {
    let mut defaults = vec![[0; 32]; 257];
    defaults[256] = Sha256::digest(EMPTY_LEAF_DOMAIN).into();
    for depth in (0..256).rev() {
        defaults[depth] = hash_node(&defaults[depth + 1], &defaults[depth + 1]);
    }
    defaults
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn bit_at(key: &[u8; 32], bit: usize) -> u8 {
    let byte = bit / 8;
    let offset = 7 - (bit % 8);
    (key[byte] >> offset) & 1
}

fn masked_prefix(mut key: [u8; 32], depth: usize) -> [u8; 32] {
    if depth >= 256 {
        return key;
    }
    let whole_bytes = depth / 8;
    let remaining_bits = depth % 8;
    if remaining_bits == 0 {
        key[whole_bytes..].fill(0);
    } else {
        key[whole_bytes] &= 0xff << (8 - remaining_bits);
        key[whole_bytes + 1..].fill(0);
    }
    key
}

fn sibling_prefix(key: [u8; 32], depth: usize) -> [u8; 32] {
    let mut sibling = masked_prefix(key, depth);
    let bit = depth - 1;
    let byte = bit / 8;
    let offset = 7 - (bit % 8);
    sibling[byte] ^= 1 << offset;
    sibling
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntryKind;

    fn entry(path: &str, marker: u8) -> IntegrityEntry {
        IntegrityEntry::new(
            NormalizedPath::new(path).unwrap(),
            EntryKind::File,
            [marker; 32],
            [marker.wrapping_add(1); 32],
            marker as u64,
        )
    }

    #[test]
    fn insertion_order_does_not_change_root() {
        let a = SparseMerkleTree::from_entries([entry("a", 1), entry("b", 2)]).unwrap();
        let b = SparseMerkleTree::from_entries([entry("b", 2), entry("a", 1)]).unwrap();
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn update_and_remove_are_incremental_and_reversible() {
        let mut tree = SparseMerkleTree::from_entries([entry("a", 1), entry("b", 2)]).unwrap();
        let original = tree.root();
        tree.upsert(entry("a", 9)).unwrap();
        assert_ne!(tree.root(), original);
        tree.upsert(entry("a", 1)).unwrap();
        assert_eq!(tree.root(), original);
        tree.remove(&NormalizedPath::new("b").unwrap());
        assert_ne!(tree.root(), original);
    }

    #[test]
    fn proof_binds_path_and_leaf() {
        let tree = SparseMerkleTree::from_entries([entry("a", 1), entry("b", 2)]).unwrap();
        let mut proof = tree.proof(&NormalizedPath::new("a").unwrap()).unwrap();
        assert!(SparseMerkleTree::verify_proof(&proof, &tree.root()));
        proof.leaf_digest[0] ^= 1;
        assert!(!SparseMerkleTree::verify_proof(&proof, &tree.root()));
    }
}

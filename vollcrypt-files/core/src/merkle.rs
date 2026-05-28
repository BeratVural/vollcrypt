use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::chunk::ChunkEnvelope;
use crate::error::FileFormatError;

/// Supported Merkle tree hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

/// Computes the SHA-256 hash of a chunk envelope.
///
/// The hash is computed over the entire serialized binary representation of the envelope.
pub fn chunk_leaf_hash(envelope: &ChunkEnvelope) -> [u8; 32] {
    chunk_leaf_hash_with_algo(envelope, HashAlgorithm::Sha256)
}

/// Computes the SHA-256 hash of a chunk's metadata (index, iv, tag) without allocating.
pub fn chunk_leaf_hash_raw(chunk_index: u32, iv: &[u8; 12], tag: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(chunk_index.to_be_bytes());
    hasher.update(iv);
    hasher.update(tag);
    hasher.finalize().into()
}

/// Computes the hash of a chunk envelope using the specified hash algorithm.
///
/// The hash is computed over: chunk_index (4B BE) || iv (12B) || tag (16B)
pub fn chunk_leaf_hash_with_algo(envelope: &ChunkEnvelope, algo: HashAlgorithm) -> [u8; 32] {
    match algo {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(envelope.chunk_index.to_be_bytes());
            hasher.update(envelope.iv);
            hasher.update(envelope.tag);
            hasher.finalize().into()
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&envelope.chunk_index.to_be_bytes());
            hasher.update(&envelope.iv);
            hasher.update(&envelope.tag);
            *hasher.finalize().as_bytes()
        }
    }
}

/// A binary Merkle Tree built using SHA-256.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Builds a Merkle Tree from a list of leaves.
    ///
    /// If the list of leaves is empty, the root is `[0u8; 32]`.
    /// If there is only one leaf, the root is that leaf.
    /// If a level has an odd number of nodes, the last node is duplicated during hashing.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        Self::from_leaves_with_algo(leaves, HashAlgorithm::Sha256)
    }

    /// Builds a Merkle Tree from a list of leaves using the specified hash algorithm.
    pub fn from_leaves_with_algo(leaves: Vec<[u8; 32]>, algo: HashAlgorithm) -> Self {
        let mut levels = Vec::new();

        if leaves.is_empty() {
            levels.push(vec![[0u8; 32]]);
            return MerkleTree { levels };
        }

        let mut current_level = leaves;
        levels.push(current_level.clone());

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };

                let parent = match algo {
                    HashAlgorithm::Sha256 => {
                        let mut hasher = Sha256::new();
                        hasher.update(left);
                        hasher.update(right);
                        let mut parent = [0u8; 32];
                        parent.copy_from_slice(&hasher.finalize());
                        parent
                    }
                    HashAlgorithm::Blake3 => {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(&left);
                        hasher.update(&right);
                        *hasher.finalize().as_bytes()
                    }
                };
                next_level.push(parent);
            }
            current_level = next_level;
            levels.push(current_level.clone());
        }

        MerkleTree { levels }
    }

    /// Returns the root hash of the Merkle Tree.
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|lvl| lvl.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Generates a Merkle proof (sibling hashes from leaf to root) for a given leaf index.
    pub fn proof(&self, mut leaf_index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        if self.levels.is_empty() || self.levels[0].is_empty() || leaf_index >= self.levels[0].len()
        {
            return proof;
        }

        for level_idx in 0..self.levels.len() - 1 {
            let level = &self.levels[level_idx];
            let sibling_index = if leaf_index.is_multiple_of(2) {
                if leaf_index + 1 < level.len() {
                    leaf_index + 1
                } else {
                    leaf_index
                }
            } else {
                leaf_index - 1
            };
            proof.push(level[sibling_index]);
            leaf_index /= 2;
        }

        proof
    }
}

/// Helper function to calculate the expected proof length for a given number of leaves.
pub fn expected_proof_len(total_leaves: usize) -> usize {
    if total_leaves <= 1 {
        0
    } else {
        let mut len = 0;
        let mut cur = total_leaves;
        while cur > 1 {
            len += 1;
            cur = cur.div_ceil(2);
        }
        len
    }
}

/// Verifies a proof length. Returns `Err` if the proof length is incorrect.
pub fn check_proof_length(total_leaves: usize, proof_len: usize) -> Result<(), FileFormatError> {
    let expected = expected_proof_len(total_leaves);
    if proof_len != expected {
        return Err(FileFormatError::InvalidProofLength {
            expected,
            got: proof_len,
        });
    }
    Ok(())
}

/// Verifies a Merkle proof against an expected root hash.
///
/// Comparison of the final root hash is performed in constant-time.
pub fn verify_merkle_proof(
    leaf: &[u8; 32],
    leaf_index: usize,
    total_leaves: usize,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    verify_merkle_proof_with_algo(
        leaf,
        leaf_index,
        total_leaves,
        proof,
        expected_root,
        HashAlgorithm::Sha256,
    )
}

/// Verifies a Merkle proof against an expected root hash using the specified hash algorithm.
///
/// Comparison of the final root hash is performed in constant-time.
pub fn verify_merkle_proof_with_algo(
    leaf: &[u8; 32],
    leaf_index: usize,
    total_leaves: usize,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
    algo: HashAlgorithm,
) -> bool {
    if leaf_index >= total_leaves {
        return false;
    }

    // Verify proof length first
    if check_proof_length(total_leaves, proof.len()).is_err() {
        return false;
    }

    let mut current_hash = *leaf;
    let mut current_idx = leaf_index;
    let mut current_total = total_leaves;

    for sibling in proof {
        if current_total <= 1 {
            return false;
        }

        current_hash = match algo {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                if current_idx.is_multiple_of(2) {
                    hasher.update(current_hash);
                    hasher.update(sibling);
                } else {
                    hasher.update(sibling);
                    hasher.update(current_hash);
                }
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&hasher.finalize());
                parent
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                if current_idx.is_multiple_of(2) {
                    hasher.update(&current_hash);
                    hasher.update(sibling);
                } else {
                    hasher.update(sibling);
                    hasher.update(&current_hash);
                }
                *hasher.finalize().as_bytes()
            }
        };

        current_idx /= 2;
        current_total = current_total.div_ceil(2);
    }

    if current_total != 1 {
        return false;
    }

    // Constant-time comparison
    current_hash.ct_eq(expected_root).into()
}

/// An incremental (streaming) Merkle Tree accumulator that computes the root hash
/// on the fly with O(log N) memory complexity.
#[derive(Debug, Clone)]
pub struct StreamingMerkle {
    active_branches: Vec<Option<[u8; 32]>>,
    total_leaves: usize,
    algo: HashAlgorithm,
}

impl StreamingMerkle {
    /// Creates a new `StreamingMerkle` accumulator using SHA-256 as the default hash algorithm.
    pub fn new() -> Self {
        Self::new_with_algo(HashAlgorithm::Sha256)
    }

    /// Creates a new `StreamingMerkle` accumulator using the specified hash algorithm.
    pub fn new_with_algo(algo: HashAlgorithm) -> Self {
        Self {
            active_branches: Vec::new(),
            total_leaves: 0,
            algo,
        }
    }

    /// Pushes a new leaf hash into the streaming accumulator.
    ///
    /// This merges left and right siblings bottom-up as perfect binary subtrees are filled,
    /// keeping only log(N) active branches in memory.
    pub fn push_leaf(&mut self, leaf: [u8; 32]) {
        let mut current = leaf;
        let mut level = 0;

        while level < self.active_branches.len() {
            if let Some(sibling) = self.active_branches[level].take() {
                // Sibling on the left (previously stored), current on the right.
                current = self.hash_nodes(&sibling, &current);
                level += 1;
            } else {
                self.active_branches[level] = Some(current);
                self.total_leaves += 1;
                return;
            }
        }

        self.active_branches.push(Some(current));
        self.total_leaves += 1;
    }

    /// Finalizes the Merkle tree accumulator and returns the final Merkle root hash.
    ///
    /// This folds the remaining active branches bottom-up, duplicating the rightmost node
    /// at any level where the number of elements is odd and greater than 1 (to replicate
    /// the static Merkle tree logic).
    pub fn finalize(self) -> [u8; 32] {
        if self.total_leaves == 0 {
            return [0u8; 32];
        }

        let mut current = None;
        let mut total_leaves_at_level = self.total_leaves;

        for level in 0..self.active_branches.len() {
            let active = self.active_branches[level];
            let is_odd = total_leaves_at_level % 2 != 0;

            match (active, current) {
                (Some(act_val), Some(cur_val)) => {
                    // Both exist. Merge them bottom-up.
                    current = Some(self.hash_nodes(&act_val, &cur_val));
                }
                (Some(act_val), None) => {
                    if is_odd && total_leaves_at_level > 1 {
                        // Duplicate rightmost leaf/subtree root
                        current = Some(self.hash_nodes(&act_val, &act_val));
                    } else {
                        current = Some(act_val);
                    }
                }
                (None, Some(cur_val)) => {
                    if is_odd && total_leaves_at_level > 1 {
                        // Duplicate carry-over
                        current = Some(self.hash_nodes(&cur_val, &cur_val));
                    } else {
                        current = Some(cur_val);
                    }
                }
                (None, None) => {}
            }

            total_leaves_at_level = total_leaves_at_level.div_ceil(2);
        }

        current.unwrap_or([0u8; 32])
    }

    fn hash_nodes(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        match self.algo {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&hasher.finalize());
                parent
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(left);
                hasher.update(right);
                *hasher.finalize().as_bytes()
            }
        }
    }
}

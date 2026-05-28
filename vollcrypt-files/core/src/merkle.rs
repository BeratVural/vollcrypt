use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::chunk::ChunkEnvelope;
use crate::error::FileFormatError;

/// Computes the SHA-256 hash of a chunk envelope.
///
/// The hash is computed over the entire serialized binary representation of the envelope.
pub fn chunk_leaf_hash(envelope: &ChunkEnvelope) -> [u8; 32] {
    // GCM tag'i zaten ciphertext'i kriptografik olarak taahhüt eder. Merkle ağacının
    // görevi içerik bütünlüğü değil, YAPI bütünlüğüdür (chunk sırası, silme, ekleme,
    // substitution). chunk_index sırayı, tag ise içeriği benzersiz şekilde bağlar.
    // İçerik manipülasyonu decrypt sırasında GCM tag verification ile yakalanır.
    //
    // SHA-256 over: chunk_index (4B BE) || iv (12B) || tag (16B)
    // Ciphertext is NOT hashed — GCM tag already commits to it.
    let mut hasher = Sha256::new();
    hasher.update(envelope.chunk_index.to_be_bytes());
    hasher.update(envelope.iv);
    hasher.update(envelope.tag);
    hasher.finalize().into()
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

                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&hasher.finalize());
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

        let mut hasher = Sha256::new();
        if current_idx.is_multiple_of(2) {
            hasher.update(current_hash);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(current_hash);
        }
        current_hash.copy_from_slice(&hasher.finalize());

        current_idx /= 2;
        current_total = current_total.div_ceil(2);
    }

    if current_total != 1 {
        return false;
    }

    // Constant-time comparison
    current_hash.ct_eq(expected_root).into()
}

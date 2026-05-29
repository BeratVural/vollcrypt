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

/// Detects if the current CPU supports SHA extensions (SHA-NI) at runtime.
pub fn detect_sha_ni_support() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("sha")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("sha2")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Chooses the optimal hash algorithm.
/// Always returns SHA-256 as it is the regulated standard, using SHA-NI when available.
pub fn default_hash_algorithm() -> HashAlgorithm {
    HashAlgorithm::Sha256
}

/// Computes the SHA-256 hash of a chunk envelope.
///
/// The hash is computed over the entire serialized binary representation of the envelope.
pub fn chunk_leaf_hash(envelope: &ChunkEnvelope) -> [u8; 32] {
    chunk_leaf_hash_with_algo(envelope, HashAlgorithm::Sha256)
}

/// Computes the SHA-256 hash of a chunk's metadata (index, iv, tag) without allocating.
pub fn chunk_leaf_hash_raw(chunk_index: u32, iv: &[u8; 12], tag: &[u8; 16]) -> [u8; 32] {
    chunk_leaf_hash_raw_with_algo(chunk_index, iv, tag, HashAlgorithm::Sha256)
}

/// Computes the hash of a chunk's metadata (index, iv, tag) without allocating using the specified hash algorithm.
/// Prepend 0x00 domain separator for leaves.
pub fn chunk_leaf_hash_raw_with_algo(
    chunk_index: u32,
    iv: &[u8; 12],
    tag: &[u8; 16],
    algo: HashAlgorithm,
) -> [u8; 32] {
    match algo {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&[0x00]); // leaf prefix
            hasher.update(chunk_index.to_be_bytes());
            hasher.update(iv);
            hasher.update(tag);
            hasher.finalize().into()
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&[0x00]); // leaf prefix
            hasher.update(&chunk_index.to_be_bytes());
            hasher.update(iv);
            hasher.update(tag);
            *hasher.finalize().as_bytes()
        }
    }
}

/// Computes the hash of a chunk envelope using the specified hash algorithm.
/// Prepend 0x00 domain separator for leaves.
pub fn chunk_leaf_hash_with_algo(envelope: &ChunkEnvelope, algo: HashAlgorithm) -> [u8; 32] {
    chunk_leaf_hash_raw_with_algo(envelope.chunk_index, &envelope.iv, &envelope.tag, algo)
}

/// Helper to bind Merkle tree root with leaf count (prevents duplicate-node collisions)
pub fn bind_root_with_length(
    tree_root: &[u8; 32],
    leaf_count: usize,
    algo: HashAlgorithm,
) -> [u8; 32] {
    match algo {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&[0x02]); // final binding prefix
            hasher.update(&(leaf_count as u64).to_be_bytes());
            hasher.update(tree_root);
            hasher.finalize().into()
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&[0x02]); // final binding prefix
            hasher.update(&(leaf_count as u64).to_be_bytes());
            hasher.update(tree_root);
            *hasher.finalize().as_bytes()
        }
    }
}

/// Helper to calculate expected proof length for a specific leaf index under promotion logic
pub fn expected_proof_len_for_leaf(mut leaf_index: usize, mut total_leaves: usize) -> usize {
    let mut len = 0;
    while total_leaves > 1 {
        let is_odd = total_leaves % 2 != 0;
        let is_last = leaf_index == total_leaves - 1;
        if !(is_odd && is_last) {
            len += 1;
        }
        leaf_index /= 2;
        total_leaves = total_leaves.div_ceil(2);
    }
    len
}

/// A binary Merkle Tree built using SHA-256/Blake3 with node promotion and domain separation.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
    algo: HashAlgorithm,
}

impl MerkleTree {
    /// Builds a Merkle Tree from a list of leaves.
    ///
    /// If the list of leaves is empty, the root is `[0u8; 32]`.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        Self::from_leaves_with_algo(leaves, HashAlgorithm::Sha256)
    }

    /// Builds a Merkle Tree from a list of leaves using the specified hash algorithm.
    pub fn from_leaves_with_algo(leaves: Vec<[u8; 32]>, algo: HashAlgorithm) -> Self {
        let mut levels = Vec::new();

        if leaves.is_empty() {
            return MerkleTree { levels, algo };
        }

        let mut current_level = leaves;
        levels.push(current_level.clone());

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            let mut chunks = current_level.chunks(2);
            while let Some(chunk) = chunks.next() {
                if chunk.len() == 2 {
                    let left = chunk[0];
                    let right = chunk[1];
                    let parent = match algo {
                        HashAlgorithm::Sha256 => {
                            let mut hasher = Sha256::new();
                            hasher.update(&[0x01]); // internal node prefix
                            hasher.update(left);
                            hasher.update(right);
                            let mut parent = [0u8; 32];
                            parent.copy_from_slice(&hasher.finalize());
                            parent
                        }
                        HashAlgorithm::Blake3 => {
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(&[0x01]); // internal node prefix
                            hasher.update(&left);
                            hasher.update(&right);
                            *hasher.finalize().as_bytes()
                        }
                    };
                    next_level.push(parent);
                } else {
                    // Carry-over (promote) the odd node to the next level unchanged (prevents collision)
                    next_level.push(chunk[0]);
                }
            }
            current_level = next_level;
            levels.push(current_level.clone());
        }

        MerkleTree { levels, algo }
    }

    /// Returns the root hash of the Merkle Tree.
    pub fn root(&self) -> [u8; 32] {
        let tree_root = self
            .levels
            .last()
            .and_then(|lvl| lvl.first())
            .copied()
            .unwrap_or([0u8; 32]);
        if self.levels.is_empty() || self.levels[0].is_empty() {
            tree_root
        } else {
            bind_root_with_length(&tree_root, self.levels[0].len(), self.algo)
        }
    }

    /// Generates a Merkle proof (sibling hashes from leaf to root) for a given leaf index.
    pub fn proof(&self, leaf_index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        if self.levels.is_empty() || self.levels[0].is_empty() || leaf_index >= self.levels[0].len()
        {
            return proof;
        }

        let mut current_idx = leaf_index;
        let mut current_total = self.levels[0].len();

        for level_idx in 0..self.levels.len() - 1 {
            let level = &self.levels[level_idx];
            let is_odd = current_total % 2 != 0;
            let is_last = current_idx == current_total - 1;

            if is_odd && is_last {
                // Promoted node has no sibling at this level
            } else {
                let sibling_index = if current_idx % 2 == 0 {
                    current_idx + 1
                } else {
                    current_idx - 1
                };
                proof.push(level[sibling_index]);
            }
            current_idx /= 2;
            current_total = current_total.div_ceil(2);
        }

        proof
    }
}

/// Helper function to calculate the expected proof length for a given number of leaves.
/// Deprecated in favor of expected_proof_len_for_leaf but kept for backward compatibility.
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

    let expected_len = expected_proof_len_for_leaf(leaf_index, total_leaves);
    if proof.len() != expected_len {
        return false;
    }

    let mut current_hash = *leaf;
    let mut current_idx = leaf_index;
    let mut current_total = total_leaves;
    let mut proof_iter = proof.iter();

    while current_total > 1 {
        let is_odd = current_total % 2 != 0;
        let is_last = current_idx == current_total - 1;

        if is_odd && is_last {
            // Promoted node, carried over unchanged without sibling
        } else {
            let sibling = match proof_iter.next() {
                Some(s) => s,
                None => return false,
            };
            current_hash = match algo {
                HashAlgorithm::Sha256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(&[0x01]); // internal node prefix
                    if current_idx % 2 == 0 {
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
                    hasher.update(&[0x01]); // internal node prefix
                    if current_idx % 2 == 0 {
                        hasher.update(&current_hash);
                        hasher.update(sibling);
                    } else {
                        hasher.update(sibling);
                        hasher.update(&current_hash);
                    }
                    *hasher.finalize().as_bytes()
                }
            };
        }

        current_idx /= 2;
        current_total = current_total.div_ceil(2);
    }

    let final_computed_root = bind_root_with_length(&current_hash, total_leaves, algo);

    // Constant-time comparison
    final_computed_root.ct_eq(expected_root).into()
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
    /// This folds the remaining active branches bottom-up with node promotion.
    pub fn finalize(self) -> [u8; 32] {
        if self.total_leaves == 0 {
            return [0u8; 32];
        }

        let mut current = None;
        let mut total_leaves_at_level = self.total_leaves;

        for level in 0..self.active_branches.len() {
            let active = self.active_branches[level];

            match (active, current) {
                (Some(act_val), Some(cur_val)) => {
                    current = Some(self.hash_nodes(&act_val, &cur_val));
                }
                (Some(act_val), None) => {
                    // Carry-over (promote)
                    current = Some(act_val);
                }
                (None, Some(cur_val)) => {
                    // Carry-over (promote)
                    current = Some(cur_val);
                }
                (None, None) => {}
            }

            total_leaves_at_level = total_leaves_at_level.div_ceil(2);
        }

        let tree_root = current.unwrap_or([0u8; 32]);
        bind_root_with_length(&tree_root, self.total_leaves, self.algo)
    }

    fn hash_nodes(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        match self.algo {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&[0x01]); // internal node prefix
                hasher.update(left);
                hasher.update(right);
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&hasher.finalize());
                parent
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&[0x01]); // internal node prefix
                hasher.update(left);
                hasher.update(right);
                *hasher.finalize().as_bytes()
            }
        }
    }
}

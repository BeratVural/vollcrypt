use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use vollcrypt_files_core::{chunk_leaf_hash, verify_merkle_proof, ChunkEnvelope, MerkleTree};

fn hash_two(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[test]
fn single_leaf_root_is_leaf() {
    let leaf = [0xAA; 32];
    let tree = MerkleTree::from_leaves(vec![leaf]);
    let expected = vollcrypt_files_core::bind_root_with_length(
        &leaf,
        1,
        vollcrypt_files_core::HashAlgorithm::Sha256,
    );
    assert_eq!(tree.root(), expected);
}

#[test]
fn two_leaves_root() {
    let leaf1 = [0x01; 32];
    let leaf2 = [0x02; 32];

    let mut hasher = Sha256::new();
    hasher.update(&[0x01]);
    hasher.update(&leaf1);
    hasher.update(&leaf2);
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&hasher.finalize());
    let expected = vollcrypt_files_core::bind_root_with_length(
        &parent,
        2,
        vollcrypt_files_core::HashAlgorithm::Sha256,
    );

    let tree = MerkleTree::from_leaves(vec![leaf1, leaf2]);
    assert_eq!(tree.root(), expected);
}

#[test]
fn odd_leaves_duplication() {
    // 3 leaves: L0, L1, L2
    // Level 0: [L0, L1, L2]
    // Level 1: [P0 = Hash(0x01 || L0 || L1), P1 = L2 (promoted)]
    // Level 2: [R = Hash(0x01 || P0 || P1)]
    let l0 = [0x0A; 32];
    let l1 = [0x0B; 32];
    let l2 = [0x0C; 32];

    let mut hasher = Sha256::new();
    hasher.update(&[0x01]);
    hasher.update(&l0);
    hasher.update(&l1);
    let mut p0 = [0u8; 32];
    p0.copy_from_slice(&hasher.finalize());

    let p1 = l2; // Promoted, not duplicated

    let mut hasher = Sha256::new();
    hasher.update(&[0x01]);
    hasher.update(&p0);
    hasher.update(&p1);
    let mut r = [0u8; 32];
    r.copy_from_slice(&hasher.finalize());

    let expected_root = vollcrypt_files_core::bind_root_with_length(
        &r,
        3,
        vollcrypt_files_core::HashAlgorithm::Sha256,
    );

    let tree = MerkleTree::from_leaves(vec![l0, l1, l2]);
    assert_eq!(tree.root(), expected_root);
}

#[test]
fn proof_verifies() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
    let tree = MerkleTree::from_leaves(leaves.clone());
    let root = tree.root();

    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof(i);
        assert_eq!(proof.len(), 3); // 2^3 = 8
        assert!(verify_merkle_proof(leaf, i, 8, &proof, &root));
    }
}

#[test]
fn proof_fails_with_wrong_leaf() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
    let tree = MerkleTree::from_leaves(leaves.clone());
    let root = tree.root();

    let proof = tree.proof(3);
    let wrong_leaf = [0xFF; 32];
    assert!(!verify_merkle_proof(&wrong_leaf, 3, 8, &proof, &root));
}

#[test]
fn proof_fails_with_wrong_root() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
    let tree = MerkleTree::from_leaves(leaves.clone());
    let wrong_root = [0xFF; 32];

    let proof = tree.proof(3);
    assert!(!verify_merkle_proof(&leaves[3], 3, 8, &proof, &wrong_root));
}

#[test]
fn proof_fails_with_tampered_proof() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
    let tree = MerkleTree::from_leaves(leaves.clone());
    let root = tree.root();

    let mut proof = tree.proof(3);
    // Tamper one hash in the proof
    proof[1][0] ^= 1;

    assert!(!verify_merkle_proof(&leaves[3], 3, 8, &proof, &root));
}

#[test]
fn large_tree_1000_leaves() {
    let mut rng = StdRng::seed_from_u64(12345);
    let mut leaves = Vec::new();
    for _ in 0..1000 {
        let mut leaf = [0u8; 32];
        rng.fill(&mut leaf);
        leaves.push(leaf);
    }

    let tree = MerkleTree::from_leaves(leaves.clone());
    let root = tree.root();

    // Verify proof for 10 random leaves
    for _ in 0..10 {
        let leaf_idx = rng.gen_range(0..1000);
        let proof = tree.proof(leaf_idx);
        assert!(verify_merkle_proof(
            &leaves[leaf_idx],
            leaf_idx,
            1000,
            &proof,
            &root
        ));
    }
}

#[test]
fn leaf_hash_ignores_ciphertext() {
    let env1 = ChunkEnvelope {
        chunk_index: 42,
        iv: [0xAA; 12],
        ciphertext: vec![0x11, 0x22, 0x33],
        tag: [0xBB; 16],
    };
    let env2 = ChunkEnvelope {
        chunk_index: 42,
        iv: [0xAA; 12],
        ciphertext: vec![0x99, 0x88, 0x77, 0x66],
        tag: [0xBB; 16],
    };
    assert_eq!(chunk_leaf_hash(&env1), chunk_leaf_hash(&env2));
}

#[test]
fn leaf_hash_changes_with_index() {
    let env1 = ChunkEnvelope {
        chunk_index: 42,
        iv: [0xAA; 12],
        ciphertext: vec![0x11, 0x22, 0x33],
        tag: [0xBB; 16],
    };
    let env2 = ChunkEnvelope {
        chunk_index: 43,
        iv: [0xAA; 12],
        ciphertext: vec![0x11, 0x22, 0x33],
        tag: [0xBB; 16],
    };
    assert_ne!(chunk_leaf_hash(&env1), chunk_leaf_hash(&env2));
}

#[test]
fn leaf_hash_changes_with_tag() {
    let env1 = ChunkEnvelope {
        chunk_index: 42,
        iv: [0xAA; 12],
        ciphertext: vec![0x11, 0x22, 0x33],
        tag: [0xBB; 16],
    };
    let mut env2 = env1.clone();
    env2.tag[0] ^= 1;
    assert_ne!(chunk_leaf_hash(&env1), chunk_leaf_hash(&env2));
}

#[test]
fn test_blake3_merkle_tree() {
    use vollcrypt_files_core::HashAlgorithm;

    let env = ChunkEnvelope {
        chunk_index: 0,
        iv: [0xAA; 12],
        ciphertext: vec![0x11, 0x22, 0x33],
        tag: [0xBB; 16],
    };

    let leaf = vollcrypt_files_core::chunk_leaf_hash_with_algo(&env, HashAlgorithm::Blake3);
    assert_ne!(leaf, [0u8; 32]);

    let leaves = vec![leaf, leaf, leaf];
    let tree = MerkleTree::from_leaves_with_algo(leaves.clone(), HashAlgorithm::Blake3);
    let root = tree.root();
    assert_ne!(root, [0u8; 32]);
    assert_ne!(root, leaf);

    let proof = tree.proof(0);
    assert_eq!(proof.len(), 2);

    let is_valid = vollcrypt_files_core::verify_merkle_proof_with_algo(
        &leaf,
        0,
        3,
        &proof,
        &root,
        HashAlgorithm::Blake3,
    );
    assert!(is_valid);
}

#[test]
fn test_streaming_merkle_differential() {
    use vollcrypt_files_core::{HashAlgorithm, StreamingMerkle};

    for algo in &[HashAlgorithm::Sha256, HashAlgorithm::Blake3] {
        let counts = [0, 1, 2, 3, 4, 5, 8, 15, 16, 32, 100, 1000];
        for &count in &counts {
            let mut leaves = Vec::new();
            for i in 0..count {
                let mut leaf = [0u8; 32];
                leaf[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                leaves.push(leaf);
            }

            // Static tree
            let static_tree = MerkleTree::from_leaves_with_algo(leaves.clone(), *algo);
            let static_root = static_tree.root();

            // Streaming tree
            let mut streaming = StreamingMerkle::new_with_algo(*algo);
            for leaf in leaves {
                streaming.push_leaf(leaf);
            }
            let streaming_root = streaming.finalize();

            assert_eq!(
                static_root, streaming_root,
                "Merkle root mismatch for count = {} with algo = {:?}",
                count, algo
            );
        }
    }
}

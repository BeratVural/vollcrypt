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
    assert_eq!(tree.root(), leaf);
}

#[test]
fn two_leaves_root() {
    let leaf1 = [0x01; 32];
    let leaf2 = [0x02; 32];
    let expected = hash_two(&leaf1, &leaf2);

    let tree = MerkleTree::from_leaves(vec![leaf1, leaf2]);
    assert_eq!(tree.root(), expected);
}

#[test]
fn odd_leaves_duplication() {
    // 3 leaves: L0, L1, L2
    // Level 0: [L0, L1, L2]
    // Level 1: [P0 = Hash(L0||L1), P1 = Hash(L2||L2)]
    // Level 2: [R = Hash(P0||P1)]
    let l0 = [0x0A; 32];
    let l1 = [0x0B; 32];
    let l2 = [0x0C; 32];

    let p0 = hash_two(&l0, &l1);
    let p1 = hash_two(&l2, &l2);
    let expected_root = hash_two(&p0, &p1);

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

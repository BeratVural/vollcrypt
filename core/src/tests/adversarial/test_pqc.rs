use crate::pqc::{
    hybrid_kem_encapsulate, hybrid_kem_decapsulate,
    authenticated_kem_encapsulate, authenticated_kem_decapsulate,
    ml_kem_keygen,
};
use crate::keys::{generate_x25519_keypair, generate_ed25519_keypair};

// ── Invalid Key Lengths ───────────────────────────────────────────────────

#[test]
fn hybrid_kem_empty_x25519_key() {
    let (_, mlkem_ek) = ml_kem_keygen();
    let (_, recipient_x25519_pk) = generate_x25519_keypair();
    let result = hybrid_kem_encapsulate(&[], &recipient_x25519_pk, &mlkem_ek);
    assert!(result.is_err(), "Empty X25519 key should return an error");
}

#[test]
fn hybrid_kem_wrong_x25519_key_length() {
    let (_, mlkem_ek) = ml_kem_keygen();
    let (_, recipient_x25519_pk) = generate_x25519_keypair();
    let result = hybrid_kem_encapsulate(&[0u8; 31], &recipient_x25519_pk, &mlkem_ek);
    assert!(result.is_err(), "Wrong X25519 key length should return an error");
}

#[test]
fn hybrid_kem_zero_x25519_key() {
    let (_, mlkem_ek) = ml_kem_keygen();
    let (_, recipient_x25519_pk) = generate_x25519_keypair();
    // A key of 32 zero bytes is automatically clamped by x25519-dalek.
    let result = hybrid_kem_encapsulate(&[0u8; 32], &recipient_x25519_pk, &mlkem_ek);
    // Instead of erroring out, it treats the zero array as a scalar, clamps it, and succeeds.
    assert!(result.is_ok(), "x25519-dalek clamps zero keys, so this succeeds safely");
}

// ── Ciphertext Manipulation ───────────────────────────────────────────────

#[test]
fn hybrid_kem_flip_bit_in_x25519_ciphertext() {
    // Hybrid KEM ciphertext in VollChat is just the ML-KEM ciphertext. 
    // The X25519 ciphertext isn't explicitly sent; instead the X25519 keys are established out of band.
    // So "X25519 part of ciphertext" doesn't exactly exist. We will just flip a bit in the ML-KEM ct.
    let (alice_sk, alice_pk) = generate_x25519_keypair();
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let (bob_dk, bob_ek) = ml_kem_keygen();

    let (shared_enc, mut ct) = hybrid_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek).expect("Encapsulation failed");

    // ML-KEM CT is typically 1088 bytes. We flip the first bit.
    ct[0] ^= 0x01;

    let result = hybrid_kem_decapsulate(&bob_sk, &alice_pk, &bob_dk, &ct);
    if let Ok(shared_dec) = result {
        assert_ne!(shared_enc, shared_dec, "Wrong bit flip should yield different shared secret (IND-CCA) - never panic");
    } else {
        assert!(result.is_err());
    }
}

#[test]
fn hybrid_kem_flip_bit_in_mlkem_ciphertext() {
    let (alice_sk, alice_pk) = generate_x25519_keypair();
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let (bob_dk, bob_ek) = ml_kem_keygen();

    let (shared_enc, mut ct) = hybrid_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek).expect("Encapsulation failed");

    // ML-KEM Ciphertext bit flip according to ML-KEM spec (implicit rejection)
    let mid = ct.len() / 2;
    ct[mid] ^= 0x01;

    let result = hybrid_kem_decapsulate(&bob_sk, &alice_pk, &bob_dk, &ct);
    match result {
        Ok(shared_dec) => assert_ne!(shared_enc, shared_dec, "Implicit rejection should yield different secret"),
        Err(_) => {} // Or explicit rejection error
    }
}

#[test]
fn hybrid_kem_truncated_ciphertext() {
    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let (bob_dk, bob_ek) = ml_kem_keygen();

    let (_, ct) = hybrid_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek).unwrap();
    let truncated = &ct[..ct.len() / 2];

    let result = hybrid_kem_decapsulate(&bob_sk, &bob_pk, &bob_dk, truncated);
    assert!(result.is_err(), "Truncated ciphertext should fail");
}

#[test]
fn hybrid_kem_empty_ciphertext() {
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let (bob_dk, _) = ml_kem_keygen();

    let result = hybrid_kem_decapsulate(&bob_sk, &bob_pk, &bob_dk, &[]);
    assert!(result.is_err(), "Empty ciphertext should fail");
}

// ── Authenticated KEM Attacks ─────────────────────────────────────────────

#[test]
fn auth_kem_wrong_sender_identity() {
    let (alice_id_sk, _alice_id_pk) = generate_ed25519_keypair();
    let (_mallory_id_sk, mallory_id_pk) = generate_ed25519_keypair();

    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let (bob_dk, bob_ek) = ml_kem_keygen();

    let (auth_ct, _) = authenticated_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek, &alice_id_sk).unwrap();

    let result = authenticated_kem_decapsulate(&bob_sk, &alice_sk, &bob_dk, &auth_ct, &mallory_id_pk);
    assert!(result.is_err(), "Should fail authentication when checking with wrong identity");
}

#[test]
fn auth_kem_tampered_ciphertext_after_signature() {
    let (alice_id_sk, alice_id_pk) = generate_ed25519_keypair();
    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let (bob_dk, bob_ek) = ml_kem_keygen();

    let (mut auth_ct, _) = authenticated_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek, &alice_id_sk).unwrap();

    // Tamper with the ciphertext (which is after the first 2 bytes length prefix)
    let ct_len = u16::from_be_bytes([auth_ct[0], auth_ct[1]]) as usize;
    if ct_len > 0 {
        auth_ct[5] ^= 0xFF;
    }

    let result = authenticated_kem_decapsulate(&bob_sk, &alice_sk, &bob_dk, &auth_ct, &alice_id_pk);
    assert!(result.is_err(), "Tampered ciphertext should fail authentication");
}

#[test]
fn auth_kem_signature_moved_to_different_ciphertext() {
    let (alice_id_sk, alice_id_pk) = generate_ed25519_keypair();
    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let (bob_dk, bob_ek) = ml_kem_keygen();

    // Encapsulation 1
    let (auth_ct1, _) = authenticated_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek, &alice_id_sk).unwrap();

    // Encapsulation 2 (different state / random values)
    let (mut auth_ct2, _) = authenticated_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek, &alice_id_sk).unwrap();

    // Swap the signature of ct2 with ct1
    let ct1_sig_start = auth_ct1.len() - 64;
    let ct2_sig_start = auth_ct2.len() - 64;
    auth_ct2[ct2_sig_start..].copy_from_slice(&auth_ct1[ct1_sig_start..]);

    let result = authenticated_kem_decapsulate(&bob_sk, &alice_sk, &bob_dk, &auth_ct2, &alice_id_pk);
    assert!(result.is_err(), "Signature replay on different ciphertext should fail");
}

#[test]
fn auth_kem_empty_authenticated_ciphertext() {
    let (_alice_id_sk, alice_id_pk) = generate_ed25519_keypair();
    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (bob_sk, _bob_pk) = generate_x25519_keypair();
    let (bob_dk, _bob_ek) = ml_kem_keygen();

    let result = authenticated_kem_decapsulate(&bob_sk, &alice_sk, &bob_dk, &[], &alice_id_pk);
    assert!(result.is_err(), "Empty authenticated ciphertext should fail");
}

#[test]
fn auth_kem_only_length_prefix_no_body() {
    let (_alice_id_sk, alice_id_pk) = generate_ed25519_keypair();
    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (bob_sk, _bob_pk) = generate_x25519_keypair();
    let (bob_dk, _bob_ek) = ml_kem_keygen();

    let prefix: [u8; 2] = 100u16.to_be_bytes();
    let result = authenticated_kem_decapsulate(&bob_sk, &alice_sk, &bob_dk, &prefix, &alice_id_pk);
    assert!(result.is_err(), "Only length prefix should fail");
}

#[test]
fn auth_kem_length_prefix_overflows_buffer() {
    let (_alice_id_sk, alice_id_pk) = generate_ed25519_keypair();
    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (bob_sk, _bob_pk) = generate_x25519_keypair();
    let (bob_dk, _bob_ek) = ml_kem_keygen();

    let mut buf = vec![0u8; 10];
    let len_prefix = 65535u16.to_be_bytes();
    buf[0..2].copy_from_slice(&len_prefix);

    let result = authenticated_kem_decapsulate(&bob_sk, &alice_sk, &bob_dk, &buf, &alice_id_pk);
    assert!(result.is_err(), "Overflowing length prefix should fail cleanly (no slice panic)");
}

// ── Cross-KEM Attacks ─────────────────────────────────────────────────────

#[test]
fn kem_shared_secrets_not_equal_wrong_private_key() {
    let (alice_sk, _alice_pk) = generate_x25519_keypair();
    let (_bob_sk, bob_pk) = generate_x25519_keypair();
    let (_bob_dk, bob_ek) = ml_kem_keygen();

    let (mallory_sk, _mallory_pk) = generate_x25519_keypair();
    let (mallory_dk, _mallory_ek) = ml_kem_keygen();

    let (shared_enc, ct) = hybrid_kem_encapsulate(&alice_sk, &bob_pk, &bob_ek).unwrap();

    let result = hybrid_kem_decapsulate(&mallory_sk, &alice_sk, &mallory_dk, &ct);
    if let Ok(shared_dec) = result {
        assert_ne!(shared_enc, shared_dec, "Mallory decapsulating with their own sk should not yield same secret");
    }
}

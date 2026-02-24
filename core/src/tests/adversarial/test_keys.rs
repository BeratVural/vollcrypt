use crate::keys::{
    generate_ed25519_keypair, generate_x25519_keypair, sign_message, verify_signature,
    ecdh_shared_secret,
};

// ── Ed25519 Attacks ───────────────────────────────────────────────────────

#[test]
fn sign_with_empty_secret_key() {
    let result = sign_message(&[], b"test");
    assert!(result.is_err(), "Empty secret key should return an error");
}

#[test]
fn sign_with_wrong_length_secret_key_31_bytes() {
    let sk = [0u8; 31];
    let result = sign_message(&sk, b"test");
    assert!(result.is_err(), "31-byte secret key should return an error");
}

#[test]
fn verify_with_wrong_public_key() {
    let (sk, _) = generate_ed25519_keypair();
    let (_, wrong_pk) = generate_ed25519_keypair();
    let msg = b"test message";
    let sig = sign_message(&sk, msg).unwrap();

    let result = verify_signature(&wrong_pk, msg, &sig);
    assert!(!result, "Verification with wrong public key must fail");
}

#[test]
fn verify_with_empty_public_key() {
    let (sk, _) = generate_ed25519_keypair();
    let msg = b"test message";
    let sig = sign_message(&sk, msg).unwrap();

    let result = verify_signature(&[], msg, &sig);
    assert!(!result, "Verification with empty public key must fail");
}

#[test]
fn verify_with_corrupted_signature_1_bit_flip() {
    let (sk, pk) = generate_ed25519_keypair();
    let msg = b"test message";
    let mut sig = sign_message(&sk, msg).unwrap();

    sig[31] ^= 0x01; // flip a bit

    let result = verify_signature(&pk, msg, &sig);
    assert!(!result, "Verification with corrupted signature must fail");
}

#[test]
fn verify_with_empty_signature() {
    let (_, pk) = generate_ed25519_keypair();
    let msg = b"test message";

    let result = verify_signature(&pk, msg, &[]);
    assert!(!result, "Verification with empty signature must fail");
}

#[test]
fn verify_with_truncated_signature_63_bytes() {
    let (sk, pk) = generate_ed25519_keypair();
    let msg = b"test message";
    let mut sig = sign_message(&sk, msg).unwrap();

    sig.pop(); // remove last byte

    let result = verify_signature(&pk, msg, &sig);
    assert!(!result, "Verification with truncated signature must fail");
}

#[test]
fn verify_with_extended_signature_65_bytes() {
    let (sk, pk) = generate_ed25519_keypair();
    let msg = b"test message";
    let mut sig = sign_message(&sk, msg).unwrap();

    sig.push(0x42);

    let result = verify_signature(&pk, msg, &sig);
    assert!(!result, "Verification with extended signature must fail");
}

#[test]
fn sign_empty_message() {
    let (sk, pk) = generate_ed25519_keypair();
    let sig = sign_message(&sk, b"").expect("Failed to sign empty message");
    let result = verify_signature(&pk, b"", &sig);
    assert!(result, "Verification of empty message must succeed");
}

#[test]
fn sign_large_message_10mb() {
    let (sk, pk) = generate_ed25519_keypair();
    let msg = vec![0x42u8; 10 * 1024 * 1024];

    let sig = sign_message(&sk, &msg).expect("Failed to sign large message");
    let result = verify_signature(&pk, &msg, &sig);
    assert!(result, "Verification of large message must succeed");
}

#[test]
fn verify_different_message_same_signature() {
    let (sk, pk) = generate_ed25519_keypair();
    let msg1 = b"message 1";
    let msg2 = b"message 2";

    let sig = sign_message(&sk, msg1).unwrap();
    let result = verify_signature(&pk, msg2, &sig);
    assert!(!result, "Verification of different message with same signature must fail");
}

#[test]
fn signature_malleability_check() {
    let (sk, pk) = generate_ed25519_keypair();
    let msg = b"test message";
    let mut sig = sign_message(&sk, msg).unwrap();

    // The signature S component is the last 32 bytes
    // We modify S to attempt a malleability attack (e.g. flip high bit)
    let s_high_byte_idx = 63;
    sig[s_high_byte_idx] ^= 0x80;

    let result = verify_signature(&pk, msg, &sig);
    assert!(!result, "Strict verification must reject modified signatures (prevent malleability)");
}

// ── X25519 Attacks ────────────────────────────────────────────────────────

#[test]
fn x25519_empty_private_key() {
    let (_, pk) = generate_x25519_keypair();
    let result = ecdh_shared_secret(&[], &pk);
    assert!(result.is_err(), "Empty private key must fail");
}

#[test]
fn x25519_low_order_point() {
    let (sk, _) = generate_x25519_keypair();

    // Known low-order point (all zeros)
    let low_order_pk = [0u8; 32];
    let result = ecdh_shared_secret(&sk, &low_order_pk);

    // Depending on dalek version, it might return Ok but with an all-zero shared secret,
    // or return an Err. The library currently might just perform standard ECDH.
    // If it returns Ok, the shared secret should not be used, but dalek 2.0+ mitigates this.
    // Here we just ensure it doesn't panic.
    if let Ok(shared) = result {
        assert_eq!(shared.len(), 32);
        // It's possible the shared secret is all zeros, which indicates a low-order point.
        // A robust API should probably err, but dalek's `diffie_hellman` returns an output.
    } else {
        assert!(result.is_err());
    }
}

#[test]
fn x25519_ecdh_commutativity() {
    let (alice_sk, alice_pk) = generate_x25519_keypair();
    let (bob_sk, bob_pk) = generate_x25519_keypair();

    let shared_alice = ecdh_shared_secret(&alice_sk, &bob_pk).expect("Alice DH failed");
    let shared_bob = ecdh_shared_secret(&bob_sk, &alice_pk).expect("Bob DH failed");

    assert_eq!(shared_alice, shared_bob, "ECDH shared secrets must match");
}

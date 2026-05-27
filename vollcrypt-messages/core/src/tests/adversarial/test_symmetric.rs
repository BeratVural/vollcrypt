use crate::symmetric::{decrypt_aes256gcm, encrypt_aes256gcm};

// ── Invalid Key Lengths ───────────────────────────────────────────────────

#[test]
fn aes_gcm_empty_key() {
    let key: [u8; 0] = [];
    let result = encrypt_aes256gcm(&key, b"test", None);
    assert!(result.is_err(), "Empty key should return an error");
}

#[test]
fn aes_gcm_short_key_15_bytes() {
    let key = [0u8; 15];
    let result = encrypt_aes256gcm(&key, b"test", None);
    assert!(result.is_err(), "Short key should return an error");
}

#[test]
fn aes_gcm_long_key_64_bytes() {
    let key = [0u8; 64];
    let result = encrypt_aes256gcm(&key, b"test", None);
    assert!(result.is_err(), "Long key should return an error");
}

#[test]
fn aes_gcm_wrong_key_decryption() {
    let key_alice = [0u8; 32];
    let key_bob = [1u8; 32];
    let encrypted = match encrypt_aes256gcm(&key_alice, b"test", None) {
        Ok(c) => c,
        Err(e) => panic!("Encryption failed: {}", e),
    };

    let result = decrypt_aes256gcm(&key_bob, &encrypted, None);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

// ── Ciphertext Manipulation ───────────────────────────────────────────────

#[test]
fn aes_gcm_flip_single_bit_in_ciphertext() {
    let key = [0u8; 32];
    // Need at least 16 bytes for tag, 12 bytes for IV, so we decrypt a decent length payload
    let mut encrypted = encrypt_aes256gcm(&key, b"this is a sufficiently long message", None)
        .expect("Encryption failed");

    // IV is 0..12, Ciphertext is 12..(len-16), Tag is (len-16)..len
    // To flip a bit in ciphertext, adjust index 20 (which is inside the ciphertext)
    encrypted[20] ^= 0x01;

    let result = decrypt_aes256gcm(&key, &encrypted, None);
    assert!(result.is_err(), "Tampered ciphertext should fail decryption");
}

#[test]
fn aes_gcm_flip_single_bit_in_auth_tag() {
    let key = [0u8; 32];
    let mut encrypted = encrypt_aes256gcm(&key, b"test message", None).expect("Encryption failed");

    // Flip a bit in the last 16 bytes (auth tag)
    let len = encrypted.len();
    encrypted[len - 5] ^= 0x01;

    let result = decrypt_aes256gcm(&key, &encrypted, None);
    assert!(result.is_err(), "Tampered auth tag should fail decryption");
}

#[test]
fn aes_gcm_flip_single_bit_in_iv() {
    let key = [0u8; 32];
    let mut encrypted = encrypt_aes256gcm(&key, b"test message", None).expect("Encryption failed");

    // Flip a bit in the first 12 bytes (IV)
    encrypted[5] ^= 0x01;

    let result = decrypt_aes256gcm(&key, &encrypted, None);
    assert!(result.is_err(), "Tampered IV should fail decryption");
}

#[test]
fn aes_gcm_truncated_ciphertext_1_byte() {
    let key = [0u8; 32];
    let mut encrypted = encrypt_aes256gcm(&key, b"test message", None).expect("Encryption failed");

    // Truncate the last byte
    encrypted.pop();

    let result = decrypt_aes256gcm(&key, &encrypted, None);
    assert!(result.is_err(), "Truncated ciphertext should fail decryption without panicking");
}

#[test]
fn aes_gcm_truncated_ciphertext_to_zero() {
    let key = [0u8; 32];
    let _ = encrypt_aes256gcm(&key, b"test message", None).expect("Encryption failed");

    let result = decrypt_aes256gcm(&key, &[], None);
    assert!(result.is_err(), "Zero-length ciphertext should fail decryption");
}

#[test]
fn aes_gcm_extended_ciphertext() {
    let key = [0u8; 32];
    let mut encrypted = encrypt_aes256gcm(&key, b"test message", None).expect("Encryption failed");

    // Extend with 100 bytes of random data
    encrypted.extend_from_slice(&[0x42; 100]);

    let result = decrypt_aes256gcm(&key, &encrypted, None);
    assert!(result.is_err(), "Extended ciphertext should fail decryption");
}

// ── AAD (Additional Authenticated Data) Attacks ──────────────────────────

#[test]
fn aes_gcm_aad_mismatch() {
    let key = [0u8; 32];
    let encrypted = encrypt_aes256gcm(&key, b"test", Some(b"message-001")).expect("Encryption failed");

    let result = decrypt_aes256gcm(&key, &encrypted, Some(b"message-002"));
    assert!(result.is_err(), "Decryption should fail when AAD mismatches");
}

#[test]
fn aes_gcm_aad_present_on_encrypt_absent_on_decrypt() {
    let key = [0u8; 32];
    let encrypted = encrypt_aes256gcm(&key, b"test", Some(b"data")).expect("Encryption failed");

    let result = decrypt_aes256gcm(&key, &encrypted, None);
    assert!(result.is_err(), "Decryption should fail when AAD is omitted");
}

#[test]
fn aes_gcm_aad_absent_on_encrypt_present_on_decrypt() {
    let key = [0u8; 32];
    let encrypted = encrypt_aes256gcm(&key, b"test", None).expect("Encryption failed");

    let result = decrypt_aes256gcm(&key, &encrypted, Some(b"data"));
    assert!(result.is_err(), "Decryption should fail when unexpected AAD is provided");
}

#[test]
fn aes_gcm_empty_aad_vs_none_aad() {
    let key = [0u8; 32];
    let encrypted_empty = encrypt_aes256gcm(&key, b"test", Some(b"")).expect("Encryption failed");
    let encrypted_none = encrypt_aes256gcm(&key, b"test", None).expect("Encryption failed");

    // Depending on implementation, None and Some(b"") might be equivalent or different.
    // The library uses `associated_data.unwrap_or(b"")`, meaning they are functionally equivalent.
    // Wait, let's verify if they can be decrypted interchangeably.
    let res1 = decrypt_aes256gcm(&key, &encrypted_empty, None);
    let res2 = decrypt_aes256gcm(&key, &encrypted_none, Some(b""));

    assert!(res1.is_ok(), "None equivalent to empty AAD");
    assert!(res2.is_ok(), "None equivalent to empty AAD");
}

// ── Edge Case Inputs ──────────────────────────────────────────────────────

#[test]
fn aes_gcm_empty_plaintext() {
    let key = [0u8; 32];
    let encrypted = encrypt_aes256gcm(&key, b"", None).expect("Encryption failed");
    assert!(!encrypted.is_empty(), "Encrypted output of empty plaintext should not be empty (due to IV + tag)");

    let decrypted = decrypt_aes256gcm(&key, &encrypted, None).expect("Decryption failed");
    assert_eq!(decrypted, b"", "Decryption should yield empty message");
}

#[test]
fn aes_gcm_single_byte_plaintext() {
    let key = [0u8; 32];
    let encrypted = encrypt_aes256gcm(&key, b"A", None).expect("Encryption failed");

    let decrypted = decrypt_aes256gcm(&key, &encrypted, None).expect("Decryption failed");
    assert_eq!(decrypted, b"A");
}

#[test]
fn aes_gcm_large_plaintext_10mb() {
    let key = [0u8; 32];
    let plaintext = vec![0x42u8; 10 * 1024 * 1024]; // 10 MB

    let encrypted = encrypt_aes256gcm(&key, &plaintext, None).expect("Encryption of large plaintext failed");
    let decrypted = decrypt_aes256gcm(&key, &encrypted, None).expect("Decryption of large plaintext failed");

    assert_eq!(decrypted, plaintext, "Large plaintext roundtrip failed");
}

#[test]
fn aes_gcm_all_zeros_plaintext() {
    let key = [0u8; 32];
    let plaintext = vec![0u8; 1024];

    let encrypted = encrypt_aes256gcm(&key, &plaintext, None).expect("Encryption failed");
    // Ensure the ciphertext part is not just zeros
    let ciphertext_only = &encrypted[12..encrypted.len() - 16];
    let all_zeros = ciphertext_only.iter().all(|&b| b == 0);
    assert!(!all_zeros, "Ciphertext should not be all zeros due to encryption");

    let decrypted = decrypt_aes256gcm(&key, &encrypted, None).expect("Decryption failed");
    assert_eq!(decrypted, plaintext, "Roundtrip failed for all zeros");
}

#[test]
fn aes_gcm_repeated_encryption_different_ciphertexts() {
    let key = [0u8; 32];
    let plaintext = b"repeated encryption test";

    let mut prev_ciphertext: Vec<u8> = Vec::new();
    for _ in 0..100 {
        let encrypted = encrypt_aes256gcm(&key, plaintext, None).expect("Encryption failed");
        let current_ciphertext = encrypted.clone();
        assert_ne!(current_ciphertext, prev_ciphertext, "Ciphertexts should differ due to IV randomness");
        prev_ciphertext = current_ciphertext;

        let decrypted = decrypt_aes256gcm(&key, &encrypted, None).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }
}

#[test]
fn aes_gcm_ciphertext_reuse_attack() {
    let key = [0u8; 32];
    let ct1 = encrypt_aes256gcm(&key, b"alice pays bob $10", None).unwrap();
    let ct2 = encrypt_aes256gcm(&key, b"alice pays bob $99", None).unwrap();

    assert_ne!(ct1, ct2, "Different messages should yield different ciphertexts");

    let pt1 = decrypt_aes256gcm(&key, &ct1, None).unwrap();
    let pt2 = decrypt_aes256gcm(&key, &ct2, None).unwrap();

    assert_eq!(pt1, b"alice pays bob $10");
    assert_eq!(pt2, b"alice pays bob $99");
}

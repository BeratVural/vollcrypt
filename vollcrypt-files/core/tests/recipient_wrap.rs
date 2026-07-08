use vollcrypt_files_core::{
    generate_dek, generate_recipient_keypair, unwrap_key_with_recipient_key, wrap_key_to_recipient,
    FileFormatError, WrapEntry,
};

#[test]
fn keypair_roundtrip() {
    let (pk, sk) = generate_recipient_keypair();
    assert_eq!(pk.x25519.len(), 32);
    assert_eq!(pk.ml_kem.len(), 1184);

    // RecipientSecretKey fields are private but we can verify structure size or drop properties.
    // We just check that the keypair generation is successful and returns expected sizes.
    let _ = sk;
}

#[test]
fn single_recipient_wrap_unwrap() {
    let dek = generate_dek();
    let recipient_id = [0x99; 16];
    let gk_version = 0;

    let (pk, sk) = generate_recipient_keypair();

    let wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();
    let unwrapped = unwrap_key_with_recipient_key(&wrap, &sk).unwrap();

    assert_eq!(dek, unwrapped);
}

#[test]
fn multi_recipient_wrap() {
    let dek = generate_dek();
    let recipient_id = [0x55; 16];
    let gk_version = 1;

    let mut recipients = Vec::new();
    let mut wraps = Vec::new();

    for _ in 0..5 {
        let (pk, sk) = generate_recipient_keypair();
        let wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();
        recipients.push(sk);
        wraps.push(wrap);
    }

    for i in 0..5 {
        let unwrapped = unwrap_key_with_recipient_key(&wraps[i], &recipients[i]).unwrap();
        assert_eq!(dek, unwrapped);
    }
}

#[test]
fn cross_recipient_unwrap_fails() {
    let dek = generate_dek();
    let recipient_id = [0x11; 16];
    let gk_version = 0;

    let (pk_a, sk_a) = generate_recipient_keypair();
    let (_pk_b, sk_b) = generate_recipient_keypair();

    let wrap_a = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk_a).unwrap();

    // Try to decrypt wrap A using recipient B's secret key
    let result = unwrap_key_with_recipient_key(&wrap_a, &sk_b);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));

    // Decrypting with correct key A should work
    let unwrapped = unwrap_key_with_recipient_key(&wrap_a, &sk_a).unwrap();
    assert_eq!(dek, unwrapped);
}

#[test]
fn tampered_ephemeral_fails() {
    let dek = generate_dek();
    let recipient_id = [0x22; 16];
    let gk_version = 0;

    let (pk, sk) = generate_recipient_keypair();
    let mut wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();

    // Tamper ephemeral key
    if let WrapEntry::HybridKem {
        x25519_ephemeral, ..
    } = &mut wrap
    {
        x25519_ephemeral[0] ^= 1;
    }

    let result = unwrap_key_with_recipient_key(&wrap, &sk);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));
}

#[test]
fn tampered_ciphertext_fails() {
    let dek = generate_dek();
    let recipient_id = [0x33; 16];
    let gk_version = 0;

    let (pk, sk) = generate_recipient_keypair();
    let mut wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();

    // Tamper ML-KEM ciphertext
    if let WrapEntry::HybridKem {
        mlkem_ciphertext, ..
    } = &mut wrap
    {
        mlkem_ciphertext[0] ^= 1;
    }

    let result = unwrap_key_with_recipient_key(&wrap, &sk);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));
}

#[test]
fn tampered_recipient_id_fails() {
    let dek = generate_dek();
    let recipient_id = [0x44; 16];
    let gk_version = 0;

    let (pk, sk) = generate_recipient_keypair();
    let mut wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();

    // Tamper Recipient ID
    if let WrapEntry::HybridKem {
        recipient_id: r_id, ..
    } = &mut wrap
    {
        r_id[0] ^= 1;
    }

    let result = unwrap_key_with_recipient_key(&wrap, &sk);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));
}

#[test]
fn tampered_gk_version_fails() {
    let dek = generate_dek();
    let recipient_id = [0x55; 16];
    let gk_version = 0;

    let (pk, sk) = generate_recipient_keypair();
    let mut wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();

    // Tamper GK version
    if let WrapEntry::HybridKem {
        gk_version: ver, ..
    } = &mut wrap
    {
        *ver += 1;
    }

    let result = unwrap_key_with_recipient_key(&wrap, &sk);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));
}

#[test]
fn wrong_wrap_type_returns_error() {
    let password_wrap = WrapEntry::PasswordPbkdf2 {
        iterations: 10_000,
        salt: [0x11; 16],
        wrapped_dek: [0x22; 40],
    };

    let (_pk, sk) = generate_recipient_keypair();
    let result = unwrap_key_with_recipient_key(&password_wrap, &sk);
    assert!(matches!(result, Err(FileFormatError::WrongWrapType)));
}

#[test]
fn test_old_kem_suite_rejected() {
    // A serialized wrap with wrap_type = 2 (old HybridKem)
    let mut serialized_old_wrap = vec![0u8; 1183]; // 3 bytes header + 1180 payload
    serialized_old_wrap[0] = 2; // Old wrap type
    let payload_len = 1180u16;
    serialized_old_wrap[1..3].copy_from_slice(&payload_len.to_be_bytes());

    let parse_res = WrapEntry::parse(&serialized_old_wrap);
    assert!(matches!(parse_res, Err(FileFormatError::UnsupportedSuite(2))));
}

#[test]
fn test_hybrid_kem_binding() {
    let dek = generate_dek();
    let recipient_id = [0x99; 16];
    let gk_version = 0;

    let (pk, sk) = generate_recipient_keypair();

    let wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();

    // If we tamper x25519_ephemeral (ct_x25519) in the WrapEntry, decryption should fail with WrongRecipientKey
    let mut tampered_wrap = wrap.clone();
    if let WrapEntry::HybridKem { x25519_ephemeral, .. } = &mut tampered_wrap {
        x25519_ephemeral[0] ^= 1;
    }

    let result = unwrap_key_with_recipient_key(&tampered_wrap, &sk);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));
}

#[test]
fn wrap_key_fails_on_low_order_recipient_key() {
    let dek = generate_dek();
    let recipient_id = [0x99; 16];
    let gk_version = 0;

    let (mut pk, _sk) = generate_recipient_keypair();
    // Zero out the recipient X25519 public key to simulate a low-order point
    pk.x25519 = [0u8; 32];

    let result = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));
}

#[test]
fn unwrap_key_fails_on_low_order_ephemeral_key() {
    let dek = generate_dek();
    let recipient_id = [0x99; 16];
    let gk_version = 0;

    let (pk, sk) = generate_recipient_keypair();
    let mut wrap = wrap_key_to_recipient(&dek, recipient_id, gk_version, &pk).unwrap();

    // Zero out the ephemeral public key inside the wrap to simulate a low-order point
    if let WrapEntry::HybridKem { x25519_ephemeral, .. } = &mut wrap {
        *x25519_ephemeral = [0u8; 32];
    }

    let result = unwrap_key_with_recipient_key(&wrap, &sk);
    assert!(matches!(result, Err(FileFormatError::WrongRecipientKey)));
}


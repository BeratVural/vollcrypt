use vollcrypt_files_core::{
    ChunkEnvelope, CipherId, FileFormatError, Header, Mode, WrapEntry, FIXED_HEADER_LEN, MAGIC,
    VERSION, HashAlgorithm,
};

#[test]
fn header_roundtrip_password_pbkdf2() {
    let wrap = WrapEntry::PasswordPbkdf2 {
        iterations: 120_000,
        salt: [0x01; 16],
        wrapped_dek: [0x02; 40],
    };

    let header = Header {
        version: VERSION,
        mode: Mode::Password,
        cipher_id: CipherId::Aes256Gcm,
        file_id: [0x03; 16],
        chunk_size: 65536,
        plaintext_size: 1024 * 1024,
        merkle_root: [0x04; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![wrap],
        signed_metadata: None,
        signature: None,
    };

    let serialized = header.write();
    assert_eq!(serialized.len(), header.serialized_len());

    let (parsed, offset) = Header::parse(&serialized).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(offset, serialized.len());
}

#[test]
fn header_roundtrip_password_argon2id() {
    let wrap = WrapEntry::PasswordArgon2id {
        m_cost: 65536,
        t_cost: 3,
        p_cost: 4,
        salt: [0x05; 16],
        wrapped_dek: [0x06; 40],
    };

    let header = Header {
        version: VERSION,
        mode: Mode::Password,
        cipher_id: CipherId::Aes256Gcm,
        file_id: [0x07; 16],
        chunk_size: 1024 * 1024,
        plaintext_size: 2048 * 1024,
        merkle_root: [0x08; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![wrap],
        signed_metadata: None,
        signature: None,
    };

    let serialized = header.write();
    assert_eq!(serialized.len(), header.serialized_len());

    let (parsed, offset) = Header::parse(&serialized).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(offset, serialized.len());
}

#[test]
fn header_roundtrip_hybrid_kem_single() {
    let wrap = WrapEntry::HybridKem {
        recipient_id: [0x09; 16],
        gk_version: 2,
        x25519_ephemeral: [0x0A; 32],
        mlkem_ciphertext: vec![0x0B; 1088],
        wrapped_dek: [0x0C; 40],
    };

    let header = Header {
        version: VERSION,
        mode: Mode::Recipient,
        cipher_id: CipherId::Aes256Gcm,
        file_id: [0x0D; 16],
        chunk_size: 65536,
        plaintext_size: 512,
        merkle_root: [0x0E; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![wrap],
        signed_metadata: None,
        signature: None,
    };

    let serialized = header.write();
    assert_eq!(serialized.len(), header.serialized_len());

    let (parsed, offset) = Header::parse(&serialized).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(offset, serialized.len());
}

#[test]
fn header_roundtrip_multi_recipient() {
    let mut wraps = Vec::new();
    for i in 0..5 {
        wraps.push(WrapEntry::HybridKem {
            recipient_id: [i as u8; 16],
            gk_version: 1,
            x25519_ephemeral: [i as u8; 32],
            mlkem_ciphertext: vec![i as u8; 1088],
            wrapped_dek: [i as u8; 40],
        });
    }

    let header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: [0xFF; 16],
        chunk_size: 262144,
        plaintext_size: 50 * 1024 * 1024,
        merkle_root: [0xEE; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps,
        signed_metadata: None,
        signature: None,
    };

    let serialized = header.write();
    assert_eq!(serialized.len(), header.serialized_len());

    let (parsed, offset) = Header::parse(&serialized).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(offset, serialized.len());
}

#[test]
fn header_roundtrip_mixed() {
    let wrap_pw = WrapEntry::PasswordPbkdf2 {
        iterations: 80_000,
        salt: [0x10; 16],
        wrapped_dek: [0x11; 40],
    };

    let mut wraps = vec![wrap_pw];

    for i in 0..3 {
        wraps.push(WrapEntry::HybridKem {
            recipient_id: [i as u8; 16],
            gk_version: 1,
            x25519_ephemeral: [i as u8; 32],
            mlkem_ciphertext: vec![i as u8; 1088],
            wrapped_dek: [i as u8; 40],
        });
    }

    let header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: [0xAA; 16],
        chunk_size: 65536,
        plaintext_size: 4096,
        merkle_root: [0xBB; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps,
        signed_metadata: None,
        signature: None,
    };

    let serialized = header.write();
    assert_eq!(serialized.len(), header.serialized_len());

    let (parsed, offset) = Header::parse(&serialized).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(offset, serialized.len());
}

#[test]
fn chunk_envelope_roundtrip() {
    let ciphertext = vec![0xCC; 65536]; // 64KB
    let chunk = ChunkEnvelope {
        chunk_index: 42,
        iv: [0xDD; 12],
        ciphertext: ciphertext.clone(),
        tag: [0xEE; 16],
    };

    let serialized = chunk.write();
    assert_eq!(serialized.len(), ChunkEnvelope::wire_size(65536));

    let parsed = ChunkEnvelope::parse(&serialized, 65536).unwrap();
    assert_eq!(parsed, chunk);
}

#[test]
fn invalid_magic_rejected() {
    let mut serialized = vec![0u8; FIXED_HEADER_LEN];
    serialized[0..8].copy_from_slice(b"BADMAGIC");
    serialized[8] = VERSION;

    let result = Header::parse(&serialized);
    assert_eq!(result.unwrap_err(), FileFormatError::InvalidMagic);
}

#[test]
fn unsupported_version_rejected() {
    let mut serialized = vec![0u8; FIXED_HEADER_LEN];
    serialized[0..8].copy_from_slice(&MAGIC);
    serialized[8] = 99;

    let result = Header::parse(&serialized);
    assert_eq!(result.unwrap_err(), FileFormatError::UnsupportedVersion(99));
}

#[test]
fn truncated_header_rejected() {
    let input = vec![0x00; FIXED_HEADER_LEN - 1];
    let result = Header::parse(&input);
    assert_eq!(
        result.unwrap_err(),
        FileFormatError::TruncatedHeader {
            expected: FIXED_HEADER_LEN,
            got: FIXED_HEADER_LEN - 1,
        }
    );
}

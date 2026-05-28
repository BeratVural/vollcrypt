use vollcrypt_file_core::{
    chunk_leaf_hash, decrypt_chunk, encrypt_chunk, generate_dek, generate_file_id,
    unwrap_dek_with_password, wrap_dek_with_password, ChunkEnvelope, CipherId, FileFormatError,
    Header, KdfChoice, MerkleTree, Mode, VERSION,
};

#[test]
fn encrypt_decrypt_small_file_pbkdf2() {
    let password = b"test-password-123";
    let plaintext = vec![0xAB; 4096]; // 4 KB

    // 1. Setup session / encryption
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    let wrap =
        wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 10_000 }).unwrap();

    let header = Header {
        version: VERSION,
        mode: Mode::Password,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        wraps: vec![wrap],
        signed_metadata: None,
        signature: None,
    };

    // 2. Serialize header and envelope
    let mut serialized = header.write();
    serialized.extend_from_slice(&envelope.write());

    // 3. Deserialize and Decrypt session
    let (parsed_header, header_len) = Header::parse(&serialized).unwrap();
    let parsed_envelope = ChunkEnvelope::parse(&serialized[header_len..], 4096).unwrap();

    let recovered_dek = unwrap_dek_with_password(&parsed_header.wraps[0], password).unwrap();
    let recovered =
        decrypt_chunk(&recovered_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();

    assert_eq!(plaintext, recovered);
}

#[test]
fn encrypt_decrypt_small_file_argon2id_interactive() {
    let password = b"test-password-123";
    let plaintext = vec![0xCD; 4096]; // 4 KB

    // 1. Setup session / encryption
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::argon2id_interactive()).unwrap();

    let header = Header {
        version: VERSION,
        mode: Mode::Password,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        wraps: vec![wrap],
        signed_metadata: None,
        signature: None,
    };

    // 2. Serialize header and envelope
    let mut serialized = header.write();
    serialized.extend_from_slice(&envelope.write());

    // 3. Deserialize and Decrypt session
    let (parsed_header, header_len) = Header::parse(&serialized).unwrap();
    let parsed_envelope = ChunkEnvelope::parse(&serialized[header_len..], 4096).unwrap();

    let recovered_dek = unwrap_dek_with_password(&parsed_header.wraps[0], password).unwrap();
    let recovered =
        decrypt_chunk(&recovered_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();

    assert_eq!(plaintext, recovered);
}

#[test]
fn wrong_password_end_to_end() {
    let password = b"correct-password";
    let wrong_password = b"wrong-password-123";
    let plaintext = vec![0xEF; 100];

    // 1. Setup session / encryption
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::argon2id_interactive()).unwrap();

    let header = Header {
        version: VERSION,
        mode: Mode::Password,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        wraps: vec![wrap],
        signed_metadata: None,
        signature: None,
    };

    // 2. Serialize
    let mut serialized = header.write();
    serialized.extend_from_slice(&envelope.write());

    // 3. Try to decrypt with wrong password
    let (parsed_header, _header_len) = Header::parse(&serialized).unwrap();

    let recovered_dek_result = unwrap_dek_with_password(&parsed_header.wraps[0], wrong_password);

    assert!(matches!(
        recovered_dek_result,
        Err(FileFormatError::WrongPassword)
    ));
}

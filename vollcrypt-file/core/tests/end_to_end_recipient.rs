use vollcrypt_file_core::{
    chunk_leaf_hash, decrypt_chunk, encrypt_chunk, generate_dek, generate_file_id,
    generate_recipient_keypair, generate_salt, unwrap_dek_with_password,
    unwrap_key_with_recipient_key, wrap_dek_with_password, wrap_key_to_recipient, ChunkEnvelope,
    CipherId, Header, KdfChoice, MerkleTree, Mode, VERSION,
};

#[test]
fn encrypt_decrypt_small_file_hybrid_kem() {
    let (pk, sk) = generate_recipient_keypair();
    let plaintext = vec![0xEE; 4096]; // 4 KB

    // 1. Setup session / encryption
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    let recipient_id = generate_file_id(); // 16 bytes random ID
    let wrap = wrap_key_to_recipient(&dek, recipient_id, 0, &pk).unwrap();

    let header = Header {
        version: VERSION,
        mode: Mode::Recipient,
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

    let recovered_dek = unwrap_key_with_recipient_key(&parsed_header.wraps[0], &sk).unwrap();
    let recovered =
        decrypt_chunk(&recovered_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();

    assert_eq!(plaintext, recovered);
}

#[test]
fn encrypt_decrypt_multi_recipient() {
    let mut recipients_pks = Vec::new();
    let mut recipients_sks = Vec::new();

    for _ in 0..3 {
        let (pk, sk) = generate_recipient_keypair();
        recipients_pks.push(pk);
        recipients_sks.push(sk);
    }

    let plaintext = vec![0x12; 1000];
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    let mut wraps = Vec::new();
    for rec_pk in &recipients_pks {
        let recipient_id = generate_file_id();
        let wrap = wrap_key_to_recipient(&dek, recipient_id, 0, rec_pk).unwrap();
        wraps.push(wrap);
    }

    let header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        wraps,
        signed_metadata: None,
        signature: None,
    };

    let mut serialized = header.write();
    serialized.extend_from_slice(&envelope.write());

    // Verify all 3 recipients can decrypt
    let (parsed_header, header_len) = Header::parse(&serialized).unwrap();
    let parsed_envelope = ChunkEnvelope::parse(&serialized[header_len..], 1000).unwrap();

    for (i, rec_sk) in recipients_sks.iter().enumerate() {
        let recovered_dek = unwrap_key_with_recipient_key(&parsed_header.wraps[i], rec_sk).unwrap();
        let recovered =
            decrypt_chunk(&recovered_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();

        assert_eq!(plaintext, recovered);
    }
}

#[test]
fn mixed_password_and_recipient_header() {
    let password = b"mixed-password-mode-1";
    let (pk, sk) = generate_recipient_keypair();

    let plaintext = vec![0x77; 500];
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    // 1. Password wrap
    let wrap_pw =
        wrap_dek_with_password(&dek, password, KdfChoice::argon2id_interactive()).unwrap();

    // 2. Recipient wrap
    let recipient_id = generate_salt();
    let wrap_kem = wrap_key_to_recipient(&dek, recipient_id, 1, &pk).unwrap();

    let header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        wraps: vec![wrap_pw, wrap_kem],
        signed_metadata: None,
        signature: None,
    };

    let mut serialized = header.write();
    serialized.extend_from_slice(&envelope.write());

    // 3. Verify unwrap via password
    let (parsed_header, header_len) = Header::parse(&serialized).unwrap();
    let parsed_envelope = ChunkEnvelope::parse(&serialized[header_len..], 500).unwrap();

    let recovered_dek_pw = unwrap_dek_with_password(&parsed_header.wraps[0], password).unwrap();
    let recovered_pw = decrypt_chunk(
        &recovered_dek_pw,
        &parsed_header.file_id,
        0,
        &parsed_envelope,
    )
    .unwrap();
    assert_eq!(plaintext, recovered_pw);

    // 4. Verify unwrap via recipient secret key
    let recovered_dek_kem = unwrap_key_with_recipient_key(&parsed_header.wraps[1], &sk).unwrap();
    let recovered_kem = decrypt_chunk(
        &recovered_dek_kem,
        &parsed_header.file_id,
        0,
        &parsed_envelope,
    )
    .unwrap();
    assert_eq!(plaintext, recovered_kem);
}

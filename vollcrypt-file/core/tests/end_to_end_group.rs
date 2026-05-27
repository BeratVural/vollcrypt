use vollcrypt_file_core::{
    chunk_leaf_hash, decrypt_chunk, ed25519_keypair_generate, encrypt_chunk, generate_dek,
    generate_file_id, generate_gk, generate_recipient_keypair, unwrap_dek_with_group_key,
    unwrap_key_with_recipient_key, wrap_dek_for_group, wrap_key_to_recipient, ChunkEnvelope,
    CipherId, FileFormatError, GroupManifest, Header, MerkleTree, Mode, VERSION,
};

#[test]
fn encrypt_decrypt_three_members() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let group_id = generate_file_id();

    // Member 1 (Founder)
    let founder_id = generate_file_id();
    let (rec_pk1, rec_sk1) = generate_recipient_keypair();

    // Member 2
    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, rec_sk2) = generate_recipient_keypair();

    // Member 3
    let member3_id = generate_file_id();
    let (member3_signing_pk, _member3_signing_sk) = ed25519_keypair_generate();
    let (rec_pk3, rec_sk3) = generate_recipient_keypair();

    // Generate GK
    let gk = generate_gk();

    // Manifest genesis
    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();
    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    // Add Member 2
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();
    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Add Member 3
    let gk_wrap3 = wrap_key_to_recipient(&gk, member3_id, 0, &rec_pk3).unwrap();
    manifest
        .add_member(&admin_sk, member3_id, member3_signing_pk, rec_pk3, gk_wrap3)
        .unwrap();

    assert!(manifest.verify().is_ok());

    // Encrypt file
    let plaintext = vec![0xAB; 4096]; // 4 KB
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    // Wrap DEK with GK
    let group_wrap = wrap_dek_for_group(&dek, group_id, 0, &gk);

    let header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        wraps: vec![group_wrap],
    };

    // Serialize
    let mut serialized = header.write();
    serialized.extend_from_slice(&envelope.write());

    // Independent decryption paths for all 3 members
    let (parsed_header, header_len) = Header::parse(&serialized).unwrap();
    let parsed_envelope = ChunkEnvelope::parse(&serialized[header_len..], 4096).unwrap();

    // Member 1 decryption
    let member1_gk_wrap = manifest.find_member_wrap(&founder_id).unwrap();
    let member1_gk = unwrap_key_with_recipient_key(&member1_gk_wrap, &rec_sk1).unwrap();
    let member1_dek = unwrap_dek_with_group_key(&parsed_header.wraps[0], &member1_gk).unwrap();
    let recovered1 =
        decrypt_chunk(&member1_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();
    assert_eq!(plaintext, recovered1);

    // Member 2 decryption
    let member2_gk_wrap = manifest.find_member_wrap(&member2_id).unwrap();
    let member2_gk = unwrap_key_with_recipient_key(&member2_gk_wrap, &rec_sk2).unwrap();
    let member2_dek = unwrap_dek_with_group_key(&parsed_header.wraps[0], &member2_gk).unwrap();
    let recovered2 =
        decrypt_chunk(&member2_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();
    assert_eq!(plaintext, recovered2);

    // Member 3 decryption
    let member3_gk_wrap = manifest.find_member_wrap(&member3_id).unwrap();
    let member3_gk = unwrap_key_with_recipient_key(&member3_gk_wrap, &rec_sk3).unwrap();
    let member3_dek = unwrap_dek_with_group_key(&parsed_header.wraps[0], &member3_gk).unwrap();
    let recovered3 =
        decrypt_chunk(&member3_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();
    assert_eq!(plaintext, recovered3);
}

#[test]
fn removed_member_lazy_still_works() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let group_id = generate_file_id();

    // Member 1 (Founder)
    let founder_id = generate_file_id();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();

    // Member 2
    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();

    // Member 3 (will be removed)
    let member3_id = generate_file_id();
    let (member3_signing_pk, _member3_signing_sk) = ed25519_keypair_generate();
    let (rec_pk3, rec_sk3) = generate_recipient_keypair();

    // Generate GK
    let gk = generate_gk();

    // Manifest genesis
    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();
    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    // Add Member 2
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();
    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Add Member 3
    let gk_wrap3 = wrap_key_to_recipient(&gk, member3_id, 0, &rec_pk3).unwrap();
    manifest
        .add_member(&admin_sk, member3_id, member3_signing_pk, rec_pk3, gk_wrap3)
        .unwrap();

    // Member 3 is active, they can find their wrap in the manifest
    let saved_wrap3 = manifest.find_member_wrap(&member3_id).unwrap();

    // Encrypt file
    let plaintext = vec![0x77; 1000];
    let dek = generate_dek();
    let file_id = generate_file_id();
    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();
    let group_wrap = wrap_dek_for_group(&dek, group_id, 0, &gk);
    let header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        wraps: vec![group_wrap],
    };

    // Serialize
    let mut serialized = header.write();
    serialized.extend_from_slice(&envelope.write());

    // Now remove Member 3 from the group manifest
    manifest.remove_member(&admin_sk, member3_id).unwrap();

    // Now, querying the manifest directly for Member 3 fails
    let res = manifest.find_member_wrap(&member3_id);
    assert!(matches!(res, Err(FileFormatError::MemberNotFound)));

    // But because lazy revocation is in effect, Member 3 can decrypt using their previously saved wrap
    let (parsed_header, header_len) = Header::parse(&serialized).unwrap();
    let parsed_envelope = ChunkEnvelope::parse(&serialized[header_len..], 1000).unwrap();

    let recovered_gk = unwrap_key_with_recipient_key(&saved_wrap3, &rec_sk3).unwrap();
    let recovered_dek = unwrap_dek_with_group_key(&parsed_header.wraps[0], &recovered_gk).unwrap();
    let recovered =
        decrypt_chunk(&recovered_dek, &parsed_header.file_id, 0, &parsed_envelope).unwrap();

    assert_eq!(plaintext, recovered);
}

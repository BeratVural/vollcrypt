use vollcrypt_files_core::{
    chunk_leaf_hash, decrypt_chunk, ed25519_keypair_generate, encrypt_chunk, generate_dek,
    generate_file_id, generate_gk, generate_recipient_keypair, rewrap_dek_in_header,
    unwrap_dek_with_group_key, unwrap_key_with_recipient_key, wrap_dek_for_group,
    wrap_key_to_recipient, CipherId, FileFormatError, GroupManifest, Header, MerkleTree, Mode,
    HashAlgorithm, VERSION,
};

#[test]
fn eager_revocation_full_flow() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let group_id = generate_file_id();

    // Member 1 (Founder)
    let founder_id = generate_file_id();
    let (rec_pk1, rec_sk1) = generate_recipient_keypair();

    // Member 2
    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, rec_sk2) = generate_recipient_keypair();

    // Member 3 (Will be revoked)
    let member3_id = generate_file_id();
    let (member3_signing_pk, _member3_signing_sk) = ed25519_keypair_generate();
    let (rec_pk3, rec_sk3) = generate_recipient_keypair();

    // GK v1
    let gk1 = generate_gk();

    // Genesis manifest
    let founder_gk_wrap = wrap_key_to_recipient(&gk1, founder_id, 1, &rec_pk1).unwrap();
    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    // Add Member 2
    let gk_wrap2 = wrap_key_to_recipient(&gk1, member2_id, 1, &rec_pk2).unwrap();
    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Add Member 3
    let gk_wrap3 = wrap_key_to_recipient(&gk1, member3_id, 1, &rec_pk3).unwrap();
    manifest
        .add_member(&admin_sk, member3_id, member3_signing_pk, rec_pk3, gk_wrap3)
        .unwrap();

    // Encrypt file with GK v1
    let plaintext = vec![0x99; 4096];
    let dek = generate_dek();
    let file_id = generate_file_id();
    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();
    let old_group_wrap = wrap_dek_for_group(&dek, group_id, 1, &gk1);

    let mut header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![old_group_wrap],
        signed_metadata: None,
        signature: None,
    };

    // Verify all 3 members can decrypt the file initially
    // Member 1
    let w1 = manifest
        .find_member_wrap_for_version(&founder_id, 1)
        .unwrap();
    let g1_1 = unwrap_key_with_recipient_key(&w1, &rec_sk1).unwrap();
    let d1 = unwrap_dek_with_group_key(&header.wraps[0], &g1_1).unwrap();
    assert_eq!(
        plaintext,
        decrypt_chunk(&d1, &file_id, 0, &envelope).unwrap()
    );

    // Member 2
    let w2 = manifest
        .find_member_wrap_for_version(&member2_id, 1)
        .unwrap();
    let g1_2 = unwrap_key_with_recipient_key(&w2, &rec_sk2).unwrap();
    let d2 = unwrap_dek_with_group_key(&header.wraps[0], &g1_2).unwrap();
    assert_eq!(
        plaintext,
        decrypt_chunk(&d2, &file_id, 0, &envelope).unwrap()
    );

    // Member 3
    let w3 = manifest
        .find_member_wrap_for_version(&member3_id, 1)
        .unwrap();
    let g1_3 = unwrap_key_with_recipient_key(&w3, &rec_sk3).unwrap();
    let d3 = unwrap_dek_with_group_key(&header.wraps[0], &g1_3).unwrap();
    assert_eq!(
        plaintext,
        decrypt_chunk(&d3, &file_id, 0, &envelope).unwrap()
    );

    // EAGER REVOCATION PROCESS:
    // 1. Remove Member 3 from manifest
    manifest.remove_member(&admin_sk, member3_id).unwrap();

    // 2. Rotate Group Key to gk2 (v2)
    let gk2 = generate_gk();
    let new_gk_version = manifest
        .rotate_group_key(&gk2, &admin_pk, &admin_sk, 1000)
        .unwrap();
    assert_eq!(new_gk_version, 2);

    // 3. Rewrap DEK in file header
    let rewrapped_count = rewrap_dek_in_header(&mut header, &gk1, &gk2, 2).unwrap();
    assert_eq!(rewrapped_count, 1);

    // Verify Member 1 and Member 2 can still decrypt (using GK v2)
    // Member 1
    let w1_v2 = manifest
        .find_member_wrap_for_version(&founder_id, 2)
        .unwrap();
    let g2_1 = unwrap_key_with_recipient_key(&w1_v2, &rec_sk1).unwrap();
    let d1_v2 = unwrap_dek_with_group_key(&header.wraps[0], &g2_1).unwrap();
    assert_eq!(
        plaintext,
        decrypt_chunk(&d1_v2, &file_id, 0, &envelope).unwrap()
    );

    // Member 2
    let w2_v2 = manifest
        .find_member_wrap_for_version(&member2_id, 2)
        .unwrap();
    let g2_2 = unwrap_key_with_recipient_key(&w2_v2, &rec_sk2).unwrap();
    let d2_v2 = unwrap_dek_with_group_key(&header.wraps[0], &g2_2).unwrap();
    assert_eq!(
        plaintext,
        decrypt_chunk(&d2_v2, &file_id, 0, &envelope).unwrap()
    );

    // Verify Member 3 CANNOT decrypt anymore
    // A. Member 3 cannot obtain version 2 wrap from manifest
    let res_w3_v2 = manifest.find_member_wrap_for_version(&member3_id, 2);
    assert!(matches!(
        res_w3_v2,
        Err(FileFormatError::WrapVersionNotFound { gk_version: 2 })
    ));

    // B. Member 3 tries to decrypt using their cached GK v1, which fails
    let res_d3_old = unwrap_dek_with_group_key(&header.wraps[0], &g1_3);
    assert!(matches!(res_d3_old, Err(FileFormatError::WrongGroupKey)));
}

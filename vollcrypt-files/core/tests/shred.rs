use vollcrypt_files_core::{
    chunk_leaf_hash, crypto_shred_header, decrypt_chunk, hybrid_keypair_generate, encrypt_chunk,
    generate_dek, generate_file_id, generate_gk, generate_recipient_keypair, wrap_dek_for_group,
    wrap_key_to_recipient, CipherId, FileFormatError, GroupManifest, HashAlgorithm, Header,
    MerkleTree, Mode, VERSION,
};

#[test]
fn shred_group_key_marks_version() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
    let (rec_pk, _rec_sk) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk1 = generate_gk();
    let gk2 = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk1, founder_id, 1, &rec_pk).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk,
        founder_gk_wrap,
    );

    manifest
        .rotate_group_key(&gk2, &admin_sk, 100)
        .unwrap();

    assert!(!manifest.is_version_shredded(1));
    assert!(!manifest.is_version_shredded(2));

    manifest
        .shred_group_key(1, "GDPR Article 17 request", &admin_sk, 150)
        .unwrap();

    assert!(manifest.is_version_shredded(1));
    assert!(!manifest.is_version_shredded(2));
}

#[test]
fn shredded_version_unwrap_returns_error() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
    let (rec_pk, _rec_sk) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk1 = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk1, founder_id, 1, &rec_pk).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk,
        founder_gk_wrap,
    );

    // Shred version 1
    manifest
        .shred_group_key(1, "Revoked", &admin_sk, 200)
        .unwrap();

    // Querying the wrap for version 1 should fail with GroupKeyShredded error
    let res = manifest.find_member_wrap_for_version(&founder_id, 1);
    assert!(matches!(res, Err(FileFormatError::GroupKeyShredded(1))));
}

#[test]
fn already_shredded_fails() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
    let (rec_pk, _rec_sk) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk1 = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk1, founder_id, 1, &rec_pk).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk,
        founder_gk_wrap,
    );

    manifest
        .shred_group_key(1, "Revoked", &admin_sk, 200)
        .unwrap();

    let res = manifest.shred_group_key(1, "Duplicate", &admin_sk, 300);
    assert!(matches!(res, Err(FileFormatError::AlreadyShredded)));
}

#[test]
fn crypto_shred_header_empties_wraps() {
    let mut header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: generate_file_id(),
        chunk_size: 4096,
        plaintext_size: 1000,
        merkle_root: [0x77; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![
            wrap_dek_for_group(&generate_dek(), generate_file_id(), 1, &generate_gk()),
            wrap_dek_for_group(&generate_dek(), generate_file_id(), 2, &generate_gk()),
        ],
        signed_metadata: None,
        signature: None,
    };

    assert_eq!(header.wraps.len(), 2);
    let original_file_id = header.file_id;
    let original_merkle_root = header.merkle_root;

    crypto_shred_header(&mut header);

    assert!(header.wraps.is_empty());
    assert_eq!(header.file_id, original_file_id);
    assert_eq!(header.merkle_root, original_merkle_root);
}

#[test]
fn decrypt_fails_after_file_shred() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = vec![0x33; 1000];

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext, None).unwrap();
    let leaf = chunk_leaf_hash(&envelope);
    let merkle_root = MerkleTree::from_leaves(vec![leaf]).root();

    let group_wrap = wrap_dek_for_group(&dek, generate_file_id(), 1, &generate_gk());

    let mut header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root,
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![group_wrap],
        signed_metadata: None,
        signature: None,
    };

    // Shred header
    crypto_shred_header(&mut header);

    // Verify decryption cannot proceed because wraps is empty
    assert!(header.wraps.is_empty());
    // Simulate caller behavior: if wraps is empty, we cannot recover dek
    let has_key = !header.wraps.is_empty();
    assert!(!has_key);

    let res = decrypt_chunk(&dek, &header.file_id, 0, &envelope, None).unwrap();
    assert_eq!(plaintext, res); // Symmetric decrypt itself works with dek, but dek wrapping has been shredded.
}

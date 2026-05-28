use vollcrypt_files_core::{
    ed25519_keypair_generate, generate_file_id, generate_gk, generate_recipient_keypair,
    unwrap_key_with_recipient_key, wrap_key_to_recipient, FileFormatError, GroupManifest,
    Operation,
};

#[test]
fn rotate_increments_version() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
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

    assert_eq!(manifest.current_gk_version(), 1);

    let ver = manifest
        .rotate_group_key(&gk2, &admin_pk, &admin_sk, 100)
        .unwrap();

    assert_eq!(ver, 2);
    assert_eq!(manifest.current_gk_version(), 2);
    assert_eq!(manifest.operations.len(), 2);

    let last_op = &manifest.operations[1];
    assert_eq!(last_op.op_type, 3); // RotateKey
}

#[test]
fn rotate_includes_all_current_members() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk1 = generate_gk();
    let gk2 = generate_gk();

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
    let member2_id = generate_file_id();
    let (m2_signing_pk, _m2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk1, member2_id, 1, &rec_pk2).unwrap();
    manifest
        .add_member(&admin_sk, member2_id, m2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Rotate Key
    manifest
        .rotate_group_key(&gk2, &admin_pk, &admin_sk, 200)
        .unwrap();

    let op =
        Operation::parse(manifest.operations[2].op_type, &manifest.operations[2].data).unwrap();

    if let Operation::RotateKey {
        new_gk_version,
        wraps,
    } = op
    {
        assert_eq!(new_gk_version, 2);
        assert_eq!(wraps.len(), 2);
        assert!(wraps.iter().any(|(mid, _)| *mid == founder_id));
        assert!(wraps.iter().any(|(mid, _)| *mid == member2_id));
    } else {
        panic!("Expected Operation::RotateKey");
    }
}

#[test]
fn rotate_excludes_removed_members() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk1 = generate_gk();
    let gk2 = generate_gk();

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
    let member2_id = generate_file_id();
    let (m2_signing_pk, _m2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk1, member2_id, 1, &rec_pk2).unwrap();
    manifest
        .add_member(&admin_sk, member2_id, m2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Remove Member 2
    manifest.remove_member(&admin_sk, member2_id).unwrap();

    // Rotate Key
    manifest
        .rotate_group_key(&gk2, &admin_pk, &admin_sk, 300)
        .unwrap();

    let op =
        Operation::parse(manifest.operations[3].op_type, &manifest.operations[3].data).unwrap();

    if let Operation::RotateKey { wraps, .. } = op {
        assert_eq!(wraps.len(), 1);
        assert_eq!(wraps[0].0, founder_id);
    } else {
        panic!("Expected Operation::RotateKey");
    }
}

#[test]
fn member_can_unwrap_new_gk() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk, rec_sk) = generate_recipient_keypair();
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

    // Rotate
    manifest
        .rotate_group_key(&gk2, &admin_pk, &admin_sk, 400)
        .unwrap();

    // Member retrieves wrap for version 2
    let wrap = manifest
        .find_member_wrap_for_version(&founder_id, 2)
        .unwrap();
    let unwrapped_gk = unwrap_key_with_recipient_key(&wrap, &rec_sk).unwrap();

    assert_eq!(gk2, unwrapped_gk);
}

#[test]
fn member_can_still_unwrap_old_gk() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk, rec_sk) = generate_recipient_keypair();
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

    // Rotate
    manifest
        .rotate_group_key(&gk2, &admin_pk, &admin_sk, 400)
        .unwrap();

    // Member retrieves wrap for version 1
    let wrap = manifest
        .find_member_wrap_for_version(&founder_id, 1)
        .unwrap();
    let unwrapped_gk = unwrap_key_with_recipient_key(&wrap, &rec_sk).unwrap();

    assert_eq!(gk1, unwrapped_gk);
}

#[test]
fn unauthorized_rotate_fails() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (_unauth_pk, unauth_sk) = ed25519_keypair_generate();
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

    // Rotate with unauthorized key
    let res = manifest.rotate_group_key(&gk2, &admin_pk, &unauth_sk, 500);
    assert!(matches!(res, Err(FileFormatError::NotAuthorized)));
}

#[test]
fn rotation_preserves_chain_integrity() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
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
        .rotate_group_key(&gk2, &admin_pk, &admin_sk, 600)
        .unwrap();

    assert!(manifest.verify().is_ok());
}

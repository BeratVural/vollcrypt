use vollcrypt_file_core::{
    ed25519_keypair_generate, generate_file_id, generate_gk, generate_recipient_keypair,
    wrap_key_to_recipient, FileFormatError, GroupManifest,
};

#[test]
fn genesis_only() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk, _rec_sk) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk).unwrap();

    let manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk,
        founder_gk_wrap,
    );

    assert_eq!(manifest.group_id, group_id);
    assert_eq!(manifest.operations.len(), 1);
    assert_eq!(manifest.current_members(), vec![founder_id]);
    assert_eq!(manifest.current_gk_version(), 0);
    assert!(manifest.verify().is_ok());
}

#[test]
fn add_two_members() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

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
    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Add Member 3
    let member3_id = generate_file_id();
    let (member3_signing_pk, _member3_signing_sk) = ed25519_keypair_generate();
    let (rec_pk3, _rec_sk3) = generate_recipient_keypair();
    let gk_wrap3 = wrap_key_to_recipient(&gk, member3_id, 0, &rec_pk3).unwrap();

    manifest
        .add_member(&admin_sk, member3_id, member3_signing_pk, rec_pk3, gk_wrap3)
        .unwrap();

    assert_eq!(manifest.operations.len(), 3);
    let mut members = manifest.current_members();
    members.sort();
    let mut expected = vec![founder_id, member2_id, member3_id];
    expected.sort();
    assert_eq!(members, expected);
    assert!(manifest.verify().is_ok());
}

#[test]
fn add_then_remove() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    assert_eq!(manifest.current_members().len(), 2);

    manifest.remove_member(&admin_sk, member2_id).unwrap();

    assert_eq!(manifest.current_members(), vec![founder_id]);
    assert!(manifest.verify().is_ok());
}

#[test]
fn remove_unknown_fails() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    let unknown_id = generate_file_id();
    let res = manifest.remove_member(&admin_sk, unknown_id);
    assert!(matches!(res, Err(FileFormatError::MemberNotFound)));
}

#[test]
fn unauthorized_admin_fails() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (_unauth_pk, unauth_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    // Try adding member using unauthorized secret key
    let res = manifest.add_member(
        &unauth_sk,
        member2_id,
        member2_signing_pk,
        rec_pk2,
        gk_wrap2,
    );
    assert!(matches!(res, Err(FileFormatError::NotAuthorized)));
}

#[test]
fn verify_passes_clean_chain() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    assert!(manifest.verify().is_ok());
}

#[test]
fn verify_fails_tampered_signature() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    // Tamper the signature of the genesis block
    manifest.operations[0].signature[0] ^= 1;

    assert!(matches!(
        manifest.verify(),
        Err(FileFormatError::SignatureInvalid)
    ));
}

#[test]
fn verify_fails_broken_chain() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Break the hash chain link on operation 1
    manifest.operations[1].prev_hash[0] ^= 1;

    assert!(matches!(
        manifest.verify(),
        Err(FileFormatError::InvalidManifestChain)
    ));
}

#[test]
fn manifest_roundtrip_binary() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    let serialized = manifest.write();
    let (parsed, read_len) = GroupManifest::parse(&serialized).unwrap();

    assert_eq!(read_len, serialized.len());
    assert_eq!(manifest.group_id, parsed.group_id);
    assert_eq!(manifest.operations.len(), parsed.operations.len());
    assert_eq!(manifest.operations[0].data, parsed.operations[0].data);
    assert_eq!(manifest.operations[1].data, parsed.operations[1].data);
    assert!(parsed.verify().is_ok());
}

#[test]
fn find_member_wrap_for_existing() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap.clone(),
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(
            &admin_sk,
            member2_id,
            member2_signing_pk,
            rec_pk2,
            gk_wrap2.clone(),
        )
        .unwrap();

    let found_founder = manifest.find_member_wrap(&founder_id).unwrap();
    assert_eq!(found_founder, founder_gk_wrap);

    let found_member2 = manifest.find_member_wrap(&member2_id).unwrap();
    assert_eq!(found_member2, gk_wrap2);
}

#[test]
fn find_member_wrap_for_removed_fails() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk,
        rec_pk1,
        founder_gk_wrap,
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = ed25519_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    manifest.remove_member(&admin_sk, member2_id).unwrap();

    let res = manifest.find_member_wrap(&member2_id);
    assert!(matches!(res, Err(FileFormatError::MemberNotFound)));
}

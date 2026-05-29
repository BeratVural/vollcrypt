use vollcrypt_files_core::{
    hybrid_keypair_generate, hybrid_sign, generate_file_id, generate_gk, generate_recipient_keypair,
    wrap_key_to_recipient, FileFormatError, GroupManifest,
};

#[test]
fn genesis_only() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Add Member 3
    let member3_id = generate_file_id();
    let (member3_signing_pk, _member3_signing_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
    let (_unauth_pk, unauth_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    assert!(manifest.verify().is_ok());
}

#[test]
fn verify_fails_tampered_signature() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    manifest.operations[0].signature.ed25519[0] ^= 1;

    assert!(matches!(
        manifest.verify(),
        Err(FileFormatError::SignatureInvalid)
    ));
}

#[test]
fn verify_fails_broken_chain() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
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
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    manifest.remove_member(&admin_sk, member2_id).unwrap();

    let res = manifest.find_member_wrap(&member2_id);
    assert!(matches!(res, Err(FileFormatError::MemberNotFound)));
}

#[test]
fn test_epoch_monotonicity_violations() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
    let (rec_pk1, _rec_sk1) = generate_recipient_keypair();
    let group_id = generate_file_id();
    let founder_id = generate_file_id();
    let gk = generate_gk();

    let founder_gk_wrap = wrap_key_to_recipient(&gk, founder_id, 0, &rec_pk1).unwrap();

    let mut manifest = GroupManifest::genesis(
        group_id,
        founder_id,
        &admin_sk,
        admin_pk.clone(),
        rec_pk1,
        founder_gk_wrap,
    );

    let member2_id = generate_file_id();
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // Verify initial sequential epochs (0 and 1)
    assert!(manifest.verify().is_ok());

    // 1. Violation: Epoch decrease
    let mut bad_manifest = manifest.clone();
    bad_manifest.operations[1].epoch = 0;
    let msg = bad_manifest.operations[1].sig_message_for_version(bad_manifest.version);
    bad_manifest.operations[1].signature =
        hybrid_sign(&admin_sk, &admin_pk, "vollf-manifest-op", &[], &msg);
    let res = bad_manifest.verify();
    assert!(matches!(
        res,
        Err(FileFormatError::ManifestEpochOutOfSequence {
            expected: 1,
            got: 0
        })
    ));

    // 2. Violation: Epoch jump
    let mut bad_manifest = manifest.clone();
    bad_manifest.operations[1].epoch = 2;
    let msg = bad_manifest.operations[1].sig_message_for_version(bad_manifest.version);
    bad_manifest.operations[1].signature =
        hybrid_sign(&admin_sk, &admin_pk, "vollf-manifest-op", &[], &msg);
    let res = bad_manifest.verify();
    assert!(matches!(
        res,
        Err(FileFormatError::ManifestEpochOutOfSequence {
            expected: 1,
            got: 2
        })
    ));
}

#[test]
fn test_verify_manifest_with_pin() {
    let (admin_pk, admin_sk) = hybrid_keypair_generate();
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
    let (member2_signing_pk, _member2_signing_sk) = hybrid_keypair_generate();
    let (rec_pk2, _rec_sk2) = generate_recipient_keypair();
    let gk_wrap2 = wrap_key_to_recipient(&gk, member2_id, 0, &rec_pk2).unwrap();

    manifest
        .add_member(&admin_sk, member2_id, member2_signing_pk, rec_pk2, gk_wrap2)
        .unwrap();

    // The head epoch of the manifest is 1.
    // 1. Pin is None: should pass
    assert!(vollcrypt_files_core::verify_manifest_with_pin(&manifest, None).is_ok());

    // 2. Pin is Some(0): should pass because head epoch (1) >= pin (0)
    assert!(vollcrypt_files_core::verify_manifest_with_pin(&manifest, Some(0)).is_ok());

    // 3. Pin is Some(1): should pass because head epoch (1) >= pin (1)
    assert!(vollcrypt_files_core::verify_manifest_with_pin(&manifest, Some(1)).is_ok());

    // 4. Pin is Some(2): should fail with RollbackError because head epoch (1) < pin (2)
    let res = vollcrypt_files_core::verify_manifest_with_pin(&manifest, Some(2));
    assert!(matches!(
        res,
        Err(FileFormatError::RollbackError {
            expected: 2,
            got: 1
        })
    ));
}

#[test]
fn test_detect_equivocation() {
    let group_id_a = generate_file_id();
    let group_id_b = generate_file_id();

    let head_a = ([0x11; 32], 5);
    let head_b = ([0x22; 32], 5);
    let head_a_same = ([0x11; 32], 5);
    let head_diff_epoch = ([0x11; 32], 6);

    // Same group, same epoch, same hash -> NoEquivocation
    let res =
        vollcrypt_files_core::detect_equivocation(group_id_a, head_a, group_id_a, head_a_same);
    assert_eq!(
        res,
        vollcrypt_files_core::EquivocationResult::NoEquivocation
    );

    // Same group, same epoch, different hash -> EquivocationDetected
    let res = vollcrypt_files_core::detect_equivocation(group_id_a, head_a, group_id_a, head_b);
    assert_eq!(
        res,
        vollcrypt_files_core::EquivocationResult::EquivocationDetected
    );

    // Different groups -> DifferentGroups
    let res = vollcrypt_files_core::detect_equivocation(group_id_a, head_a, group_id_b, head_b);
    assert_eq!(
        res,
        vollcrypt_files_core::EquivocationResult::DifferentGroups
    );

    // Different epochs -> DifferentEpochs
    let res =
        vollcrypt_files_core::detect_equivocation(group_id_a, head_a, group_id_a, head_diff_epoch);
    assert_eq!(
        res,
        vollcrypt_files_core::EquivocationResult::DifferentEpochs
    );
}

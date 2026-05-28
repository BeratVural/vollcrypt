use vollcrypt_file_core::{
    ed25519_keypair_generate, generate_file_id, generate_gk, resolve_sender, sign_header_plain,
    sign_header_sealed, CipherId, FileFormatError, Header, KeyLog, Mode,
};

fn create_test_header() -> Header {
    Header {
        version: 2,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: generate_file_id(),
        chunk_size: 4096,
        plaintext_size: 1000,
        merkle_root: [0x55; 32],
        wraps: vec![],
        signed_metadata: None,
        signature: None,
    }
}

#[test]
fn full_resolution_plain() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(admin_pk);

    let (device_pk, device_sk) = ed25519_keypair_generate();
    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let timestamp = 100;

    let key_log_id = keylog
        .register_device(
            user_id,
            device_id,
            device_pk,
            "Alice's Mac",
            &admin_sk,
            timestamp,
        )
        .unwrap();

    keylog.verify().unwrap();

    let mut header = create_test_header();
    sign_header_plain(&mut header, &device_pk, &device_sk, key_log_id, timestamp).unwrap();

    let sender_info = resolve_sender(&header, &keylog, None).unwrap();

    assert_eq!(sender_info.user_id, user_id);
    assert_eq!(sender_info.device_id, device_id);
    assert_eq!(sender_info.signer_pubkey, device_pk);
    assert!(sender_info.device_was_active);
    assert_eq!(sender_info.human_label, Some("Alice's Mac".to_string()));
}

#[test]
fn full_resolution_sealed() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(admin_pk);

    let (device_pk, device_sk) = ed25519_keypair_generate();
    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let timestamp = 100;

    let key_log_id = keylog
        .register_device(
            user_id,
            device_id,
            device_pk,
            "Alice's Mac",
            &admin_sk,
            timestamp,
        )
        .unwrap();

    keylog.verify().unwrap();

    let gk = generate_gk();
    let group_id = generate_file_id();
    let mut header = create_test_header();

    sign_header_sealed(
        &mut header,
        &device_pk,
        &device_sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    // Resolving with correct GK works
    let sender_info = resolve_sender(&header, &keylog, Some(&gk)).unwrap();
    assert_eq!(sender_info.user_id, user_id);
    assert_eq!(sender_info.device_id, device_id);
    assert_eq!(sender_info.signer_pubkey, device_pk);
    assert!(sender_info.device_was_active);
    assert_eq!(sender_info.human_label, Some("Alice's Mac".to_string()));

    // Resolving without GK fails
    let res = resolve_sender(&header, &keylog, None);
    assert!(matches!(res, Err(FileFormatError::SealedGkRequired)));
}

#[test]
fn resolution_after_device_revoke() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(admin_pk);

    let (device_pk, device_sk) = ed25519_keypair_generate();
    let user_id = generate_file_id();
    let device_id = generate_file_id();

    // Register at 100
    let key_log_id = keylog
        .register_device(user_id, device_id, device_pk, "Alice's Mac", &admin_sk, 100)
        .unwrap();

    // Revoke at 150
    keylog.revoke_device(device_id, &admin_sk, 150).unwrap();

    keylog.verify().unwrap();

    // Alice signs header claiming signing timestamp is 200 (after revoke)
    let mut header = create_test_header();
    sign_header_plain(&mut header, &device_pk, &device_sk, key_log_id, 200).unwrap();

    // Resolution should still succeed (signature verifies, device info is looked up)
    // but device_was_active should be false!
    let sender_info = resolve_sender(&header, &keylog, None).unwrap();
    assert_eq!(sender_info.user_id, user_id);
    assert_eq!(sender_info.signer_pubkey, device_pk);
    assert!(!sender_info.device_was_active);
}

#[test]
fn wrong_gk_for_sealed_resolution() {
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(admin_pk);

    let (device_pk, device_sk) = ed25519_keypair_generate();
    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let timestamp = 100;

    let key_log_id = keylog
        .register_device(
            user_id,
            device_id,
            device_pk,
            "Alice's Mac",
            &admin_sk,
            timestamp,
        )
        .unwrap();

    keylog.verify().unwrap();

    let gk = generate_gk();
    let wrong_gk = generate_gk();
    let group_id = generate_file_id();
    let mut header = create_test_header();

    sign_header_sealed(
        &mut header,
        &device_pk,
        &device_sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    let res = resolve_sender(&header, &keylog, Some(&wrong_gk));
    assert!(matches!(res, Err(FileFormatError::WrongGroupKey)));
}

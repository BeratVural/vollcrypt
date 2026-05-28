use vollcrypt_files_core::{
    ed25519_keypair_generate, generate_file_id, FileFormatError, KeyLog, KeyLogEntryType,
};

#[test]
fn register_one_device() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let (device_pk, _device_sk) = ed25519_keypair_generate();

    let entry_hash = keylog
        .register_device(user_id, device_id, device_pk, "MacBook Pro", &auth_sk, 100)
        .unwrap();

    keylog.verify().unwrap();

    let entry = keylog.lookup_by_entry_hash(&entry_hash).unwrap();
    if let KeyLogEntryType::DeviceRegister {
        user_id: parsed_uid,
        device_id: parsed_did,
        human_label,
        ..
    } = &entry.entry
    {
        assert_eq!(*parsed_uid, user_id);
        assert_eq!(*parsed_did, device_id);
        assert_eq!(human_label, "MacBook Pro");
    } else {
        panic!("Expected DeviceRegister");
    }
}

#[test]
fn register_two_devices() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id1 = generate_file_id();
    let (device_pk1, _device_sk1) = ed25519_keypair_generate();
    let device_id2 = generate_file_id();
    let (device_pk2, _device_sk2) = ed25519_keypair_generate();

    let hash1 = keylog
        .register_device(user_id, device_id1, device_pk1, "iPhone 15", &auth_sk, 100)
        .unwrap();
    let hash2 = keylog
        .register_device(user_id, device_id2, device_pk2, "iPad Air", &auth_sk, 110)
        .unwrap();

    keylog.verify().unwrap();

    assert!(keylog.lookup_by_entry_hash(&hash1).is_some());
    assert!(keylog.lookup_by_entry_hash(&hash2).is_some());
}

#[test]
fn revoke_device() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let (device_pk, _device_sk) = ed25519_keypair_generate();

    keylog
        .register_device(user_id, device_id, device_pk, "MacBook Pro", &auth_sk, 100)
        .unwrap();

    assert!(keylog.device_was_active_at(&device_id, 150));

    keylog.revoke_device(device_id, &auth_sk, 200).unwrap();

    keylog.verify().unwrap();

    // Active at 150 (before revoke)
    assert!(keylog.device_was_active_at(&device_id, 150));
    // Inactive at 250 (after revoke)
    assert!(!keylog.device_was_active_at(&device_id, 250));
}

#[test]
fn register_then_revoke_unknown_fails() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);
    let unknown_device_id = generate_file_id();

    let res = keylog.revoke_device(unknown_device_id, &auth_sk, 100);
    assert!(matches!(res, Err(FileFormatError::DeviceNotFound)));
}

#[test]
fn double_revoke_fails() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let (device_pk, _device_sk) = ed25519_keypair_generate();

    keylog
        .register_device(user_id, device_id, device_pk, "MacBook Pro", &auth_sk, 100)
        .unwrap();

    keylog.revoke_device(device_id, &auth_sk, 200).unwrap();

    let res = keylog.revoke_device(device_id, &auth_sk, 300);
    assert!(matches!(res, Err(FileFormatError::DeviceAlreadyRevoked)));
}

#[test]
fn unauthorized_signer_breaks_verify() {
    let (auth_pk, _auth_sk) = ed25519_keypair_generate();
    let (_wrong_pk, wrong_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let (device_pk, _device_sk) = ed25519_keypair_generate();

    // Sign with unauthorized key wrong_sk
    keylog
        .register_device(user_id, device_id, device_pk, "MacBook Pro", &wrong_sk, 100)
        .unwrap();

    let res = keylog.verify();
    assert!(matches!(res, Err(FileFormatError::SignatureInvalid)));
}

#[test]
fn tampered_entry_data_breaks_verify() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let (device_pk, _device_sk) = ed25519_keypair_generate();

    keylog
        .register_device(user_id, device_id, device_pk, "MacBook Pro", &auth_sk, 100)
        .unwrap();

    // Tamper entry type data
    if let KeyLogEntryType::DeviceRegister {
        ref mut human_label,
        ..
    } = keylog.entries[0].entry
    {
        *human_label = "Tampered MacBook".to_string();
    }

    let res = keylog.verify();
    assert!(matches!(res, Err(FileFormatError::SignatureInvalid)));
}

#[test]
fn tampered_prev_hash_breaks_chain() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id1 = generate_file_id();
    let (device_pk1, _device_sk1) = ed25519_keypair_generate();
    let device_id2 = generate_file_id();
    let (device_pk2, _device_sk2) = ed25519_keypair_generate();

    keylog
        .register_device(user_id, device_id1, device_pk1, "iPhone 15", &auth_sk, 100)
        .unwrap();
    keylog
        .register_device(user_id, device_id2, device_pk2, "iPad Air", &auth_sk, 110)
        .unwrap();

    // Tamper second entry's prev_hash
    keylog.entries[1].prev_hash[0] ^= 1;

    let res = keylog.verify();
    assert!(matches!(res, Err(FileFormatError::InvalidKeyLogChain)));
}

#[test]
fn keylog_roundtrip_binary() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id1 = generate_file_id();
    let (device_pk1, _device_sk1) = ed25519_keypair_generate();
    let device_id2 = generate_file_id();
    let (device_pk2, _device_sk2) = ed25519_keypair_generate();

    keylog
        .register_device(user_id, device_id1, device_pk1, "iPhone 15", &auth_sk, 100)
        .unwrap();
    keylog
        .register_device(user_id, device_id2, device_pk2, "iPad Air", &auth_sk, 110)
        .unwrap();
    keylog.revoke_device(device_id1, &auth_sk, 200).unwrap();

    let bytes = keylog.write();
    let parsed = KeyLog::parse(&bytes).unwrap();

    assert_eq!(keylog.authority_pubkey, parsed.authority_pubkey);
    assert_eq!(keylog.entries.len(), parsed.entries.len());

    // Validate parsed chain verify works
    parsed.verify().unwrap();
}

#[test]
fn lookup_by_entry_hash() {
    let (auth_pk, auth_sk) = ed25519_keypair_generate();
    let mut keylog = KeyLog::new(auth_pk);

    let user_id = generate_file_id();
    let device_id = generate_file_id();
    let (device_pk, _device_sk) = ed25519_keypair_generate();

    let entry_hash = keylog
        .register_device(user_id, device_id, device_pk, "MacBook Pro", &auth_sk, 100)
        .unwrap();

    let entry = keylog.lookup_by_entry_hash(&entry_hash);
    assert!(entry.is_some());
}

use vollcrypt_files_core::{
    aes256_gcm_decrypt, hybrid_keypair_generate, generate_file_id, generate_gk, sign_header_plain,
    sign_header_sealed, verify_header_signature_plain, verify_header_signature_plain_policy,
    verify_header_signature_sealed, verify_header_signature_sealed_policy, CipherId,
    FileFormatError, HashAlgorithm, Header, Mode, SignedMetadata, KeyLog, VerificationPolicy,
};

fn create_test_header() -> Header {
    Header {
        version: 3,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: generate_file_id(),
        chunk_size: 4096,
        plaintext_size: 1000,
        merkle_root: [0x55; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![],
        signed_metadata: None,
        signature: None,
    }
}

#[test]
fn sign_verify_plain_roundtrip() {
    let mut header = create_test_header();
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;

    sign_header_plain(&mut header, &pk, &sk, key_log_id, timestamp).unwrap();

    let verified_pk = verify_header_signature_plain(&header, VerificationPolicy::RequireSigned).unwrap();
    assert_eq!(verified_pk, pk);
}

#[test]
fn sign_verify_sealed_roundtrip() {
    let mut header = create_test_header();
    let (auth_pk, auth_sk) = hybrid_keypair_generate();
    let mut key_log = KeyLog::new(auth_pk);

    let (pk, sk) = hybrid_keypair_generate();
    let timestamp = 987654321;
    let user_id = generate_file_id();
    let device_id = generate_file_id();
    
    let key_log_id = key_log
        .register_device(user_id, device_id, pk.clone(), "MacBook Pro", &auth_sk, timestamp)
        .unwrap();

    let group_id = generate_file_id();
    let gk = generate_gk();

    sign_header_sealed(
        &mut header,
        &pk,
        &sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    let verified_pk = verify_header_signature_sealed(&header, &gk, &key_log, VerificationPolicy::RequireSigned).unwrap();
    assert_eq!(verified_pk, pk);
}

#[test]
fn verify_unsigned_header_fails() {
    let header = create_test_header();
    let res = verify_header_signature_plain(&header, VerificationPolicy::AllowLegacy);
    assert!(matches!(res, Err(FileFormatError::HeaderNotSigned)));
}

#[test]
fn verify_sealed_with_plain_fails() {
    let mut header = create_test_header();
    let (auth_pk, auth_sk) = hybrid_keypair_generate();
    let mut key_log = KeyLog::new(auth_pk);

    let (pk, sk) = hybrid_keypair_generate();
    let timestamp = 987654321;
    let user_id = generate_file_id();
    let device_id = generate_file_id();
    
    let key_log_id = key_log
        .register_device(user_id, device_id, pk.clone(), "MacBook Pro", &auth_sk, timestamp)
        .unwrap();

    let group_id = generate_file_id();
    let gk = generate_gk();

    sign_header_sealed(
        &mut header,
        &pk,
        &sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    let res = verify_header_signature_plain(&header, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::HeaderSealed)));
}

#[test]
fn verify_plain_with_sealed_fails() {
    let mut header = create_test_header();
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;
    let gk = generate_gk();
    let (auth_pk, _auth_sk) = hybrid_keypair_generate();
    let key_log = KeyLog::new(auth_pk);

    sign_header_plain(&mut header, &pk, &sk, key_log_id, timestamp).unwrap();

    let res = verify_header_signature_sealed(&header, &gk, &key_log, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::HeaderNotSealed)));
}

#[test]
fn wrong_sk_signs_wrong_signature() {
    let mut header = create_test_header();
    let (pk, _sk) = hybrid_keypair_generate();
    let (_wrong_pk, wrong_sk) = hybrid_keypair_generate();
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;

    // Use wrong_sk to sign, but pass pk as the claim
    sign_header_plain(&mut header, &pk, &wrong_sk, key_log_id, timestamp).unwrap();

    let res = verify_header_signature_plain(&header, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::SignatureInvalid)));
}

#[test]
fn tampered_header_fails_verify() {
    let mut header = create_test_header();
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;

    sign_header_plain(&mut header, &pk, &sk, key_log_id, timestamp).unwrap();

    // Tamper header field
    header.chunk_size ^= 1;

    let res = verify_header_signature_plain(&header, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::SignatureInvalid)));
}

#[test]
fn tampered_signature_fails_verify() {
    let mut header = create_test_header();
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;

    sign_header_plain(&mut header, &pk, &sk, key_log_id, timestamp).unwrap();

    // Tamper signature
    if let Some(ref mut sig) = header.signature {
        sig.ed25519[0] ^= 1;
    }

    let res = verify_header_signature_plain(&header, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::SignatureInvalid)));
}

#[test]
fn wrong_gk_fails_sealed_verify() {
    let mut header = create_test_header();
    let (auth_pk, auth_sk) = hybrid_keypair_generate();
    let mut key_log = KeyLog::new(auth_pk);

    let (pk, sk) = hybrid_keypair_generate();
    let timestamp = 987654321;
    let user_id = generate_file_id();
    let device_id = generate_file_id();
    
    let key_log_id = key_log
        .register_device(user_id, device_id, pk.clone(), "MacBook Pro", &auth_sk, timestamp)
        .unwrap();

    let group_id = generate_file_id();
    let gk = generate_gk();
    let wrong_gk = generate_gk();

    sign_header_sealed(
        &mut header,
        &pk,
        &sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    let res = verify_header_signature_sealed(&header, &wrong_gk, &key_log, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::WrongGroupKey)));
}

#[test]
fn sealed_timestamp_in_clear() {
    let mut header = create_test_header();
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xBB; 32];
    let timestamp = 987654321;
    let group_id = generate_file_id();
    let gk = generate_gk();

    sign_header_sealed(
        &mut header,
        &pk,
        &sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    let metadata = header.signed_metadata.as_ref().unwrap();
    if let SignedMetadata::Sealed {
        sealed_payload,
        sealed_tag,
        iv,
        timestamp: clear_timestamp,
        ..
    } = metadata
    {
        assert_eq!(*clear_timestamp, timestamp);

        let mut aad = Vec::with_capacity(24);
        aad.extend_from_slice(&header.file_id);
        aad.extend_from_slice(&timestamp.to_be_bytes());

        let plaintext = aes256_gcm_decrypt(&gk, iv, &aad, sealed_payload, sealed_tag).unwrap();
        // Under v3, plaintext is only 32 bytes (key_log_id)
        assert_eq!(plaintext.len(), 32);
        assert_eq!(&plaintext[0..32], &key_log_id[..]);
    } else {
        panic!("Expected Sealed metadata");
    }
}

#[test]
fn test_require_signed_policy_plain() {
    let mut header = create_test_header();
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;

    // Unsigned header (default: version 3, but signature and metadata are None)
    header.signed_metadata = None;
    header.signature = None;

    // With require_pq_signature = false, verify should fail with HeaderNotSigned
    let res = verify_header_signature_plain_policy(&header, VerificationPolicy::AllowLegacy);
    assert!(matches!(res, Err(FileFormatError::HeaderNotSigned)));

    // With require_pq_signature = true, verify should fail with IntegrityError
    let res = verify_header_signature_plain_policy(&header, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::IntegrityError(_))));

    // Now sign it
    sign_header_plain(&mut header, &pk, &sk, key_log_id, timestamp).unwrap();

    // Verification should pass in both cases
    let res_false = verify_header_signature_plain_policy(&header, VerificationPolicy::AllowLegacy).unwrap();
    assert_eq!(res_false, pk);
    let res_true = verify_header_signature_plain_policy(&header, VerificationPolicy::RequireSigned).unwrap();
    assert_eq!(res_true, pk);

    // Downgrade version to 1 and remove metadata
    header.version = 1;
    header.signed_metadata = None;
    header.signature = None;

    // With require_pq_signature = false, verify should fail with HeaderNotSigned
    let res = verify_header_signature_plain_policy(&header, VerificationPolicy::AllowLegacy);
    assert!(matches!(res, Err(FileFormatError::HeaderNotSigned)));

    // With require_pq_signature = true, verify should fail with IntegrityError (downgrade prevention)
    let res = verify_header_signature_plain_policy(&header, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::IntegrityError(_))));
}

#[test]
fn test_require_signed_policy_sealed() {
    let mut header = create_test_header();
    let (auth_pk, auth_sk) = hybrid_keypair_generate();
    let mut key_log = KeyLog::new(auth_pk);

    let (pk, sk) = hybrid_keypair_generate();
    let timestamp = 987654321;
    let user_id = generate_file_id();
    let device_id = generate_file_id();
    
    let key_log_id = key_log
        .register_device(user_id, device_id, pk.clone(), "MacBook Pro", &auth_sk, timestamp)
        .unwrap();

    let group_id = generate_file_id();
    let gk = generate_gk();

    // Unsigned header
    header.signed_metadata = None;
    header.signature = None;

    // With require_pq_signature = false, verify should fail with HeaderNotSigned
    let res = verify_header_signature_sealed_policy(&header, &gk, &key_log, VerificationPolicy::AllowLegacy);
    assert!(matches!(res, Err(FileFormatError::HeaderNotSigned)));

    // With require_pq_signature = true, verify should fail with IntegrityError
    let res = verify_header_signature_sealed_policy(&header, &gk, &key_log, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::IntegrityError(_))));

    // Now sign it
    sign_header_sealed(
        &mut header,
        &pk,
        &sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    // Verification should pass in both cases
    let res_false = verify_header_signature_sealed_policy(&header, &gk, &key_log, VerificationPolicy::AllowLegacy).unwrap();
    assert_eq!(res_false, pk);
    let res_true = verify_header_signature_sealed_policy(&header, &gk, &key_log, VerificationPolicy::RequireSigned).unwrap();
    assert_eq!(res_true, pk);

    // Downgrade version to 1 and remove metadata
    header.version = 1;
    header.signed_metadata = None;
    header.signature = None;

    // With require_pq_signature = false, verify should fail with HeaderNotSigned
    let res = verify_header_signature_sealed_policy(&header, &gk, &key_log, VerificationPolicy::AllowLegacy);
    assert!(matches!(res, Err(FileFormatError::HeaderNotSigned)));

    // With require_pq_signature = true, verify should fail with IntegrityError (downgrade prevention)
    let res = verify_header_signature_sealed_policy(&header, &gk, &key_log, VerificationPolicy::RequireSigned);
    assert!(matches!(res, Err(FileFormatError::IntegrityError(_))));
}

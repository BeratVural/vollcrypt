use vollcrypt_files_core::{
    decrypt_chunk, encrypt_chunk, generate_dek, generate_file_id, generate_gk,
    rewrap_dek_in_header, unwrap_dek_with_group_key, unwrap_dek_with_password, wrap_dek_for_group,
    wrap_dek_with_password, CipherId, FileFormatError, HashAlgorithm, Header, KdfChoice, Mode,
    VERSION,
};

#[test]
fn rewrap_updates_gk_version() {
    let dek = generate_dek();
    let group_id = generate_file_id();
    let old_gk = generate_gk();
    let new_gk = generate_gk();

    let old_wrap = wrap_dek_for_group(&dek, group_id, 1, &old_gk);

    let mut header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: generate_file_id(),
        chunk_size: 4096,
        plaintext_size: 1000,
        merkle_root: [0x55; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![old_wrap],
        signed_metadata: None,
        signature: None,
    };

    let count = rewrap_dek_in_header(&mut header, &old_gk, &new_gk, 2).unwrap();
    assert_eq!(count, 1);

    // Verify version is now 2
    let updated_wrap = &header.wraps[0];
    let unwrapped_dek = unwrap_dek_with_group_key(updated_wrap, &new_gk).unwrap();
    assert_eq!(dek, unwrapped_dek);

    // Check version field in wrap is 2
    match updated_wrap {
        vollcrypt_files_core::WrapEntry::GroupWrap { gk_version, .. } => {
            assert_eq!(*gk_version, 2);
        }
        _ => panic!("Expected GroupWrap"),
    }
}

#[test]
fn rewrap_preserves_dek() {
    let plaintext = vec![0xEE; 2000];
    let dek = generate_dek();
    let file_id = generate_file_id();

    let envelope = encrypt_chunk(&dek, &file_id, 0, &plaintext, None).unwrap();

    let old_gk = generate_gk();
    let new_gk = generate_gk();
    let group_id = generate_file_id();

    let mut header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id,
        chunk_size: 4096,
        plaintext_size: plaintext.len() as u64,
        merkle_root: [0xaa; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![wrap_dek_for_group(&dek, group_id, 1, &old_gk)],
        signed_metadata: None,
        signature: None,
    };

    // Verify decrypt with v1 works
    let recovered_dek_v1 = unwrap_dek_with_group_key(&header.wraps[0], &old_gk).unwrap();
    let res_v1 = decrypt_chunk(&recovered_dek_v1, &file_id, 0, &envelope, None).unwrap();
    assert_eq!(plaintext, res_v1);

    // Rewrap from v1 to v2
    rewrap_dek_in_header(&mut header, &old_gk, &new_gk, 2).unwrap();

    // Verify decrypt with v2 works
    let recovered_dek_v2 = unwrap_dek_with_group_key(&header.wraps[0], &new_gk).unwrap();
    let res_v2 = decrypt_chunk(&recovered_dek_v2, &file_id, 0, &envelope, None).unwrap();
    assert_eq!(plaintext, res_v2);

    // Verify decrypt with v1 fails (wrap updated)
    let res_old = unwrap_dek_with_group_key(&header.wraps[0], &old_gk);
    assert!(matches!(res_old, Err(FileFormatError::WrongGroupKey)));
}

#[test]
fn rewrap_wrong_old_gk_fails() {
    let dek = generate_dek();
    let old_gk = generate_gk();
    let wrong_old_gk = generate_gk();
    let new_gk = generate_gk();

    let mut header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: generate_file_id(),
        chunk_size: 4096,
        plaintext_size: 1000,
        merkle_root: [0xaa; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![wrap_dek_for_group(&dek, generate_file_id(), 1, &old_gk)],
        signed_metadata: None,
        signature: None,
    };

    let res = rewrap_dek_in_header(&mut header, &wrong_old_gk, &new_gk, 2);
    assert!(matches!(res, Err(FileFormatError::WrongGroupKey)));
}

#[test]
fn rewrap_skips_non_group_wraps() {
    let dek = generate_dek();
    let old_gk = generate_gk();
    let new_gk = generate_gk();
    let group_id = generate_file_id();

    let password = b"skip-password-wrap-1";
    let pw_wrap =
        wrap_dek_with_password(&dek, password, KdfChoice::argon2id_interactive()).unwrap();
    let grp_wrap = wrap_dek_for_group(&dek, group_id, 1, &old_gk);

    let mut header = Header {
        version: VERSION,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: generate_file_id(),
        chunk_size: 4096,
        plaintext_size: 1000,
        merkle_root: [0x55; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![pw_wrap, grp_wrap],
        signed_metadata: None,
        signature: None,
    };

    let count = rewrap_dek_in_header(&mut header, &old_gk, &new_gk, 2).unwrap();
    assert_eq!(count, 1);

    // Verify GroupWrap is updated
    let unwrapped_grp = unwrap_dek_with_group_key(&header.wraps[1], &new_gk).unwrap();
    assert_eq!(dek, unwrapped_grp);

    // Verify PasswordWrap is unchanged and still decryptable with password
    let unwrapped_pw = unwrap_dek_with_password(&header.wraps[0], password).unwrap();
    assert_eq!(dek, unwrapped_pw);
}

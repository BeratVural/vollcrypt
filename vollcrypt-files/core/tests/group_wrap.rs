use vollcrypt_files_core::{
    generate_dek, generate_file_id, generate_gk, unwrap_dek_with_group_key, wrap_dek_for_group,
    FileFormatError, WrapEntry,
};

#[test]
fn group_wrap_roundtrip() {
    let dek = generate_dek();
    let group_id = generate_file_id();
    let gk_version = 42;
    let gk = generate_gk();

    let wrap = wrap_dek_for_group(&dek, group_id, gk_version, &gk);

    // Verify it is indeed GroupWrap and has correct fields
    if let WrapEntry::GroupWrap {
        group_id: w_group_id,
        gk_version: w_gk_version,
        ..
    } = &wrap
    {
        assert_eq!(*w_group_id, group_id);
        assert_eq!(*w_gk_version, gk_version);
    } else {
        panic!("Expected WrapEntry::GroupWrap");
    }

    // Roundtrip unwrap
    let unwrapped = unwrap_dek_with_group_key(&wrap, &gk).unwrap();
    assert_eq!(dek, unwrapped);
}

#[test]
fn wrong_gk_fails_group_unwrap() {
    let dek = generate_dek();
    let group_id = generate_file_id();
    let gk_version = 0;
    let gk = generate_gk();
    let wrong_gk = generate_gk();

    let wrap = wrap_dek_for_group(&dek, group_id, gk_version, &gk);

    // Unwrapping with wrong GK should fail
    let res = unwrap_dek_with_group_key(&wrap, &wrong_gk);
    assert!(matches!(res, Err(FileFormatError::WrongGroupKey)));
}

#[test]
fn group_wrap_wrong_wrap_type() {
    let password_wrap = WrapEntry::PasswordPbkdf2 {
        iterations: 10_000,
        salt: [0xaa; 16],
        wrapped_dek: [0xbb; 40],
    };

    let gk = generate_gk();
    let res = unwrap_dek_with_group_key(&password_wrap, &gk);
    assert!(matches!(res, Err(FileFormatError::WrongWrapType)));
}

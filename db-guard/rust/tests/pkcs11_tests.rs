#[cfg(feature = "pkcs11")]
#[test]
fn test_pkcs11_invalid_library_path() {
    use vollcrypt_db_guard::pkcs11_impl::decrypt_with_hsm;

    let res = decrypt_with_hsm(
        "non_existent_library_mock.dll",
        "123456",
        Some(0),
        "010203",
        b"ciphertext_data",
    );

    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(err_msg.contains("Failed to load PKCS#11 library") || err_msg.contains("library"));
}

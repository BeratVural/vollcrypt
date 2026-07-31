use vollcrypt_files_core::{
    generate_dek, unwrap_dek_with_password, wrap_dek_with_password, FileFormatError, KdfChoice,
};

#[test]
fn pbkdf2_wrap_unwrap_roundtrip() {
    let dek = generate_dek();
    let password = b"my-secure-password";

    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::pbkdf2_default()).unwrap();
    let unwrapped = unwrap_dek_with_password(&wrap, password).unwrap();

    assert_eq!(dek, unwrapped);
}

#[test]
fn argon2id_wrap_unwrap_roundtrip() {
    let dek = generate_dek();
    let password = b"my-secure-password";

    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::argon2id_default()).unwrap();
    let unwrapped = unwrap_dek_with_password(&wrap, password).unwrap();

    assert_eq!(dek, unwrapped);
}

#[test]
fn argon2id_interactive_roundtrip() {
    let dek = generate_dek();
    let password = b"my-secure-password";

    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::argon2id_interactive()).unwrap();
    let unwrapped = unwrap_dek_with_password(&wrap, password).unwrap();

    assert_eq!(dek, unwrapped);
}

#[test]
fn wrong_password_fails_pbkdf2() {
    let dek = generate_dek();
    let password = b"my-secure-password";
    let wrong_password = b"wrong-password";

    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::pbkdf2_default()).unwrap();
    let result = unwrap_dek_with_password(&wrap, wrong_password);

    assert!(matches!(result, Err(FileFormatError::WrongPassword)));
}

#[test]
fn wrong_password_fails_argon2id() {
    let dek = generate_dek();
    let password = b"my-secure-password";
    let wrong_password = b"wrong-password";

    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::argon2id_interactive()).unwrap();
    let result = unwrap_dek_with_password(&wrap, wrong_password);

    assert!(matches!(result, Err(FileFormatError::WrongPassword)));
}

#[test]
fn weak_pbkdf2_iterations_are_rejected() {
    let dek = generate_dek();
    let password = b"my-secure-password";

    let result = wrap_dek_with_password(
        &dek,
        password,
        KdfChoice::Pbkdf2 {
            iterations: 599_999,
        },
    );

    assert!(matches!(
        result,
        Err(FileFormatError::KdfParameterOutOfRange(_))
    ));
}

#[test]
fn weak_argon2_params_are_rejected() {
    let dek = generate_dek();
    let password = b"my-secure-password";

    for (m_cost, t_cost) in [(19_455, 2), (19_456, 1)] {
        let result = wrap_dek_with_password(
            &dek,
            password,
            KdfChoice::Argon2id {
                m_cost,
                t_cost,
                p_cost: 1,
            },
        );
        assert!(matches!(
            result,
            Err(FileFormatError::KdfParameterOutOfRange(_))
        ));
    }
}
#[test]
fn invalid_argon2_params_error() {
    let dek = generate_dek();
    let password = b"my-secure-password";

    // m_cost = 0 is invalid and should result in KdfParameterOutOfRange
    let result = wrap_dek_with_password(
        &dek,
        password,
        KdfChoice::Argon2id {
            m_cost: 0,
            t_cost: 3,
            p_cost: 4,
        },
    );

    assert!(matches!(
        result,
        Err(FileFormatError::KdfParameterOutOfRange(_))
    ));
}

use once_cell::sync::Lazy;
use sea_orm::sea_query::ValueType;
use sea_orm::Value;
use std::sync::Mutex;
use vollcrypt_db_guard::seaorm_impl::EncryptedString;
use vollcrypt_db_guard::{set_active_version, set_key};

static TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[test]
fn test_seaorm_encrypted_string_value_conversion() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let key_v1 = [99u8; 32];
    set_key("1", &key_v1);
    set_active_version("1").unwrap();

    let raw = "Sensitive SeaORM Value";
    let encrypted_string = EncryptedString(raw.to_string());

    // 1. Convert to Value (encryption)
    let val: Value = encrypted_string.into();

    if let Value::String(Some(ref s)) = val {
        assert!(s.starts_with("VOLLVALT:v1:"));
        assert_ne!(s.as_ref(), raw);

        // 2. Convert back (decryption)
        let decrypted = <EncryptedString as ValueType>::try_from(val).unwrap();
        assert_eq!(decrypted.0, raw);
    } else {
        panic!("Value is not a String");
    }
}

#[test]
fn test_seaorm_dual_read_fallback() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let key_v1 = [99u8; 32];
    set_key("1", &key_v1);
    set_active_version("1").unwrap();

    // Plaintext legacy value
    let legacy_val = Value::String(Some(Box::new("Legacy plaintext".to_string())));

    let decrypted = <EncryptedString as ValueType>::try_from(legacy_val).unwrap();
    assert_eq!(decrypted.0, "Legacy plaintext");
}

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use vollcrypt_db_guard::{set_key, set_active_version, encrypt_field, decrypt_field};
use vollcrypt_db_guard::diesel_impl::EncryptedString;

diesel::table! {
    users (id) {
        id -> Integer,
        name -> Text,
        credit_card -> Text,
    }
}

#[derive(Insertable, Queryable, Debug, PartialEq)]
#[diesel(table_name = users)]
struct User {
    id: i32,
    name: String,
    credit_card: EncryptedString,
}

#[test]
fn test_diesel_encrypted_string_roundtrip() {
    // 1. Initialize encryption key
    let key_v1 = [42u8; 32];
    set_key("1", &key_v1);
    set_active_version("1").unwrap();

    // 2. Establish in-memory SQLite connection
    let mut conn = SqliteConnection::establish(":memory:").unwrap();

    // Create a mock table
    diesel::sql_query("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, credit_card TEXT NOT NULL)")
        .execute(&mut conn)
        .unwrap();

    // 3. Insert a user
    let raw_card = "1234-5678-9012-3456";
    let new_user = User {
        id: 1,
        name: "Alice".to_string(),
        credit_card: EncryptedString(raw_card.to_string()),
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&mut conn)
        .unwrap();

    // 4. Query using raw SQL to verify it is encrypted in the DB
    #[derive(QueryableByName, Debug)]
    #[allow(dead_code)]
    struct RawUser {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        id: i32,
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        credit_card: String,
    }

    let raw_rows = diesel::sql_query("SELECT id, name, credit_card FROM users")
        .load::<RawUser>(&mut conn)
        .unwrap();

    assert_eq!(raw_rows.len(), 1);
    let stored_card = &raw_rows[0].credit_card;
    println!("STORED CARD IN DB: {:?}", stored_card);
    
    // It must start with key version prefix "VOLLVALT:v1:" and be encrypted (not the raw string)
    assert!(stored_card.starts_with("VOLLVALT:v1:"));
    assert_ne!(stored_card, raw_card);

    // 5. Query using Diesel ORM to verify it decrypts automatically
    let queried_users = users::table
        .load::<User>(&mut conn)
        .unwrap();

    assert_eq!(queried_users.len(), 1);
    assert_eq!(queried_users[0].credit_card.0, raw_card);
}

#[test]
fn test_key_rotation() {
    let key_v1 = [1u8; 32];
    let key_v2 = [2u8; 32];

    set_key("1", &key_v1);
    set_key("2", &key_v2);

    // Write with key v1
    set_active_version("1").unwrap();
    let text = "Sensitive Data";
    let encrypted_v1 = encrypt_field(text.as_bytes()).unwrap();
    assert!(encrypted_v1.starts_with("VOLLVALT:v1:"));

    // Rotate active key to v2
    set_active_version("2").unwrap();
    let encrypted_v2 = encrypt_field(text.as_bytes()).unwrap();
    assert!(encrypted_v2.starts_with("VOLLVALT:v2:"));

    // Both should decrypt successfully since both keys are in the registry
    let decrypted_v1 = decrypt_field(&encrypted_v1).unwrap();
    assert_eq!(String::from_utf8(decrypted_v1).unwrap(), text);

    let decrypted_v2 = decrypt_field(&encrypted_v2).unwrap();
    assert_eq!(String::from_utf8(decrypted_v2).unwrap(), text);
}

#[test]
fn test_rust_blind_indexing() {
    use vollcrypt_db_guard::compute_blind_index;

    let root_salt = b"test_root_salt_value_32_bytes_long";
    let val = "test_value_to_index";

    // 1. Derivation and uniqueness: different column names must produce different blind indices
    let idx_col1 = compute_blind_index(val, root_salt, "users.email").unwrap();
    let idx_col2 = compute_blind_index(val, root_salt, "users.ssn").unwrap();

    assert_ne!(idx_col1, idx_col2);

    // 2. Consistency: same value, root salt, and column name must produce same blind index
    let idx_col1_again = compute_blind_index(val, root_salt, "users.email").unwrap();
    assert_eq!(idx_col1, idx_col1_again);

    // 3. Different value on same column must produce different blind index
    let idx_col1_diff_val = compute_blind_index("different_value", root_salt, "users.email").unwrap();
    assert_ne!(idx_col1, idx_col1_diff_val);
}

#[test]
fn test_rust_context_and_rate_limiting() {
    use vollcrypt_db_guard::{set_context, clear_context, UserContext, CURRENT_CONTEXT};
    use vollcrypt_db_guard::{set_key, set_active_version, encrypt_field, decrypt_field};
    use vollcrypt_db_guard::{set_max_decrypt_rate, reset_rust_fail_closed_for_testing};

    // 1. Thread-local Context Verification
    let context = UserContext {
        role: Some("ADMIN".to_string()),
        user_id: Some("user_123".to_string()),
    };
    set_context(context.clone());

    CURRENT_CONTEXT.with(|ctx| {
        let borrowed = ctx.borrow();
        assert!(borrowed.is_some());
        let inner = borrowed.as_ref().unwrap();
        assert_eq!(inner.role, Some("ADMIN".to_string()));
        assert_eq!(inner.user_id, Some("user_123".to_string()));
    });

    clear_context();
    CURRENT_CONTEXT.with(|ctx| {
        assert!(ctx.borrow().is_none());
    });

    // 2. Rate Limiting and Fail-Closed Zeroization
    reset_rust_fail_closed_for_testing();
    let key = [42u8; 32];
    set_key("1", &key);
    set_active_version("1").unwrap();

    let text = "Decryption payload";
    let encrypted = encrypt_field(text.as_bytes()).unwrap();

    // Set rate limit to 3 decryptions
    set_max_decrypt_rate(3);

    // Call decrypt_field 3 times (allowed)
    assert!(decrypt_field(&encrypted).is_ok());
    assert!(decrypt_field(&encrypted).is_ok());
    assert!(decrypt_field(&encrypted).is_ok());

    // 4th call should trigger fail-closed rate limit error
    let res = decrypt_field(&encrypted);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Decryption rate limit exceeded"));

    // Key in registry must be cleared (zeroized)
    // Attempting another decryption should fail with "Decryption key version not found in registry"
    reset_rust_fail_closed_for_testing(); // reset fail closed state to check key presence
    let res_after = decrypt_field(&encrypted);
    assert!(res_after.is_err());
    assert!(res_after.unwrap_err().contains("Decryption key version not found"));
}

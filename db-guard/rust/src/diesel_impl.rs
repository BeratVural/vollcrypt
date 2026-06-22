use diesel::backend::Backend;
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use diesel::serialize::{self, ToSql, Output};
use diesel::sql_types::Text;
use std::fmt;
#[cfg(any(feature = "postgres", feature = "mysql"))]
use std::io::Write;

/// A wrapper type for `String` that automatically encrypts values stored in the database
/// and decrypts them when read.
///
/// Under the hood, it uses AES-256-GCM field-level encryption with version prefixes
/// for zero-downtime key rotation.
#[derive(Clone, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = Text)]
pub struct EncryptedString(pub String);

impl fmt::Debug for EncryptedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Prevents accidental leakage of sensitive PII or credit card numbers in system logs.
        write!(f, "EncryptedString([REDACTED])")
    }
}

// 1. SQLite ToSql (uses set_value)
#[cfg(feature = "sqlite")]
impl ToSql<Text, diesel::sqlite::Sqlite> for EncryptedString {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::sqlite::Sqlite>) -> serialize::Result {
        let encrypted = crate::encrypt_field(self.0.as_bytes())
            .map_err(|e| format!("Field encryption failed: {}", e))?;
        out.set_value(encrypted);
        Ok(serialize::IsNull::No)
    }
}

// 2. PostgreSQL ToSql (uses write_all)
#[cfg(feature = "postgres")]
impl ToSql<Text, diesel::pg::Pg> for EncryptedString {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::pg::Pg>) -> serialize::Result {
        let encrypted = crate::encrypt_field(self.0.as_bytes())
            .map_err(|e| format!("Field encryption failed: {}", e))?;
        out.write_all(encrypted.as_bytes())?;
        Ok(serialize::IsNull::No)
    }
}

// 3. MySQL ToSql (uses write_all)
#[cfg(feature = "mysql")]
impl ToSql<Text, diesel::mysql::Mysql> for EncryptedString {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::mysql::Mysql>) -> serialize::Result {
        let encrypted = crate::encrypt_field(self.0.as_bytes())
            .map_err(|e| format!("Field encryption failed: {}", e))?;
        out.write_all(encrypted.as_bytes())?;
        Ok(serialize::IsNull::No)
    }
}

// FromSql remains generic because it relies on String's FromSql implementation
impl<DB> FromSql<Text, DB> for EncryptedString
where
    DB: Backend,
    String: FromSql<Text, DB>,
{
    fn from_sql(bytes: DB::RawValue<'_>) -> deserialize::Result<Self> {
        let stored_val = <String as FromSql<Text, DB>>::from_sql(bytes)?;
        let decrypted_bytes = crate::decrypt_field(&stored_val)
            .map_err(|e| format!("Field decryption failed: {}", e))?;
        let decrypted_str = String::from_utf8(decrypted_bytes)
            .map_err(|e| format!("Field encoding conversion error: {}", e))?;
        Ok(EncryptedString(decrypted_str))
    }
}

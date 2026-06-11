use sea_orm::{TryGetable, DbErr, Value, TryGetError, QueryResult};
use sea_orm::sea_query::{ValueType, Nullable};
use std::fmt;

/// A wrapper type for `String` that automatically encrypts values stored in the database
/// and decrypts them when read.
///
/// Designed to work transparently within SeaORM Model entities.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedString(pub String);

impl fmt::Debug for EncryptedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mask PII data in debug logging
        write!(f, "EncryptedString([REDACTED])")
    }
}

impl From<EncryptedString> for Value {
    fn from(val: EncryptedString) -> Self {
        let encrypted = crate::encrypt_field(val.0.as_bytes()).unwrap_or_default();
        Value::String(Some(Box::new(encrypted)))
    }
}

impl ValueType for EncryptedString {
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            Value::String(Some(s)) => {
                let decrypted_bytes = crate::decrypt_field(&s)
                    .map_err(|_| sea_orm::sea_query::ValueTypeErr)?;
                let decrypted_str = String::from_utf8(decrypted_bytes)
                    .map_err(|_| sea_orm::sea_query::ValueTypeErr)?;
                Ok(EncryptedString(decrypted_str))
            }
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        "EncryptedString".to_string()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::Text
    }
}

impl TryGetable for EncryptedString {
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        let s = String::try_get_by(res, index)?;
        let decrypted_bytes = crate::decrypt_field(&s)
            .map_err(|e| TryGetError::DbErr(DbErr::Custom(format!("Decryption failed: {}", e))))?;
        let decrypted_str = String::from_utf8(decrypted_bytes)
            .map_err(|e| TryGetError::DbErr(DbErr::Custom(format!("UTF-8 decoding error: {}", e))))?;
        Ok(EncryptedString(decrypted_str))
    }
}

impl Nullable for EncryptedString {
    fn null() -> Value {
        Value::String(None)
    }
}

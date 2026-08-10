use std::path::{Path, PathBuf};
use std::time::Duration;

use mysql::prelude::Queryable;
use mysql::{
    AccessMode, Conn, IsolationLevel, Opts, OptsBuilder, Row, SslOpts, Transaction, TxOpts, Value,
    from_value_opt, params,
};
use sha2::{Digest, Sha256};

use crate::{
    CanonicalReportBuilder, CanonicalSourceSchema, DatabaseError, DatabaseScanConfig,
    DatabaseScanReport, DatabaseValue, Result, SCHEMA_DOMAIN, validate_identifier,
};

const MAX_CA_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct MySqlScanOptions {
    connection: String,
    database: String,
    ca_file: Option<PathBuf>,
}

impl MySqlScanOptions {
    pub fn new(connection: impl Into<String>) -> Result<Self> {
        let connection = connection.into();
        let parsed = Opts::from_url(&connection)
            .map_err(|_| DatabaseError::Config("invalid MySQL connection settings".to_owned()))?;
        if parsed.get_socket().is_some() {
            return Err(DatabaseError::Config(
                "MySQL Unix sockets and named pipes are outside the TLS adapter boundary"
                    .to_owned(),
            ));
        }
        let database = parsed
            .get_db_name()
            .ok_or_else(|| {
                DatabaseError::Config("MySQL connection settings must select a database".to_owned())
            })?
            .to_owned();
        let options = Self {
            connection,
            database,
            ca_file: None,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn with_ca_file(mut self, ca_file: Option<PathBuf>) -> Result<Self> {
        self.ca_file = ca_file;
        self.validate()?;
        Ok(self)
    }

    pub fn database(&self) -> &str {
        &self.database
    }

    fn validate(&self) -> Result<()> {
        validate_identifier(&self.database, "MySQL database")?;
        if let Some(path) = &self.ca_file {
            validate_ca_file(path)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct MySqlColumn {
    name: String,
    data_type: String,
    column_type: String,
    nullable: bool,
    default_value: Option<String>,
    extra: String,
    collation: Option<String>,
    character_set: Option<String>,
    numeric_precision: Option<u64>,
    numeric_scale: Option<u64>,
    datetime_precision: Option<u64>,
}

pub fn scan_mysql(
    options: &MySqlScanOptions,
    config: &DatabaseScanConfig,
    scope_id: &str,
    created_at_unix_ms: u64,
) -> Result<DatabaseScanReport> {
    options.validate()?;
    config.validate()?;
    validate_identifier(scope_id, "scope")?;

    let parsed = Opts::from_url(&options.connection)
        .map_err(|_| DatabaseError::Config("invalid MySQL connection settings".to_owned()))?;
    let ssl = SslOpts::default().with_root_cert_path(options.ca_file.clone());
    let connection_options = OptsBuilder::from_opts(parsed)
        .prefer_socket(false)
        .tcp_connect_timeout(Some(Duration::from_secs(10)))
        .init(vec!["SET time_zone = '+00:00'"])
        .ssl_opts(Some(ssl));
    let mut connection = Conn::new(connection_options).map_err(mysql_error)?;
    let transaction_options = TxOpts::default()
        .set_isolation_level(Some(IsolationLevel::RepeatableRead))
        .set_access_mode(Some(AccessMode::ReadOnly))
        .set_with_consistent_snapshot(true);
    let mut transaction = connection
        .start_transaction(transaction_options)
        .map_err(mysql_error)?;
    let scan = scan_transaction(
        &mut transaction,
        options,
        config,
        scope_id,
        created_at_unix_ms,
    );
    let rollback = transaction.rollback().map_err(mysql_error);
    match (scan, rollback) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(report), Ok(())) => Ok(report),
    }
}

fn scan_transaction(
    transaction: &mut Transaction<'_>,
    options: &MySqlScanOptions,
    config: &DatabaseScanConfig,
    scope_id: &str,
    created_at_unix_ms: u64,
) -> Result<DatabaseScanReport> {
    let columns = load_columns(transaction, options, config)?;
    let key_columns = load_key_columns(transaction, options, config, &columns)?;
    let key_indexes = resolve_key_indexes(&columns, &key_columns)?;
    let schema_material = schema_material(options, config, &columns);
    let schema_hash = hash_schema(&schema_material);
    let schema_size = u64::try_from(schema_material.len())
        .map_err(|_| DatabaseError::Limit("MySQL schema length exceeds u64".to_owned()))?;
    let column_names = columns.iter().map(|column| column.name.clone()).collect();
    let mut builder = CanonicalReportBuilder::new(
        config,
        CanonicalSourceSchema {
            key_columns,
            key_indexes,
            column_names,
            schema_hash,
            schema_size,
        },
        scope_id,
        created_at_unix_ms,
    )?;

    let select = mysql_select(config, &columns);
    let rows = transaction.query_iter(select).map_err(mysql_error)?;
    for row in rows {
        let values = row
            .map_err(mysql_error)?
            .unwrap()
            .into_iter()
            .zip(&columns)
            .map(|(value, column)| mysql_value(value, column, config.limits.max_value_bytes))
            .collect::<Result<Vec<_>>>()?;
        builder.push_row(values)?;
    }
    builder.finish()
}

fn load_columns(
    transaction: &mut Transaction<'_>,
    options: &MySqlScanOptions,
    config: &DatabaseScanConfig,
) -> Result<Vec<MySqlColumn>> {
    let rows: Vec<Row> = transaction
        .exec(
            r#"SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, IS_NULLABLE = 'YES',
                      COLUMN_DEFAULT, EXTRA, COLLATION_NAME, CHARACTER_SET_NAME,
                      NUMERIC_PRECISION, NUMERIC_SCALE, DATETIME_PRECISION
                 FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = :database AND TABLE_NAME = :table
                ORDER BY ORDINAL_POSITION"#,
            params! {
                "database" => &options.database,
                "table" => &config.table,
            },
        )
        .map_err(mysql_error)?;
    if rows.is_empty() {
        return Err(DatabaseError::Config(format!(
            "MySQL table does not exist: {}.{}",
            options.database, config.table
        )));
    }
    if rows.len() > config.limits.max_columns {
        return Err(DatabaseError::Limit(
            "MySQL column count exceeds its limit".to_owned(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let column = MySqlColumn {
                name: required_column(&row, 0, "COLUMN_NAME")?,
                data_type: required_column(&row, 1, "DATA_TYPE")?,
                column_type: required_column(&row, 2, "COLUMN_TYPE")?,
                nullable: required_column::<i64>(&row, 3, "IS_NULLABLE")? != 0,
                default_value: optional_column(&row, 4, "COLUMN_DEFAULT")?,
                extra: required_column(&row, 5, "EXTRA")?,
                collation: optional_column(&row, 6, "COLLATION_NAME")?,
                character_set: optional_column(&row, 7, "CHARACTER_SET_NAME")?,
                numeric_precision: optional_column(&row, 8, "NUMERIC_PRECISION")?,
                numeric_scale: optional_column(&row, 9, "NUMERIC_SCALE")?,
                datetime_precision: optional_column(&row, 10, "DATETIME_PRECISION")?,
            };
            validate_identifier(&column.name, "MySQL column")?;
            Ok(column)
        })
        .collect()
}

fn load_key_columns(
    transaction: &mut Transaction<'_>,
    options: &MySqlScanOptions,
    config: &DatabaseScanConfig,
    columns: &[MySqlColumn],
) -> Result<Vec<String>> {
    if !config.key_columns.is_empty() {
        return config
            .key_columns
            .iter()
            .map(|configured| {
                columns
                    .iter()
                    .find(|column| column.name.eq_ignore_ascii_case(configured))
                    .map(|column| column.name.clone())
                    .ok_or_else(|| {
                        DatabaseError::Config(format!(
                            "configured key column does not exist: {configured}"
                        ))
                    })
            })
            .collect();
    }
    let keys: Vec<String> = transaction
        .exec(
            r#"SELECT COLUMN_NAME
                 FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                WHERE TABLE_SCHEMA = :database AND TABLE_NAME = :table
                  AND CONSTRAINT_NAME = 'PRIMARY'
                ORDER BY ORDINAL_POSITION"#,
            params! {
                "database" => &options.database,
                "table" => &config.table,
            },
        )
        .map_err(mysql_error)?;
    if keys.is_empty() {
        return Err(DatabaseError::Config(
            "MySQL table has no primary key; provide one or more --key-column values".to_owned(),
        ));
    }
    Ok(keys)
}

fn resolve_key_indexes(columns: &[MySqlColumn], key_columns: &[String]) -> Result<Vec<usize>> {
    key_columns
        .iter()
        .map(|key| {
            columns
                .iter()
                .position(|column| column.name == *key)
                .ok_or_else(|| {
                    DatabaseError::Config(format!("MySQL key column is unavailable: {key}"))
                })
        })
        .collect()
}

fn mysql_select(config: &DatabaseScanConfig, columns: &[MySqlColumn]) -> String {
    let projection = columns
        .iter()
        .map(|column| quote_identifier(&column.name))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "SELECT {projection} FROM {}",
        quote_identifier(&config.table)
    )
}

fn mysql_value(value: Value, column: &MySqlColumn, maximum: u64) -> Result<DatabaseValue> {
    let value = match value {
        Value::NULL => DatabaseValue::Null,
        Value::Bytes(bytes) if is_binary_type(&column.data_type) => DatabaseValue::Blob(bytes),
        Value::Bytes(bytes) => DatabaseValue::Text(bytes),
        Value::Int(value) => DatabaseValue::Integer(value),
        Value::UInt(value) => DatabaseValue::Unsigned(value),
        Value::Float(value) if value.is_finite() => DatabaseValue::Real(f64::from(value).to_bits()),
        Value::Double(value) if value.is_finite() => DatabaseValue::Real(value.to_bits()),
        Value::Float(_) | Value::Double(_) => {
            return Err(DatabaseError::Config(format!(
                "non-finite MySQL floating-point value is not canonical: {}",
                column.name
            )));
        }
        Value::Date(year, month, day, hour, minute, second, micros) => {
            let mut bytes = Vec::with_capacity(11);
            bytes.extend_from_slice(&year.to_be_bytes());
            bytes.extend_from_slice(&[month, day, hour, minute, second]);
            bytes.extend_from_slice(&micros.to_be_bytes());
            DatabaseValue::Blob(bytes)
        }
        Value::Time(negative, days, hour, minute, second, micros) => {
            let mut bytes = Vec::with_capacity(12);
            bytes.push(u8::from(negative));
            bytes.extend_from_slice(&days.to_be_bytes());
            bytes.extend_from_slice(&[hour, minute, second]);
            bytes.extend_from_slice(&micros.to_be_bytes());
            DatabaseValue::Blob(bytes)
        }
    };
    if crate::value_size(&value) > maximum {
        return Err(DatabaseError::Limit(
            "individual MySQL value exceeds its limit".to_owned(),
        ));
    }
    Ok(value)
}

fn is_binary_type(data_type: &str) -> bool {
    matches!(
        data_type.to_ascii_lowercase().as_str(),
        "binary"
            | "varbinary"
            | "tinyblob"
            | "blob"
            | "mediumblob"
            | "longblob"
            | "bit"
            | "geometry"
    )
}

fn schema_material(
    options: &MySqlScanOptions,
    config: &DatabaseScanConfig,
    columns: &[MySqlColumn],
) -> Vec<u8> {
    let mut material = Vec::new();
    append_field(&mut material, b"mysql-v1");
    append_field(&mut material, options.database.as_bytes());
    append_field(&mut material, config.table.as_bytes());
    for column in columns {
        append_field(&mut material, column.name.as_bytes());
        append_field(&mut material, column.data_type.as_bytes());
        append_field(&mut material, column.column_type.as_bytes());
        material.push(u8::from(column.nullable));
        append_optional(&mut material, column.default_value.as_deref());
        append_field(&mut material, column.extra.as_bytes());
        append_optional(&mut material, column.collation.as_deref());
        append_optional(&mut material, column.character_set.as_deref());
        append_optional_u64(&mut material, column.numeric_precision);
        append_optional_u64(&mut material, column.numeric_scale);
        append_optional_u64(&mut material, column.datetime_precision);
    }
    material
}

fn hash_schema(material: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SCHEMA_DOMAIN);
    hash.update(material);
    hash.finalize().into()
}

fn append_optional(target: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            target.push(1);
            append_field(target, value.as_bytes());
        }
        None => target.push(0),
    }
}

fn append_optional_u64(target: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            target.push(1);
            target.extend_from_slice(&value.to_be_bytes());
        }
        None => target.push(0),
    }
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn quote_identifier(identifier: &str) -> String {
    format!("\x60{}\x60", identifier.replace('\x60', "\x60\x60"))
}

fn required_column<T>(row: &Row, index: usize, name: &str) -> Result<T>
where
    T: mysql::prelude::FromValue,
{
    optional_column(row, index, name)?.ok_or_else(|| {
        DatabaseError::MySql(format!("MySQL metadata field {name} is unexpectedly NULL"))
    })
}

fn optional_column<T>(row: &Row, index: usize, name: &str) -> Result<Option<T>>
where
    T: mysql::prelude::FromValue,
{
    convert_optional(row.as_ref(index), name)
}

fn convert_optional<T>(value: Option<&Value>, name: &str) -> Result<Option<T>>
where
    T: mysql::prelude::FromValue,
{
    match value {
        None => Err(DatabaseError::MySql(format!(
            "MySQL metadata row did not contain field {name}"
        ))),
        Some(Value::NULL) => Ok(None),
        Some(value) => from_value_opt(value.clone()).map(Some).map_err(|error| {
            DatabaseError::MySql(format!(
                "MySQL metadata field {name} has an unexpected value: {error:?}"
            ))
        }),
    }
}

fn validate_ca_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_CA_BYTES {
        return Err(DatabaseError::Config(
            "MySQL CA path must be a regular non-symlink file no larger than 16 MiB".to_owned(),
        ));
    }
    Ok(())
}

fn mysql_error(error: mysql::Error) -> DatabaseError {
    DatabaseError::MySql(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(name: &str, data_type: &str) -> MySqlColumn {
        MySqlColumn {
            name: name.to_owned(),
            data_type: data_type.to_owned(),
            column_type: data_type.to_owned(),
            nullable: false,
            default_value: None,
            extra: String::new(),
            collation: None,
            character_set: None,
            numeric_precision: None,
            numeric_scale: None,
            datetime_precision: None,
        }
    }

    #[test]
    fn connection_requires_selected_database() {
        assert!(MySqlScanOptions::new("mysql://user@localhost").is_err());
        assert!(MySqlScanOptions::new("mysql://user@localhost/shield").is_ok());
    }

    #[test]
    fn select_and_schema_bind_database_table_and_types() {
        let options = MySqlScanOptions::new("mysql://user@localhost/shield").unwrap();
        let config = DatabaseScanConfig::new("records", vec![]).unwrap();
        let columns = vec![column("id", "bigint"), column("payload", "text")];
        assert_eq!(
            mysql_select(&config, &columns),
            "SELECT `id`,`payload` FROM `records`"
        );
        let first = hash_schema(&schema_material(&options, &config, &columns));
        let changed = vec![column("id", "bigint"), column("payload", "blob")];
        assert_ne!(
            first,
            hash_schema(&schema_material(&options, &config, &changed))
        );
    }

    #[test]
    fn values_preserve_unsigned_binary_and_finite_float_types() {
        assert_eq!(
            mysql_value(Value::UInt(u64::MAX), &column("id", "bigint"), 16).unwrap(),
            DatabaseValue::Unsigned(u64::MAX)
        );
        assert_eq!(
            mysql_value(Value::Bytes(vec![0xff]), &column("payload", "blob"), 16).unwrap(),
            DatabaseValue::Blob(vec![0xff])
        );
        assert!(mysql_value(Value::Double(f64::NAN), &column("n", "double"), 16).is_err());
    }

    #[test]
    fn nullable_metadata_is_decoded_without_panicking() {
        assert_eq!(
            convert_optional::<String>(Some(&Value::NULL), "COLUMN_DEFAULT").unwrap(),
            None
        );
        assert_eq!(
            convert_optional::<u64>(Some(&Value::UInt(65)), "NUMERIC_PRECISION").unwrap(),
            Some(65)
        );
        assert!(convert_optional::<u64>(None, "NUMERIC_PRECISION").is_err());
    }
}

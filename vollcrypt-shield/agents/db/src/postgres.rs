use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{TryStreamExt, pin_mut};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use tokio_postgres::IsolationLevel;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::ToSql;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::{
    CanonicalReportBuilder, CanonicalSourceSchema, DatabaseError, DatabaseScanConfig,
    DatabaseScanReport, DatabaseValue, Result, SCHEMA_DOMAIN, validate_identifier,
};

const MAX_CA_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct PostgresScanOptions {
    connection: String,
    schema: String,
    ca_file: Option<PathBuf>,
}

impl PostgresScanOptions {
    pub fn new(connection: impl Into<String>) -> Result<Self> {
        let options = Self {
            connection: connection.into(),
            schema: "public".to_owned(),
            ca_file: None,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn with_schema(mut self, schema: impl Into<String>) -> Result<Self> {
        self.schema = schema.into();
        self.validate()?;
        Ok(self)
    }

    pub fn with_ca_file(mut self, ca_file: Option<PathBuf>) -> Result<Self> {
        self.ca_file = ca_file;
        self.validate()?;
        Ok(self)
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<()> {
        if self.connection.trim().is_empty() {
            return Err(DatabaseError::Config(
                "PostgreSQL connection settings must not be empty".to_owned(),
            ));
        }
        validate_identifier(&self.schema, "PostgreSQL schema")?;
        if let Some(path) = &self.ca_file {
            validate_ca_file(path)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct PostgresColumn {
    name: String,
    data_type: String,
    udt_schema: String,
    udt_name: String,
    nullable: bool,
    default_value: Option<String>,
    identity: String,
    generated: String,
    generation_expression: Option<String>,
    collation: Option<String>,
}

pub async fn scan_postgres(
    options: &PostgresScanOptions,
    config: &DatabaseScanConfig,
    scope_id: &str,
    created_at_unix_ms: u64,
) -> Result<DatabaseScanReport> {
    options.validate()?;
    config.validate()?;
    validate_identifier(scope_id, "scope")?;

    let mut connection_config = tokio_postgres::Config::from_str(&options.connection)
        .map_err(|_| DatabaseError::Config("invalid PostgreSQL connection settings".to_owned()))?;
    connection_config
        .ssl_mode(SslMode::Require)
        .connect_timeout(Duration::from_secs(10));
    let connector = postgres_tls_connector(options.ca_file.as_deref())?;
    let (mut client, connection) = connection_config
        .connect(connector)
        .await
        .map_err(postgres_error)?;
    let connection_task = tokio::spawn(connection);
    let scan = scan_client(&mut client, options, config, scope_id, created_at_unix_ms).await;
    drop(client);
    let connection_result = connection_task.await.map_err(|_| {
        DatabaseError::Postgres("PostgreSQL connection task terminated unexpectedly".to_owned())
    })?;
    match (scan, connection_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(postgres_error(error)),
        (Ok(report), Ok(())) => Ok(report),
    }
}

async fn scan_client(
    client: &mut tokio_postgres::Client,
    options: &PostgresScanOptions,
    config: &DatabaseScanConfig,
    scope_id: &str,
    created_at_unix_ms: u64,
) -> Result<DatabaseScanReport> {
    let transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(postgres_error)?;
    transaction
        .batch_execute(
            r#"SET LOCAL TIME ZONE 'UTC';
               SET LOCAL DateStyle = 'ISO, YMD';
               SET LOCAL IntervalStyle = 'iso_8601';
               SET LOCAL extra_float_digits = 3;"#,
        )
        .await
        .map_err(postgres_error)?;

    let columns = load_columns(&transaction, options, config).await?;
    let key_columns = load_key_columns(&transaction, options, config, &columns).await?;
    let key_indexes = resolve_key_indexes(&columns, &key_columns)?;
    let schema_material = schema_material(options, config, &columns);
    let schema_hash = hash_schema(&schema_material);
    let schema_size = u64::try_from(schema_material.len())
        .map_err(|_| DatabaseError::Limit("PostgreSQL schema length exceeds u64".to_owned()))?;
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

    let select = postgres_select(options, config, &columns);
    let rows = transaction
        .query_raw(&select, std::iter::empty::<&(dyn ToSql + Sync)>())
        .await
        .map_err(postgres_error)?;
    pin_mut!(rows);
    while let Some(row) = rows.try_next().await.map_err(postgres_error)? {
        let mut values = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            let value: Option<String> = row.try_get(index).map_err(postgres_error)?;
            let value = match value {
                None => DatabaseValue::Null,
                Some(value) => {
                    let bytes = value.into_bytes();
                    if bytes.len() as u64 > config.limits.max_value_bytes {
                        return Err(DatabaseError::Limit(
                            "individual PostgreSQL value exceeds its limit".to_owned(),
                        ));
                    }
                    DatabaseValue::Text(bytes)
                }
            };
            values.push(value);
        }
        builder.push_row(values)?;
    }
    transaction.rollback().await.map_err(postgres_error)?;
    builder.finish()
}

async fn load_columns(
    transaction: &tokio_postgres::Transaction<'_>,
    options: &PostgresScanOptions,
    config: &DatabaseScanConfig,
) -> Result<Vec<PostgresColumn>> {
    let rows = transaction
        .query(
            r#"SELECT column_name, data_type, udt_schema, udt_name,
                      is_nullable = 'YES', column_default, identity_generation,
                      is_generated, generation_expression, collation_name
                 FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = $2
                ORDER BY ordinal_position"#,
            &[&options.schema, &config.table],
        )
        .await
        .map_err(postgres_error)?;
    if rows.is_empty() {
        return Err(DatabaseError::Config(format!(
            "PostgreSQL table does not exist: {}.{}",
            options.schema, config.table
        )));
    }
    if rows.len() > config.limits.max_columns {
        return Err(DatabaseError::Limit(
            "PostgreSQL column count exceeds its limit".to_owned(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let column = PostgresColumn {
                name: row.try_get(0).map_err(postgres_error)?,
                data_type: row.try_get(1).map_err(postgres_error)?,
                udt_schema: row.try_get(2).map_err(postgres_error)?,
                udt_name: row.try_get(3).map_err(postgres_error)?,
                nullable: row.try_get(4).map_err(postgres_error)?,
                default_value: row.try_get(5).map_err(postgres_error)?,
                identity: row
                    .try_get::<_, Option<String>>(6)
                    .map_err(postgres_error)?
                    .unwrap_or_default(),
                generated: row.try_get(7).map_err(postgres_error)?,
                generation_expression: row.try_get(8).map_err(postgres_error)?,
                collation: row.try_get(9).map_err(postgres_error)?,
            };
            validate_identifier(&column.name, "PostgreSQL column")?;
            validate_postgres_type(&column)?;
            Ok(column)
        })
        .collect()
}

async fn load_key_columns(
    transaction: &tokio_postgres::Transaction<'_>,
    options: &PostgresScanOptions,
    config: &DatabaseScanConfig,
    columns: &[PostgresColumn],
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
    let rows = transaction
        .query(
            r#"SELECT attribute.attname
                 FROM pg_catalog.pg_index AS idx
                 JOIN pg_catalog.pg_class AS table_class ON table_class.oid = idx.indrelid
                 JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
                 JOIN unnest(idx.indkey) WITH ORDINALITY AS key(attnum, position) ON true
                 JOIN pg_catalog.pg_attribute AS attribute
                   ON attribute.attrelid = table_class.oid AND attribute.attnum = key.attnum
                WHERE idx.indisprimary AND namespace.nspname = $1 AND table_class.relname = $2
                ORDER BY key.position"#,
            &[&options.schema, &config.table],
        )
        .await
        .map_err(postgres_error)?;
    if rows.is_empty() {
        return Err(DatabaseError::Config(
            "PostgreSQL table has no primary key; provide one or more --key-column values"
                .to_owned(),
        ));
    }
    rows.into_iter()
        .map(|row| row.try_get(0).map_err(postgres_error))
        .collect()
}

fn resolve_key_indexes(columns: &[PostgresColumn], key_columns: &[String]) -> Result<Vec<usize>> {
    key_columns
        .iter()
        .map(|key| {
            columns
                .iter()
                .position(|column| column.name == *key)
                .ok_or_else(|| {
                    DatabaseError::Config(format!("PostgreSQL key column is unavailable: {key}"))
                })
        })
        .collect()
}

fn validate_postgres_type(column: &PostgresColumn) -> Result<()> {
    if column.data_type.eq_ignore_ascii_case("money")
        || column.udt_name.eq_ignore_ascii_case("money")
    {
        return Err(DatabaseError::Config(format!(
            "PostgreSQL money column is locale-dependent and unsupported: {}",
            column.name
        )));
    }
    if column.udt_schema != "pg_catalog" && column.udt_schema != "information_schema" {
        return Err(DatabaseError::Config(format!(
            "PostgreSQL user-defined type is outside the canonical adapter boundary: {}",
            column.name
        )));
    }
    Ok(())
}

fn postgres_select(
    options: &PostgresScanOptions,
    config: &DatabaseScanConfig,
    columns: &[PostgresColumn],
) -> String {
    let projection = columns
        .iter()
        .map(|column| {
            let name = quote_identifier(&column.name);
            format!("({name})::text AS {name}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "SELECT {projection} FROM {}.{}",
        quote_identifier(&options.schema),
        quote_identifier(&config.table)
    )
}

fn schema_material(
    options: &PostgresScanOptions,
    config: &DatabaseScanConfig,
    columns: &[PostgresColumn],
) -> Vec<u8> {
    let mut material = Vec::new();
    append_field(&mut material, b"postgresql-v1");
    append_field(&mut material, options.schema.as_bytes());
    append_field(&mut material, config.table.as_bytes());
    for column in columns {
        append_field(&mut material, column.name.as_bytes());
        append_field(&mut material, column.data_type.as_bytes());
        append_field(&mut material, column.udt_schema.as_bytes());
        append_field(&mut material, column.udt_name.as_bytes());
        material.push(u8::from(column.nullable));
        append_optional(&mut material, column.default_value.as_deref());
        append_field(&mut material, column.identity.as_bytes());
        append_field(&mut material, column.generated.as_bytes());
        append_optional(&mut material, column.generation_expression.as_deref());
        append_optional(&mut material, column.collation.as_deref());
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

fn append_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn quote_identifier(identifier: &str) -> String {
    format!(r#""{}""#, identifier.replace('"', r#""""#))
}

fn postgres_tls_connector(ca_file: Option<&Path>) -> Result<MakeRustlsConnect> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if let Some(path) = ca_file {
        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| {
                DatabaseError::Config("PostgreSQL CA file contains invalid PEM data".to_owned())
            })?;
        if certificates.is_empty() {
            return Err(DatabaseError::Config(
                "PostgreSQL CA file contains no certificates".to_owned(),
            ));
        }
        for certificate in certificates {
            roots.add(certificate).map_err(|_| {
                DatabaseError::Config("PostgreSQL CA certificate is invalid".to_owned())
            })?;
        }
    }
    if roots.is_empty() {
        return Err(DatabaseError::Config(
            "no PostgreSQL TLS trust roots are available".to_owned(),
        ));
    }
    let provider = rustls::crypto::ring::default_provider();
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| DatabaseError::Config("PostgreSQL TLS profile is unavailable".to_owned()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(tls))
}

fn validate_ca_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_CA_BYTES {
        return Err(DatabaseError::Config(
            "PostgreSQL CA path must be a regular non-symlink file no larger than 16 MiB"
                .to_owned(),
        ));
    }
    Ok(())
}

fn postgres_error(error: tokio_postgres::Error) -> DatabaseError {
    DatabaseError::Postgres(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(name: &str) -> PostgresColumn {
        PostgresColumn {
            name: name.to_owned(),
            data_type: "text".to_owned(),
            udt_schema: "pg_catalog".to_owned(),
            udt_name: "text".to_owned(),
            nullable: false,
            default_value: None,
            identity: String::new(),
            generated: "NEVER".to_owned(),
            generation_expression: None,
            collation: None,
        }
    }

    #[test]
    fn select_quotes_schema_table_and_columns() {
        let options = PostgresScanOptions::new("host=database")
            .unwrap()
            .with_schema("audit")
            .unwrap();
        let config = DatabaseScanConfig::new("records", vec![]).unwrap();
        assert_eq!(
            postgres_select(&options, &config, &[column("id"), column("payload")]),
            r#"SELECT ("id")::text AS "id",("payload")::text AS "payload" FROM "audit"."records""#
        );
    }

    #[test]
    fn schema_hash_binds_postgres_namespace_and_types() {
        let base = PostgresScanOptions::new("host=database").unwrap();
        let alternate = base.clone().with_schema("audit").unwrap();
        let config = DatabaseScanConfig::new("records", vec![]).unwrap();
        let columns = vec![column("id")];
        assert_ne!(
            hash_schema(&schema_material(&base, &config, &columns)),
            hash_schema(&schema_material(&alternate, &config, &columns))
        );
        let mut changed = columns.clone();
        changed[0].udt_name = "varchar".to_owned();
        assert_ne!(
            hash_schema(&schema_material(&base, &config, &columns)),
            hash_schema(&schema_material(&base, &config, &changed))
        );
    }

    #[test]
    fn locale_dependent_and_user_defined_types_fail_closed() {
        let mut unsupported = column("amount");
        unsupported.data_type = "money".to_owned();
        unsupported.udt_name = "money".to_owned();
        assert!(validate_postgres_type(&unsupported).is_err());
        unsupported.data_type = "USER-DEFINED".to_owned();
        unsupported.udt_name = "custom".to_owned();
        unsupported.udt_schema = "public".to_owned();
        assert!(validate_postgres_type(&unsupported).is_err());
    }
}

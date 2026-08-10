#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{
    DifferenceKind, EntryKind, IntegrityEntry, MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey,
    NormalizedPath, SignedSnapshot, Snapshot, VerificationDifference, VerificationReport,
};

mod mysql;
mod postgres;

pub use mysql::{MySqlScanOptions, scan_mysql};
pub use postgres::{PostgresScanOptions, scan_postgres};

const BASELINE_FILE: &str = "baseline.snapshot.cbor";
const KEY_DIRECTORY: &str = "keys";
const PUBLIC_KEY_FILE: &str = "agent.public";
const SECRET_KEY_FILE: &str = "agent.seed";
const SCOPE_FILE: &str = "scope.id";
const MAX_BASELINE_BYTES: u64 = 134_217_728;
const ROW_KEY_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-DB-ROW-KEY-v1\0";
const ROW_CONTENT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-DB-ROW-CONTENT-v1\0";
const SCHEMA_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-DB-SCHEMA-v1\0";
const DB_GUARD_CONTEXT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-DB-GUARD-CONTEXT-v1\0";
const MAX_DB_GUARD_CONTEXT_BYTES: u64 = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("PostgreSQL error: {0}")]
    Postgres(String),
    #[error("MySQL error: {0}")]
    MySql(String),
    #[error("invalid database scan configuration: {0}")]
    Config(String),
    #[error("database scan limit exceeded: {0}")]
    Limit(String),
    #[error("invalid database agent state: {0}")]
    State(String),
    #[error(transparent)]
    Core(#[from] vollcrypt_shield_core::ShieldError),
}

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseScanLimits {
    pub max_rows: u64,
    pub max_value_bytes: u64,
    pub max_total_value_bytes: u64,
    pub max_columns: usize,
}

impl Default for DatabaseScanLimits {
    fn default() -> Self {
        Self {
            max_rows: 1_000_000,
            max_value_bytes: 16_777_216,
            max_total_value_bytes: 1_073_741_824,
            max_columns: 1_024,
        }
    }
}

impl DatabaseScanLimits {
    fn validate(&self) -> Result<()> {
        if self.max_rows == 0
            || self.max_value_bytes == 0
            || self.max_total_value_bytes < self.max_value_bytes
            || self.max_columns == 0
            || self.max_columns > 16_384
        {
            return Err(DatabaseError::Config(
                "database scan limits are inconsistent or zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseScanConfig {
    pub table: String,
    pub key_columns: Vec<String>,
    pub limits: DatabaseScanLimits,
    pub db_guard_context: Option<DbGuardContextV1>,
}

impl DatabaseScanConfig {
    pub fn new(table: impl Into<String>, key_columns: Vec<String>) -> Result<Self> {
        let config = Self {
            table: table.into(),
            key_columns,
            limits: DatabaseScanLimits::default(),
            db_guard_context: None,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_db_guard_context(mut self, context: Option<DbGuardContextV1>) -> Result<Self> {
        self.db_guard_context = context;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_identifier(&self.table, "table")?;
        self.limits.validate()?;
        let mut seen = BTreeSet::new();
        for column in &self.key_columns {
            validate_identifier(column, "key column")?;
            if !seen.insert(column.to_ascii_lowercase()) {
                return Err(DatabaseError::Config(
                    "key columns contain a duplicate".to_owned(),
                ));
            }
        }
        if let Some(context) = &self.db_guard_context {
            context.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbGuardContextV1 {
    pub format_version: u16,
    pub database_id: String,
    pub kms_route_id: Option<String>,
    pub encryption_policy_digest: String,
    pub key_epoch: u64,
}

impl DbGuardContextV1 {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1 {
            return Err(DatabaseError::Config(
                "unsupported db-guard context format version".to_owned(),
            ));
        }
        validate_context_identifier(&self.database_id, "db-guard databaseId")?;
        if let Some(route) = &self.kms_route_id {
            validate_context_identifier(route, "db-guard kmsRouteId")?;
        }
        decode_context_digest(&self.encryption_policy_digest)?;
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.format_version.to_be_bytes());
        append_context_field(&mut bytes, self.database_id.as_bytes());
        match &self.kms_route_id {
            Some(route) => {
                bytes.push(1);
                append_context_field(&mut bytes, route.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&decode_context_digest(&self.encryption_policy_digest)?);
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        Ok(bytes)
    }
}

pub fn load_db_guard_context_v1(path: &Path) -> Result<DbGuardContextV1> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DB_GUARD_CONTEXT_BYTES
    {
        return Err(DatabaseError::Config(
            "db-guard context must be a regular non-symlink file no larger than 64 KiB".to_owned(),
        ));
    }
    let context: DbGuardContextV1 =
        serde_json::from_slice(&std::fs::read(path)?).map_err(|error| {
            DatabaseError::Config(format!("invalid db-guard context JSON: {error}"))
        })?;
    context.validate()?;
    Ok(context)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseScanReport {
    pub table: String,
    pub key_columns: Vec<String>,
    pub record_count: u64,
    pub total_value_bytes: u64,
    pub schema_hash: [u8; 32],
    pub snapshot: Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DatabaseValue {
    Null,
    Integer(i64),
    Unsigned(u64),
    Real(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone)]
struct ColumnInfo {
    name: String,
    declared_type: String,
    not_null: bool,
    default_value: Option<String>,
    primary_key_order: u32,
    hidden: u32,
}

pub(crate) struct CanonicalReportBuilder {
    table: String,
    key_columns: Vec<String>,
    key_indexes: Vec<usize>,
    column_names: Vec<String>,
    limits: DatabaseScanLimits,
    schema_hash: [u8; 32],
    scope_id: String,
    created_at_unix_ms: u64,
    entries: Vec<IntegrityEntry>,
    paths: BTreeSet<NormalizedPath>,
    record_count: u64,
    total_value_bytes: u64,
}

pub(crate) struct CanonicalSourceSchema {
    pub(crate) key_columns: Vec<String>,
    pub(crate) key_indexes: Vec<usize>,
    pub(crate) column_names: Vec<String>,
    pub(crate) schema_hash: [u8; 32],
    pub(crate) schema_size: u64,
}

impl CanonicalReportBuilder {
    pub(crate) fn new(
        config: &DatabaseScanConfig,
        mut schema: CanonicalSourceSchema,
        scope_id: &str,
        created_at_unix_ms: u64,
    ) -> Result<Self> {
        if let Some(context) = &config.db_guard_context {
            let context_bytes = context.canonical_bytes()?;
            let mut hash = Sha256::new();
            hash.update(DB_GUARD_CONTEXT_DOMAIN);
            hash.update(schema.schema_hash);
            hash.update((context_bytes.len() as u64).to_be_bytes());
            hash.update(&context_bytes);
            schema.schema_hash = hash.finalize().into();
            schema.schema_size = schema
                .schema_size
                .checked_add(context_bytes.len() as u64)
                .ok_or_else(|| {
                    DatabaseError::Limit("database schema context size overflow".to_owned())
                })?;
        }
        let schema_path = NormalizedPath::new(format!("schema/{}", config.table))?;
        Ok(Self {
            table: config.table.clone(),
            key_columns: schema.key_columns,
            key_indexes: schema.key_indexes,
            column_names: schema.column_names,
            limits: config.limits.clone(),
            schema_hash: schema.schema_hash,
            scope_id: scope_id.to_owned(),
            created_at_unix_ms,
            entries: vec![IntegrityEntry::new(
                schema_path,
                EntryKind::File,
                schema.schema_hash,
                [0; 32],
                schema.schema_size,
            )],
            paths: BTreeSet::new(),
            record_count: 0,
            total_value_bytes: 0,
        })
    }

    pub(crate) fn push_row(&mut self, values: Vec<DatabaseValue>) -> Result<()> {
        if values.len() != self.column_names.len() {
            return Err(DatabaseError::Config(
                "record source returned an unexpected column count".to_owned(),
            ));
        }
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or_else(|| DatabaseError::Limit("row count overflow".to_owned()))?;
        if self.record_count > self.limits.max_rows {
            return Err(DatabaseError::Limit("row count limit exceeded".to_owned()));
        }
        let row_bytes = values.iter().try_fold(0_u64, |total, value| {
            total
                .checked_add(value_size(value))
                .ok_or_else(|| DatabaseError::Limit("row value bytes overflow".to_owned()))
        })?;
        self.total_value_bytes = self
            .total_value_bytes
            .checked_add(row_bytes)
            .ok_or_else(|| DatabaseError::Limit("total value bytes overflow".to_owned()))?;
        if self.total_value_bytes > self.limits.max_total_value_bytes {
            return Err(DatabaseError::Limit(
                "total value byte limit exceeded".to_owned(),
            ));
        }
        let key_hash = hash_key(&self.table, &self.key_columns, &self.key_indexes, &values)?;
        let path = NormalizedPath::new(format!("row/{}", hex::encode(key_hash)))?;
        if !self.paths.insert(path.clone()) {
            return Err(DatabaseError::Config(
                "selected key columns do not uniquely identify every row".to_owned(),
            ));
        }
        let content = hash_row(&self.table, self.schema_hash, &self.column_names, &values);
        self.entries.push(IntegrityEntry::new(
            path,
            EntryKind::File,
            content,
            self.schema_hash,
            row_bytes,
        ));
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<DatabaseScanReport> {
        let snapshot = Snapshot::new(&self.scope_id, self.entries, self.created_at_unix_ms)?;
        Ok(DatabaseScanReport {
            table: self.table,
            key_columns: self.key_columns,
            record_count: self.record_count,
            total_value_bytes: self.total_value_bytes,
            schema_hash: self.schema_hash,
            snapshot,
        })
    }
}

fn validate_context_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(DatabaseError::Config(format!(
            "{label} must be 1..128 safe ASCII characters"
        )));
    }
    Ok(())
}

fn decode_context_digest(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).map_err(|_| {
        DatabaseError::Config(
            "db-guard encryptionPolicyDigest must be a 32-byte hexadecimal digest".to_owned(),
        )
    })?;
    decoded.try_into().map_err(|_| {
        DatabaseError::Config(
            "db-guard encryptionPolicyDigest must be a 32-byte hexadecimal digest".to_owned(),
        )
    })
}

fn append_context_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

pub struct DatabaseAgent {
    state_dir: PathBuf,
    scope_id: String,
    secret: MlDsa65SecretKey,
    public: MlDsa65PublicKey,
}

impl DatabaseAgent {
    pub fn initialize(state_dir: &Path, scope_id: &str) -> Result<Self> {
        validate_identifier(scope_id, "scope")?;
        std::fs::create_dir_all(state_dir)?;
        secure_directory(state_dir)?;
        let state_dir = state_dir.canonicalize()?;
        let keys = state_dir.join(KEY_DIRECTORY);
        std::fs::create_dir_all(&keys)?;
        secure_directory(&keys)?;
        let secret_path = keys.join(SECRET_KEY_FILE);
        let public_path = keys.join(PUBLIC_KEY_FILE);
        let scope_path = state_dir.join(SCOPE_FILE);
        if secret_path.exists() || public_path.exists() || scope_path.exists() {
            return Err(DatabaseError::State(
                "refusing to overwrite existing database agent identity".to_owned(),
            ));
        }
        let pair = MlDsa65KeyPair::generate()?;
        write_new(&secret_path, pair.secret.expose_seed(), true)?;
        write_new(&public_path, pair.public.as_bytes(), false)?;
        write_new(&scope_path, scope_id.as_bytes(), false)?;
        Self::load(&state_dir)
    }

    pub fn load(state_dir: &Path) -> Result<Self> {
        let state_dir = state_dir.canonicalize()?;
        secure_directory(&state_dir)?;
        let keys = state_dir.join(KEY_DIRECTORY);
        secure_directory(&keys)?;
        let secret = MlDsa65SecretKey::from_seed(&read_regular(&keys.join(SECRET_KEY_FILE), 32)?)?;
        let public =
            MlDsa65PublicKey::from_bytes(&read_regular(&keys.join(PUBLIC_KEY_FILE), 1_952)?)?;
        if secret.public_key()?.as_bytes() != public.as_bytes() {
            return Err(DatabaseError::State(
                "database agent secret and public keys do not match".to_owned(),
            ));
        }
        let scope_id = String::from_utf8(read_regular(&state_dir.join(SCOPE_FILE), 128)?)
            .map_err(|_| DatabaseError::State("scope id is not UTF-8".to_owned()))?;
        validate_identifier(&scope_id, "scope")?;
        Ok(Self {
            state_dir,
            scope_id,
            secret,
            public,
        })
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn key_id(&self) -> [u8; 32] {
        self.public.key_id()
    }

    pub fn create_baseline(
        &self,
        database: &Path,
        config: &DatabaseScanConfig,
        replace: bool,
    ) -> Result<DatabaseScanReport> {
        self.ensure_disjoint(database)?;
        let baseline = self.baseline_path();
        if baseline.exists() {
            self.load_baseline()?;
            if !replace {
                return Err(DatabaseError::State(
                    "baseline exists; pass --replace to approve replacement".to_owned(),
                ));
            }
        }
        let report = scan_sqlite(database, config, &self.scope_id, now_unix_ms()?)?;
        self.create_baseline_from_report(&report, replace)?;
        Ok(report)
    }

    pub fn load_baseline(&self) -> Result<Snapshot> {
        let signed =
            SignedSnapshot::from_cbor(&read_regular(&self.baseline_path(), MAX_BASELINE_BYTES)?)?;
        if signed.public_key()?.as_bytes() != self.public.as_bytes() {
            return Err(DatabaseError::State(
                "baseline signer does not match database agent identity".to_owned(),
            ));
        }
        let snapshot = signed.verify()?;
        if snapshot.scope_id != self.scope_id {
            return Err(DatabaseError::State(
                "baseline scope does not match database agent scope".to_owned(),
            ));
        }
        Ok(snapshot)
    }

    pub fn verify(
        &self,
        database: &Path,
        config: &DatabaseScanConfig,
    ) -> Result<(DatabaseScanReport, VerificationReport)> {
        self.ensure_disjoint(database)?;
        let baseline = self.load_baseline()?;
        let observed = scan_sqlite(database, config, &self.scope_id, now_unix_ms()?)?;
        let verification = self.verify_report_against(&baseline, &observed)?;
        Ok((observed, verification))
    }

    pub fn create_baseline_from_report(
        &self,
        report: &DatabaseScanReport,
        replace: bool,
    ) -> Result<()> {
        if report.snapshot.scope_id != self.scope_id {
            return Err(DatabaseError::State(
                "scan report scope does not match database agent scope".to_owned(),
            ));
        }
        let baseline = self.baseline_path();
        if baseline.exists() {
            self.load_baseline()?;
            if !replace {
                return Err(DatabaseError::State(
                    "baseline exists; pass --replace to approve replacement".to_owned(),
                ));
            }
        }
        let signed = SignedSnapshot::sign(&report.snapshot, &self.secret)?;
        write_atomic(&baseline, &signed.to_cbor()?, replace)
    }

    pub fn verify_report(&self, report: &DatabaseScanReport) -> Result<VerificationReport> {
        let baseline = self.load_baseline()?;
        self.verify_report_against(&baseline, report)
    }

    fn verify_report_against(
        &self,
        baseline: &Snapshot,
        report: &DatabaseScanReport,
    ) -> Result<VerificationReport> {
        if report.snapshot.scope_id != self.scope_id {
            return Err(DatabaseError::State(
                "scan report scope does not match database agent scope".to_owned(),
            ));
        }
        Ok(compare_snapshots(baseline, &report.snapshot))
    }

    fn baseline_path(&self) -> PathBuf {
        self.state_dir.join(BASELINE_FILE)
    }

    fn ensure_disjoint(&self, database: &Path) -> Result<()> {
        let database = database.canonicalize()?;
        if !database.is_file() {
            return Err(DatabaseError::Config(
                "database path must be a regular file".to_owned(),
            ));
        }
        if database.starts_with(&self.state_dir) {
            return Err(DatabaseError::State(
                "database file must not be stored inside agent state".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn scan_sqlite(
    database: &Path,
    config: &DatabaseScanConfig,
    scope_id: &str,
    created_at_unix_ms: u64,
) -> Result<DatabaseScanReport> {
    config.validate()?;
    validate_identifier(scope_id, "scope")?;
    let metadata = std::fs::symlink_metadata(database)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DatabaseError::Config(
            "SQLite path must be a regular non-symlink file".to_owned(),
        ));
    }
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    let result = scan_connection(&connection, config, scope_id, created_at_unix_ms);
    let rollback = connection.execute_batch("ROLLBACK");
    match (result, rollback) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn scan_connection(
    connection: &Connection,
    config: &DatabaseScanConfig,
    scope_id: &str,
    created_at_unix_ms: u64,
) -> Result<DatabaseScanReport> {
    let schema_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [&config.table],
            |row| row.get(0),
        )
        .optional()?;
    let schema_sql = schema_sql.ok_or_else(|| {
        DatabaseError::Config(format!("SQLite table does not exist: {}", config.table))
    })?;
    if schema_sql
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("CREATE VIRTUAL TABLE")
    {
        return Err(DatabaseError::Config(
            "SQLite virtual tables are outside the trusted adapter boundary".to_owned(),
        ));
    }
    let columns = load_columns(connection, &config.table, config.limits.max_columns)?;
    let selected_columns: Vec<_> = columns.iter().filter(|column| column.hidden != 1).collect();
    if selected_columns.is_empty() {
        return Err(DatabaseError::Config(
            "SQLite table has no selectable columns".to_owned(),
        ));
    }
    let key_columns = resolve_key_columns(&columns, &config.key_columns)?;
    let key_indexes: Vec<_> = key_columns
        .iter()
        .map(|key| {
            selected_columns
                .iter()
                .position(|column| column.name == *key)
                .ok_or_else(|| DatabaseError::Config(format!("key column is hidden: {key}")))
        })
        .collect::<Result<_>>()?;
    let schema_hash = hash_schema(&config.table, &schema_sql, &columns);
    let select = format!(
        "SELECT {} FROM {}",
        selected_columns
            .iter()
            .map(|column| quote_identifier(&column.name))
            .collect::<Vec<_>>()
            .join(","),
        quote_identifier(&config.table)
    );
    let mut statement = connection.prepare(&select)?;
    let mut rows = statement.query([])?;
    let schema_size = u64::try_from(schema_sql.len())
        .map_err(|_| DatabaseError::Limit("schema length exceeds u64".to_owned()))?;
    let column_names = selected_columns
        .iter()
        .map(|column| column.name.clone())
        .collect();
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
    while let Some(row) = rows.next()? {
        let mut values = Vec::with_capacity(selected_columns.len());
        for index in 0..selected_columns.len() {
            let value = database_value(row.get_ref(index)?, config.limits.max_value_bytes)?;
            values.push(value);
        }
        builder.push_row(values)?;
    }
    builder.finish()
}

fn load_columns(connection: &Connection, table: &str, maximum: usize) -> Result<Vec<ColumnInfo>> {
    let pragma = format!("PRAGMA table_xinfo({})", quote_identifier(table));
    let mut statement = connection.prepare(&pragma)?;
    let columns = statement
        .query_map([], |row| {
            Ok(ColumnInfo {
                name: row.get(1)?,
                declared_type: row.get(2)?,
                not_null: row.get::<_, i64>(3)? != 0,
                default_value: row.get(4)?,
                primary_key_order: row.get::<_, u32>(5)?,
                hidden: row.get::<_, u32>(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if columns.is_empty() || columns.len() > maximum {
        return Err(DatabaseError::Limit(
            "SQLite column count is zero or exceeds its limit".to_owned(),
        ));
    }
    for column in &columns {
        validate_identifier(&column.name, "column")?;
    }
    Ok(columns)
}

fn resolve_key_columns(columns: &[ColumnInfo], configured: &[String]) -> Result<Vec<String>> {
    if configured.is_empty() {
        let mut primary: Vec<_> = columns
            .iter()
            .filter(|column| column.primary_key_order > 0)
            .collect();
        primary.sort_by_key(|column| column.primary_key_order);
        if primary.is_empty() {
            return Err(DatabaseError::Config(
                "table has no primary key; provide one or more --key-column values".to_owned(),
            ));
        }
        return Ok(primary
            .into_iter()
            .map(|column| column.name.clone())
            .collect());
    }
    configured
        .iter()
        .map(|configured_name| {
            columns
                .iter()
                .find(|column| column.name.eq_ignore_ascii_case(configured_name))
                .map(|column| column.name.clone())
                .ok_or_else(|| {
                    DatabaseError::Config(format!(
                        "configured key column does not exist: {configured_name}"
                    ))
                })
        })
        .collect()
}

fn database_value(value: ValueRef<'_>, maximum: u64) -> Result<DatabaseValue> {
    let result = match value {
        ValueRef::Null => DatabaseValue::Null,
        ValueRef::Integer(value) => DatabaseValue::Integer(value),
        ValueRef::Real(value) if value.is_finite() => DatabaseValue::Real(value.to_bits()),
        ValueRef::Real(_) => {
            return Err(DatabaseError::Config(
                "non-finite SQLite REAL values are not canonical".to_owned(),
            ));
        }
        ValueRef::Text(value) => DatabaseValue::Text(value.to_vec()),
        ValueRef::Blob(value) => DatabaseValue::Blob(value.to_vec()),
    };
    if value_size(&result) > maximum {
        return Err(DatabaseError::Limit(
            "individual SQLite value exceeds its limit".to_owned(),
        ));
    }
    Ok(result)
}

fn value_size(value: &DatabaseValue) -> u64 {
    match value {
        DatabaseValue::Null => 0,
        DatabaseValue::Integer(_) | DatabaseValue::Unsigned(_) | DatabaseValue::Real(_) => 8,
        DatabaseValue::Text(value) | DatabaseValue::Blob(value) => value.len() as u64,
    }
}

fn hash_schema(table: &str, sql: &str, columns: &[ColumnInfo]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SCHEMA_DOMAIN);
    update_bytes(&mut hash, table.as_bytes());
    update_bytes(&mut hash, sql.as_bytes());
    hash.update((columns.len() as u64).to_be_bytes());
    for column in columns {
        update_bytes(&mut hash, column.name.as_bytes());
        update_bytes(&mut hash, column.declared_type.as_bytes());
        hash.update([u8::from(column.not_null)]);
        match &column.default_value {
            Some(value) => {
                hash.update([1]);
                update_bytes(&mut hash, value.as_bytes());
            }
            None => hash.update([0]),
        }
        hash.update(column.primary_key_order.to_be_bytes());
        hash.update(column.hidden.to_be_bytes());
    }
    hash.finalize().into()
}

fn hash_key(
    table: &str,
    key_columns: &[String],
    key_indexes: &[usize],
    values: &[DatabaseValue],
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(ROW_KEY_DOMAIN);
    update_bytes(&mut hash, table.as_bytes());
    for (column, index) in key_columns.iter().zip(key_indexes) {
        let value = &values[*index];
        if matches!(value, DatabaseValue::Null) {
            return Err(DatabaseError::Config(
                "row key columns must not contain NULL".to_owned(),
            ));
        }
        update_bytes(&mut hash, column.as_bytes());
        update_value(&mut hash, value);
    }
    Ok(hash.finalize().into())
}

fn hash_row(
    table: &str,
    schema_hash: [u8; 32],
    columns: &[String],
    values: &[DatabaseValue],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ROW_CONTENT_DOMAIN);
    update_bytes(&mut hash, table.as_bytes());
    hash.update(schema_hash);
    for (column, value) in columns.iter().zip(values) {
        update_bytes(&mut hash, column.as_bytes());
        update_value(&mut hash, value);
    }
    hash.finalize().into()
}

fn update_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn update_value(hash: &mut Sha256, value: &DatabaseValue) {
    match value {
        DatabaseValue::Null => hash.update([0]),
        DatabaseValue::Integer(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        DatabaseValue::Unsigned(value) => {
            hash.update([5]);
            hash.update(value.to_be_bytes());
        }
        DatabaseValue::Real(bits) => {
            hash.update([2]);
            hash.update(bits.to_be_bytes());
        }
        DatabaseValue::Text(value) => {
            hash.update([3]);
            update_bytes(hash, value);
        }
        DatabaseValue::Blob(value) => {
            hash.update([4]);
            update_bytes(hash, value);
        }
    }
}

fn compare_snapshots(baseline: &Snapshot, observed: &Snapshot) -> VerificationReport {
    let baseline_entries: BTreeMap<_, _> = baseline
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let observed_entries: BTreeMap<_, _> = observed
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let mut differences = Vec::new();
    for (path, entry) in &baseline_entries {
        match observed_entries.get(path) {
            None => differences.push(VerificationDifference {
                path: path.clone(),
                kind: DifferenceKind::Removed,
            }),
            Some(observed_entry) if *entry != *observed_entry => {
                differences.push(VerificationDifference {
                    path: path.clone(),
                    kind: DifferenceKind::Modified,
                });
            }
            Some(_) => {}
        }
    }
    for path in observed_entries.keys() {
        if !baseline_entries.contains_key(path) {
            differences.push(VerificationDifference {
                path: path.clone(),
                kind: DifferenceKind::Added,
            });
        }
    }
    VerificationReport {
        scope_id: baseline.scope_id.clone(),
        baseline_root: baseline.root,
        observed_root: observed.root,
        differences,
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DatabaseError::Config(format!(
            "{label} must be a 1-128 character ASCII identifier"
        )));
    }
    Ok(())
}

fn now_unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| DatabaseError::State(error.to_string()))?
            .as_millis(),
    )
    .map_err(|_| DatabaseError::Limit("system time exceeds u64".to_owned()))
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(DatabaseError::State(format!(
            "state entry is not a bounded regular file: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| DatabaseError::Limit("state entry exceeds address space".to_owned()))?,
    );
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(DatabaseError::Limit(
            "state entry changed beyond its size limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8], _secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if _secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let temporary = path.with_extension("tmp");
    write_new(&temporary, bytes, false)?;
    if !replace {
        match std::fs::hard_link(&temporary, path) {
            Ok(()) => {
                std::fs::remove_file(temporary)?;
                return Ok(());
            }
            Err(error) => {
                let _ = std::fs::remove_file(temporary);
                return Err(error.into());
            }
        }
    }
    #[cfg(windows)]
    if path.exists() {
        let backup = path.with_extension("previous");
        if backup.exists() {
            let _ = std::fs::remove_file(&temporary);
            return Err(DatabaseError::State(
                "stale baseline backup blocks replacement".to_owned(),
            ));
        }
        std::fs::rename(path, &backup)?;
        if let Err(error) = std::fs::rename(&temporary, path) {
            let _ = std::fs::rename(&backup, path);
            return Err(error.into());
        }
        std::fs::remove_file(backup)?;
        return Ok(());
    }
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn secure_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DatabaseError::State(format!(
            "state path is not a non-symlink directory: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT NOT NULL, balance INTEGER NOT NULL);\
                 INSERT INTO accounts VALUES (1, 'a@example.test', 10);\
                 INSERT INTO accounts VALUES (2, 'b@example.test', 20);",
            )
            .unwrap();
    }

    #[test]
    fn scan_is_deterministic_private_and_detects_row_and_schema_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.sqlite");
        database(&path);
        let config = DatabaseScanConfig::new("accounts", vec![]).unwrap();
        let first = scan_sqlite(&path, &config, "accounts", 100).unwrap();
        let second = scan_sqlite(&path, &config, "accounts", 100).unwrap();
        assert_eq!(first.snapshot.root, second.snapshot.root);
        assert_eq!(first.key_columns, vec!["id"]);
        assert_eq!(first.record_count, 2);
        assert!(
            first
                .snapshot
                .entries
                .iter()
                .all(|entry| !entry.path.as_str().contains("example"))
        );

        let connection = Connection::open(&path).unwrap();
        connection
            .execute("UPDATE accounts SET balance = 99 WHERE id = 2", [])
            .unwrap();
        let changed = scan_sqlite(&path, &config, "accounts", 101).unwrap();
        assert_ne!(first.snapshot.root, changed.snapshot.root);
        connection
            .execute(
                "ALTER TABLE accounts ADD COLUMN enabled INTEGER DEFAULT 1",
                [],
            )
            .unwrap();
        let schema_changed = scan_sqlite(&path, &config, "accounts", 102).unwrap();
        assert_ne!(changed.schema_hash, schema_changed.schema_hash);
    }

    #[test]
    fn agent_signs_baseline_and_reports_database_drift() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.sqlite");
        database(&path);
        let state = directory.path().join("state");
        let agent = DatabaseAgent::initialize(&state, "accounts").unwrap();
        let config = DatabaseScanConfig::new("accounts", vec![]).unwrap();
        agent.create_baseline(&path, &config, false).unwrap();
        assert!(agent.verify(&path, &config).unwrap().1.is_match());
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("DELETE FROM accounts WHERE id = 1", [])
            .unwrap();
        let verification = agent.verify(&path, &config).unwrap().1;
        assert!(!verification.is_match());
        assert!(
            verification
                .differences
                .iter()
                .any(|difference| difference.kind == DifferenceKind::Removed)
        );
    }

    #[test]
    fn key_columns_must_exist_be_non_null_and_unique() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("no-key.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE events (category TEXT, value TEXT); INSERT INTO events VALUES ('x', '1'), ('x', '2');")
            .unwrap();
        let automatic = DatabaseScanConfig::new("events", vec![]).unwrap();
        assert!(scan_sqlite(&path, &automatic, "events", 100).is_err());
        let duplicate = DatabaseScanConfig::new("events", vec!["category".to_owned()]).unwrap();
        assert!(scan_sqlite(&path, &duplicate, "events", 100).is_err());
    }

    #[test]
    fn virtual_tables_are_rejected_before_row_access() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("virtual.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE VIRTUAL TABLE docs USING fts5(content);")
            .unwrap();
        let config = DatabaseScanConfig::new("docs", vec!["content".to_owned()]).unwrap();
        assert!(scan_sqlite(&path, &config, "docs", 100).is_err());
    }

    #[test]
    fn db_guard_context_is_versioned_validated_and_bound_to_root() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("app.sqlite");
        database(&database_path);
        let standalone = DatabaseScanConfig::new("accounts", vec![]).unwrap();
        let context = DbGuardContextV1 {
            format_version: 1,
            database_id: "primary/accounts".to_owned(),
            kms_route_id: Some("kms/eu-central-1/app".to_owned()),
            encryption_policy_digest: "ab".repeat(32),
            key_epoch: 7,
        };
        let enhanced = standalone
            .clone()
            .with_db_guard_context(Some(context.clone()))
            .unwrap();
        let standalone_report = scan_sqlite(&database_path, &standalone, "accounts", 100).unwrap();
        let enhanced_report = scan_sqlite(&database_path, &enhanced, "accounts", 100).unwrap();
        assert_ne!(standalone_report.schema_hash, enhanced_report.schema_hash);
        assert_ne!(
            standalone_report.snapshot.root,
            enhanced_report.snapshot.root
        );

        let context_path = directory.path().join("db-guard-context.json");
        std::fs::write(&context_path, serde_json::to_vec(&context).unwrap()).unwrap();
        assert_eq!(load_db_guard_context_v1(&context_path).unwrap(), context);
    }

    #[test]
    fn db_guard_context_rejects_unknown_versions_fields_and_digests() {
        let directory = tempfile::tempdir().unwrap();
        let context_path = directory.path().join("db-guard-context.json");
        std::fs::write(
            &context_path,
            r#"{"formatVersion":2,"databaseId":"db","kmsRouteId":null,"encryptionPolicyDigest":"00","keyEpoch":1}"#,
        )
        .unwrap();
        assert!(load_db_guard_context_v1(&context_path).is_err());
        std::fs::write(
            &context_path,
            format!(
                r#"{{"formatVersion":1,"databaseId":"db","kmsRouteId":null,"encryptionPolicyDigest":"{}","keyEpoch":1,"unknown":true}}"#,
                "00".repeat(32)
            ),
        )
        .unwrap();
        assert!(load_db_guard_context_v1(&context_path).is_err());
    }
}

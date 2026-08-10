#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use serde_json::json;
use vollcrypt_shield_db::{
    DatabaseAgent, DatabaseScanConfig, MySqlScanOptions, PostgresScanOptions, scan_mysql,
    scan_postgres, scan_sqlite,
};

#[derive(Parser)]
#[command(name = "vollcrypt-shield-db")]
#[command(about = "Independent database record integrity agent for Vollcrypt Shield")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        scope: String,
    },
    Scan {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
    },
    Baseline {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    Verify {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
    },
    ScanPostgres {
        #[arg(long, default_value = "SHIELD_POSTGRES_URL")]
        connection_env: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
    },
    BaselinePostgres {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "SHIELD_POSTGRES_URL")]
        connection_env: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    VerifyPostgres {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "SHIELD_POSTGRES_URL")]
        connection_env: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
    },
    ScanMysql {
        #[arg(long, default_value = "SHIELD_MYSQL_URL")]
        connection_env: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
    },
    BaselineMysql {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "SHIELD_MYSQL_URL")]
        connection_env: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    VerifyMysql {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "SHIELD_MYSQL_URL")]
        connection_env: String,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        table: String,
        #[arg(long = "key-column")]
        key_columns: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Init { state_dir, scope } => {
            let agent = DatabaseAgent::initialize(&state_dir, &scope)?;
            print_json(json!({
                "status": "initialized",
                "scopeId": agent.scope_id(),
                "keyId": hex::encode(agent.key_id()),
            }))?;
        }
        Command::Scan {
            database,
            table,
            key_columns,
        } => {
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let report = scan_sqlite(&database, &config, "standalone-scan", now_ms()?)?;
            print_json(scan_json("valid", &report))?;
        }
        Command::Baseline {
            state_dir,
            database,
            table,
            key_columns,
            replace,
        } => {
            let agent = DatabaseAgent::load(&state_dir)?;
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let report = agent.create_baseline(&database, &config, replace)?;
            let mut value = scan_json("baseline-created", &report);
            value["scopeId"] = json!(agent.scope_id());
            value["keyId"] = json!(hex::encode(agent.key_id()));
            print_json(value)?;
        }
        Command::Verify {
            state_dir,
            database,
            table,
            key_columns,
        } => {
            let agent = DatabaseAgent::load(&state_dir)?;
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let (scan, verification) = agent.verify(&database, &config)?;
            print_json(json!({
                "status": if verification.is_match() { "match" } else { "mismatch" },
                "scopeId": verification.scope_id,
                "table": scan.table,
                "keyColumns": scan.key_columns,
                "recordCount": scan.record_count,
                "baselineRoot": hex::encode(verification.baseline_root),
                "observedRoot": hex::encode(verification.observed_root),
                "differences": verification.differences,
            }))?;
            if !verification.is_match() {
                std::process::exit(2);
            }
        }
        Command::ScanPostgres {
            connection_env,
            schema,
            ca_file,
            table,
            key_columns,
        } => {
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let options = postgres_options(&connection_env, schema, ca_file)?;
            let report = scan_postgres(&options, &config, "standalone-scan", now_ms()?).await?;
            print_json(scan_json("valid", &report))?;
        }
        Command::BaselinePostgres {
            state_dir,
            connection_env,
            schema,
            ca_file,
            table,
            key_columns,
            replace,
        } => {
            let agent = DatabaseAgent::load(&state_dir)?;
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let options = postgres_options(&connection_env, schema, ca_file)?;
            let report = scan_postgres(&options, &config, agent.scope_id(), now_ms()?).await?;
            agent.create_baseline_from_report(&report, replace)?;
            let mut value = scan_json("baseline-created", &report);
            value["scopeId"] = json!(agent.scope_id());
            value["keyId"] = json!(hex::encode(agent.key_id()));
            print_json(value)?;
        }
        Command::VerifyPostgres {
            state_dir,
            connection_env,
            schema,
            ca_file,
            table,
            key_columns,
        } => {
            let agent = DatabaseAgent::load(&state_dir)?;
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let options = postgres_options(&connection_env, schema, ca_file)?;
            let scan = scan_postgres(&options, &config, agent.scope_id(), now_ms()?).await?;
            let verification = agent.verify_report(&scan)?;
            print_verification(&scan, &verification)?;
            if !verification.is_match() {
                std::process::exit(2);
            }
        }
        Command::ScanMysql {
            connection_env,
            ca_file,
            table,
            key_columns,
        } => {
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let options = mysql_options(&connection_env, ca_file)?;
            let report = scan_mysql(&options, &config, "standalone-scan", now_ms()?)?;
            print_json(scan_json("valid", &report))?;
        }
        Command::BaselineMysql {
            state_dir,
            connection_env,
            ca_file,
            table,
            key_columns,
            replace,
        } => {
            let agent = DatabaseAgent::load(&state_dir)?;
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let options = mysql_options(&connection_env, ca_file)?;
            let report = scan_mysql(&options, &config, agent.scope_id(), now_ms()?)?;
            agent.create_baseline_from_report(&report, replace)?;
            let mut value = scan_json("baseline-created", &report);
            value["scopeId"] = json!(agent.scope_id());
            value["keyId"] = json!(hex::encode(agent.key_id()));
            print_json(value)?;
        }
        Command::VerifyMysql {
            state_dir,
            connection_env,
            ca_file,
            table,
            key_columns,
        } => {
            let agent = DatabaseAgent::load(&state_dir)?;
            let config = DatabaseScanConfig::new(table, key_columns)?;
            let options = mysql_options(&connection_env, ca_file)?;
            let scan = scan_mysql(&options, &config, agent.scope_id(), now_ms()?)?;
            let verification = agent.verify_report(&scan)?;
            print_verification(&scan, &verification)?;
            if !verification.is_match() {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn postgres_options(
    connection_env: &str,
    schema: String,
    ca_file: Option<PathBuf>,
) -> Result<PostgresScanOptions, Box<dyn std::error::Error>> {
    let connection = std::env::var(connection_env).map_err(|_| {
        format!("PostgreSQL connection environment variable is missing: {connection_env}")
    })?;
    Ok(PostgresScanOptions::new(connection)?
        .with_schema(schema)?
        .with_ca_file(ca_file)?)
}

fn mysql_options(
    connection_env: &str,
    ca_file: Option<PathBuf>,
) -> Result<MySqlScanOptions, Box<dyn std::error::Error>> {
    let connection = std::env::var(connection_env).map_err(|_| {
        format!("MySQL connection environment variable is missing: {connection_env}")
    })?;
    Ok(MySqlScanOptions::new(connection)?.with_ca_file(ca_file)?)
}

fn print_verification(
    scan: &vollcrypt_shield_db::DatabaseScanReport,
    verification: &vollcrypt_shield_core::VerificationReport,
) -> Result<(), serde_json::Error> {
    print_json(json!({
        "status": if verification.is_match() { "match" } else { "mismatch" },
        "scopeId": verification.scope_id,
        "table": scan.table,
        "keyColumns": scan.key_columns,
        "recordCount": scan.record_count,
        "baselineRoot": hex::encode(verification.baseline_root),
        "observedRoot": hex::encode(verification.observed_root),
        "differences": verification.differences,
    }))
}

fn scan_json(status: &str, report: &vollcrypt_shield_db::DatabaseScanReport) -> serde_json::Value {
    json!({
        "status": status,
        "table": report.table,
        "keyColumns": report.key_columns,
        "recordCount": report.record_count,
        "totalValueBytes": report.total_value_bytes,
        "schemaHash": hex::encode(report.schema_hash),
        "root": hex::encode(report.snapshot.root),
    })
}

fn print_json(value: serde_json::Value) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn now_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

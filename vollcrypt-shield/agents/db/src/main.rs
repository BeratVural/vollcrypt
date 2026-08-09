#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use serde_json::json;
use vollcrypt_shield_db::{DatabaseAgent, DatabaseScanConfig, scan_sqlite};

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
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
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
    }
    Ok(())
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

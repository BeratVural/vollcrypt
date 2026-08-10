#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::json;
use vollcrypt_shield_container::{
    ContainerAgent, OciLayoutScanner, OciScanLimits, RuntimeKind, monitor_docker,
};

#[derive(Parser)]
#[command(name = "vollcrypt-shield-container")]
#[command(about = "Independent OCI image-layout integrity agent for Vollcrypt Shield")]
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
        layout: PathBuf,
    },
    Baseline {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        layout: PathBuf,
        #[arg(long)]
        replace: bool,
    },
    Verify {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        layout: PathBuf,
    },
    ApproveDocker {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long = "image-digest", required = true)]
        image_digests: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    WatchDocker {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        max_observations: Option<usize>,
    },
    RuntimeAuditVerify {
        #[arg(long)]
        state_dir: PathBuf,
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
            let agent = ContainerAgent::initialize(&state_dir, &scope)?;
            print_json(json!({
                "status": "initialized",
                "scopeId": agent.scope_id(),
                "keyId": hex::encode(agent.key_id()),
            }))?;
        }
        Command::Scan { layout } => {
            let report =
                OciLayoutScanner::new(&layout, OciScanLimits::default())?.scan(now_ms()?)?;
            print_json(json!({
                "status": "valid",
                "guaranteeLevel": report.guarantee_level,
                "descriptorsVerified": report.descriptors_verified,
                "bytesVerified": report.bytes_verified,
                "root": hex::encode(report.snapshot.root),
            }))?;
        }
        Command::Baseline {
            state_dir,
            layout,
            replace,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let report = agent.create_baseline(&layout, OciScanLimits::default(), replace)?;
            print_json(json!({
                "status": "baseline-created",
                "scopeId": agent.scope_id(),
                "keyId": hex::encode(agent.key_id()),
                "descriptorsVerified": report.descriptors_verified,
                "bytesVerified": report.bytes_verified,
                "root": hex::encode(report.snapshot.root),
            }))?;
        }
        Command::Verify { state_dir, layout } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let (scan, verification) = agent.verify_layout(&layout, OciScanLimits::default())?;
            print_json(json!({
                "status": if verification.is_match() { "match" } else { "mismatch" },
                "scopeId": verification.scope_id,
                "guaranteeLevel": scan.guarantee_level,
                "descriptorsVerified": scan.descriptors_verified,
                "bytesVerified": scan.bytes_verified,
                "baselineRoot": hex::encode(verification.baseline_root),
                "observedRoot": hex::encode(verification.observed_root),
                "differences": verification.differences,
            }))?;
            if !verification.is_match() {
                std::process::exit(2);
            }
        }
        Command::ApproveDocker {
            state_dir,
            image_digests,
            replace,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let policy =
                agent.create_runtime_policy(RuntimeKind::Docker, &image_digests, replace)?;
            print_json(json!({
                "status": "docker-policy-approved",
                "scopeId": agent.scope_id(),
                "runtime": policy.runtime(),
                "approvedImageDigests": policy.approved_image_digests(),
            }))?;
        }
        Command::WatchDocker {
            state_dir,
            max_observations,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let summary = monitor_docker(&agent, max_observations, |decision| {
                if let Ok(encoded) = serde_json::to_string(decision) {
                    println!("{encoded}");
                }
            })
            .await?;
            print_json(json!({
                "status": if summary.violations == 0 { "monitor-complete" } else { "violations-detected" },
                "observations": summary.observations,
                "violations": summary.violations,
            }))?;
            if summary.violations > 0 {
                std::process::exit(2);
            }
        }
        Command::RuntimeAuditVerify { state_dir } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let events = agent.verify_runtime_audit()?;
            print_json(json!({
                "status": "valid",
                "scopeId": agent.scope_id(),
                "records": events.len(),
            }))?;
        }
    }
    Ok(())
}

fn print_json(value: serde_json::Value) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn now_ms() -> Result<u64, Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};

    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use vollcrypt_shield_container::{
    ContainerAgent, OciLayoutScanner, OciScanLimits, RuntimeKind, check_admission_file,
    check_sidecar, monitor_containerd, monitor_docker, serve_admission, serve_sidecar,
};

#[derive(Clone, Copy, ValueEnum)]
enum RuntimeArgument {
    Docker,
    Containerd,
    Sidecar,
    Admission,
}

impl From<RuntimeArgument> for RuntimeKind {
    fn from(value: RuntimeArgument) -> Self {
        match value {
            RuntimeArgument::Docker => Self::Docker,
            RuntimeArgument::Containerd => Self::Containerd,
            RuntimeArgument::Sidecar => Self::Sidecar,
            RuntimeArgument::Admission => Self::Admission,
        }
    }
}

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
    ApproveContainerd {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long = "image-digest", required = true)]
        image_digests: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    WatchContainerd {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "/run/containerd/containerd.sock")]
        socket: PathBuf,
        #[arg(long)]
        max_observations: Option<usize>,
    },
    ApproveSidecar {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        binding: String,
        #[arg(long = "image-digest", required = true)]
        image_digests: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    SidecarCheck {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        evidence_file: Option<PathBuf>,
    },
    ServeSidecar {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        evidence_file: Option<PathBuf>,
        #[arg(long, default_value = "0.0.0.0:9464")]
        listen: SocketAddr,
        #[arg(long, default_value_t = 5)]
        poll_seconds: u64,
    },
    ApproveAdmission {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long = "image-digest", required = true)]
        image_digests: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    AdmissionCheck {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        review: PathBuf,
    },
    ServeAdmission {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: SocketAddr,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
    },
    RuntimeAuditVerify {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, value_enum, default_value_t = RuntimeArgument::Docker)]
        runtime: RuntimeArgument,
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
        Command::ApproveContainerd {
            state_dir,
            namespace,
            image_digests,
            replace,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let policy =
                agent.create_containerd_runtime_policy(&namespace, &image_digests, replace)?;
            print_json(json!({
                "status": "containerd-policy-approved",
                "scopeId": agent.scope_id(),
                "runtime": policy.runtime(),
                "namespace": policy.namespace(),
                "approvedImageDigests": policy.approved_image_digests(),
            }))?;
        }
        Command::WatchContainerd {
            state_dir,
            socket,
            max_observations,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let summary = monitor_containerd(&agent, &socket, max_observations, |decision| {
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
        Command::ApproveSidecar {
            state_dir,
            binding,
            image_digests,
            replace,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let policy = agent.create_sidecar_runtime_policy(&binding, &image_digests, replace)?;
            print_json(json!({
                "status": "sidecar-policy-approved",
                "scopeId": agent.scope_id(),
                "runtime": policy.runtime(),
                "binding": policy.binding(),
                "approvedImageDigests": policy.approved_image_digests(),
                "guaranteeLevel": "constrained",
            }))?;
        }
        Command::SidecarCheck {
            state_dir,
            evidence_file,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let decision = check_sidecar(&agent, evidence_file.as_deref())?;
            print_json(serde_json::to_value(&decision)?)?;
            if !decision.approved {
                std::process::exit(2);
            }
        }
        Command::ServeSidecar {
            state_dir,
            evidence_file,
            listen,
            poll_seconds,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            serve_sidecar(
                &agent,
                evidence_file.as_deref(),
                listen,
                Duration::from_secs(poll_seconds),
            )
            .await?;
        }
        Command::ApproveAdmission {
            state_dir,
            namespace,
            image_digests,
            replace,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let policy =
                agent.create_admission_runtime_policy(&namespace, &image_digests, replace)?;
            print_json(json!({
                "status": "admission-policy-approved",
                "scopeId": agent.scope_id(),
                "runtime": policy.runtime(),
                "namespace": policy.namespace(),
                "approvedImageDigests": policy.approved_image_digests(),
                "guaranteeLevel": "build-time-only",
            }))?;
        }
        Command::AdmissionCheck { state_dir, review } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let outcome = check_admission_file(&agent, &review)?;
            print_json(outcome.response)?;
            if !outcome.allowed {
                std::process::exit(2);
            }
        }
        Command::ServeAdmission {
            state_dir,
            listen,
            tls_cert,
            tls_key,
        } => {
            let agent = ContainerAgent::load(&state_dir)?;
            serve_admission(&agent, listen, &tls_cert, &tls_key).await?;
        }
        Command::RuntimeAuditVerify { state_dir, runtime } => {
            let agent = ContainerAgent::load(&state_dir)?;
            let runtime = RuntimeKind::from(runtime);
            let events = agent.verify_runtime_audit_for(runtime)?;
            print_json(json!({
                "status": "valid",
                "scopeId": agent.scope_id(),
                "runtime": runtime,
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

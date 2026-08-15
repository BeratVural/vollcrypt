use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use vollcrypt_shield_core::{
    BreakGlassCommand, MetadataPolicy, MlDsa65PublicKey, MlDsa65SecretKey, ResponsePolicy,
    ScanProfile, SignedBreakGlassCommand, SignedSnapshot,
};
use vollcrypt_shield_fs::{
    AgentConfig, NotificationConfig, Scanner, ScopeConfig, ShieldAgent, WitnessPairingServer,
};
use vollcrypt_shield_protocol::{
    control_plane::{SignedAgentSummary, SignedEnrollmentRequest},
    offline::{
        MAX_OFFLINE_PAYLOAD_BYTES, OfflinePackageInput, OfflinePackageKind, SignedOfflinePackage,
    },
    witness::AttestationRequest,
};

mod dashboard;
mod tui;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OfflineKind {
    FleetEnrollment,
    FleetSummary,
    WitnessRequest,
    Snapshot,
}

impl OfflineKind {
    const fn protocol_kind(self) -> OfflinePackageKind {
        match self {
            Self::FleetEnrollment => OfflinePackageKind::FleetEnrollmentRequest,
            Self::FleetSummary => OfflinePackageKind::FleetSummary,
            Self::WitnessRequest => OfflinePackageKind::WitnessAttestationRequest,
            Self::Snapshot => OfflinePackageKind::SnapshotEvidence,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "vollcrypt-shield",
    version,
    about = "Vollcrypt Shield filesystem integrity CLI"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    MonitorFolder {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        break_glass_key: PathBuf,
        #[arg(long, default_value = "default")]
        scope: String,
    },
    /// Add another independent folder or project to an existing local agent.
    #[command(visible_alias = "scope-add")]
    AddFolder {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        scope: String,
    },
    ConfigExample {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Init {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        break_glass_key: PathBuf,
    },
    Baseline {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
    },
    Verify {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
    },
    /// Verify every configured scope and return a combined JSON report.
    VerifyAll {
        #[arg(long)]
        config: PathBuf,
    },
    Watch {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
    },
    Dashboard {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=3600))]
        refresh_secs: u64,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        no_color: bool,
    },
    /// Open the full-screen, read-only integrity interface.
    Tui {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
        refresh_secs: u64,
        #[arg(long)]
        no_color: bool,
    },
    AuditVerify {
        #[arg(long)]
        config: PathBuf,
    },
    PairWitness {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:49372")]
        listen: SocketAddr,
        #[arg(long)]
        advertise: Option<SocketAddr>,
        #[arg(long, default_value_t = 5)]
        valid_minutes: u64,
    },
    WitnessPolicyExport {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        threshold: usize,
        #[arg(long)]
        output: PathBuf,
    },
    WitnessRequest {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        output: PathBuf,
    },
    FleetEnrollmentRequest {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        label: String,
        #[arg(long)]
        output: PathBuf,
    },
    FleetSummary {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        previous_hash: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    OfflinePack {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, value_enum)]
        kind: OfflineKind,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        previous_hash: Option<String>,
        #[arg(long, default_value_t = 7)]
        valid_days: u64,
        #[arg(long)]
        output: PathBuf,
    },
    OfflineUnpack {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        expected_public_key: PathBuf,
        #[arg(long)]
        expected_sequence: u64,
        #[arg(long)]
        previous_hash: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    PolicyActivate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
    },
    BreakGlassCreate {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 15)]
        valid_minutes: u64,
    },
    BreakGlassApply {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        command: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    match arguments.command {
        Command::MonitorFolder {
            root,
            state_dir,
            config,
            break_glass_key,
            scope,
        } => {
            let root_metadata = std::fs::symlink_metadata(&root)?;
            if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
                return Err("monitored root must be a regular directory, not a symlink".into());
            }
            let root = root.canonicalize()?;
            let state_dir = canonical_new_path(&state_dir, "state directory")?;
            let config = canonical_new_path(&config, "configuration")?;
            let break_glass_key = canonical_new_path(&break_glass_key, "break-glass key")?;
            if config.exists()
                || state_dir.exists()
                || break_glass_key.exists()
                || break_glass_key.with_extension("public").exists()
            {
                return Err("refusing to overwrite existing Shield setup material".into());
            }
            if config.starts_with(&root) || break_glass_key.starts_with(&root) {
                return Err(
                    "configuration and break-glass key must be stored outside the monitored root"
                        .into(),
                );
            }
            let scope_config = ScopeConfig {
                id: scope.clone(),
                root,
                include: vec!["**".to_owned()],
                exclude: vec![],
                metadata: MetadataPolicy::default(),
                full_scan: ScanProfile::full_default(),
                incremental_scan: ScanProfile::incremental_default(),
                full_rescan_interval_secs: 300,
                response: ResponsePolicy::default(),
            };
            let value = AgentConfig {
                state_dir,
                scopes: vec![scope_config.clone()],
                notifications: NotificationConfig::default(),
            };
            value.validate()?;
            Scanner::new(&scope_config)?.full_scan(&scope_config)?;
            let mut agent = ShieldAgent::initialize(value.clone(), &break_glass_key)?;
            let baseline = agent.create_baseline(&scope)?;
            write_new(&config, value.to_toml()?.as_bytes())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "config": config,
                    "scope": scope,
                    "root": scope_config.root,
                    "stateDir": value.state_dir,
                    "breakGlassKey": break_glass_key,
                    "baselineRoot": hex::encode(baseline.root),
                    "policyMode": "dry-run",
                }))?
            );
        }
        Command::AddFolder {
            config,
            root,
            scope,
        } => {
            let metadata = std::fs::symlink_metadata(&root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("monitored root must be a regular directory, not a symlink".into());
            }
            let root = root.canonicalize()?;
            let config = config.canonicalize()?;
            if config.starts_with(&root) {
                return Err("configuration must be stored outside the monitored root".into());
            }
            let mut value = load_config(&config)?;
            if value.scopes.iter().any(|candidate| candidate.id == scope) {
                return Err(format!("scope id already exists: {scope}").into());
            }
            let scope_config = ScopeConfig {
                id: scope.clone(),
                root,
                include: vec!["**".to_owned()],
                exclude: vec![],
                metadata: MetadataPolicy::default(),
                full_scan: ScanProfile::full_default(),
                incremental_scan: ScanProfile::incremental_default(),
                full_rescan_interval_secs: 300,
                response: ResponsePolicy::default(),
            };
            value.scopes.push(scope_config.clone());
            value.validate()?;
            Scanner::new(&scope_config)?.full_scan(&scope_config)?;
            replace_file(&config, value.to_toml()?.as_bytes())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "config": &config,
                    "scope": &scope,
                    "root": &scope_config.root,
                    "scopeCount": value.scopes.len(),
                    "policyMode": "dry-run",
                    "baselineRequired": true,
                    "next": {
                        "command": "baseline",
                        "config": &config,
                        "scope": &scope_config.id,
                    },
                }))?
            );
        }
        Command::ConfigExample {
            root,
            state_dir,
            output,
        } => {
            let config = AgentConfig {
                state_dir,
                scopes: vec![ScopeConfig {
                    id: "default".to_owned(),
                    root,
                    include: vec!["**".to_owned()],
                    exclude: vec![],
                    metadata: MetadataPolicy::default(),
                    full_scan: ScanProfile::full_default(),
                    incremental_scan: ScanProfile::incremental_default(),
                    full_rescan_interval_secs: 300,
                    response: ResponsePolicy::default(),
                }],
                notifications: NotificationConfig::default(),
            };
            write_new(&output, config.to_toml()?.as_bytes())?;
            println!("{}", output.display());
        }
        Command::Init {
            config,
            break_glass_key,
        } => {
            ShieldAgent::initialize(load_config(&config)?, &break_glass_key)?;
            println!("initialized; store {} offline", break_glass_key.display());
        }
        Command::Baseline { config, scope } => {
            let mut agent = ShieldAgent::load(load_config(&config)?)?;
            let snapshot = agent.create_baseline(&scope)?;
            println!("{}", hex::encode(snapshot.root));
        }
        Command::Verify { config, scope } => {
            let mut agent = ShieldAgent::load(load_config(&config)?)?;
            let (report, outcomes) = agent.verify_scope(&scope)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "match": report.is_match(),
                    "report": report,
                    "outcomes": outcomes,
                }))?
            );
            if !report.is_match() {
                return Err("integrity verification failed".into());
            }
        }
        Command::VerifyAll { config } => {
            let value = load_config(&config)?;
            let scope_ids = value
                .scopes
                .iter()
                .map(|scope| scope.id.clone())
                .collect::<Vec<_>>();
            let mut agent = ShieldAgent::load(value)?;
            let mut all_match = true;
            let mut results = Vec::with_capacity(scope_ids.len());
            for scope in &scope_ids {
                match agent.verify_scope(scope) {
                    Ok((report, outcomes)) => {
                        all_match &= report.is_match();
                        results.push(serde_json::json!({
                            "scope": scope,
                            "match": report.is_match(),
                            "report": report,
                            "outcomes": outcomes,
                        }));
                    }
                    Err(error) => {
                        all_match = false;
                        results.push(serde_json::json!({
                            "scope": scope,
                            "match": false,
                            "error": error.to_string(),
                        }));
                    }
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "match": all_match,
                    "scopeCount": scope_ids.len(),
                    "results": results,
                }))?
            );
            if !all_match {
                return Err("one or more integrity verifications failed".into());
            }
        }
        Command::Watch { config, scope } => {
            ShieldAgent::load(load_config(&config)?)?.watch_scope(&scope)?;
        }
        Command::Status { config, scope } => {
            let value = load_config(&config)?;
            let status = load_status(value, &scope)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::Dashboard {
            config,
            scope,
            refresh_secs,
            once,
            no_color,
        } => {
            let interactive = std::io::stdout().is_terminal();
            loop {
                let value = load_config(&config)?;
                let scope_config = value
                    .scopes
                    .iter()
                    .find(|candidate| candidate.id == scope)
                    .cloned()
                    .ok_or_else(|| format!("unknown scope id: {scope}"))?;
                let notifications = dashboard::read_notification_tail(&value.state_dir, &scope);
                let status = load_status(value, &scope)?;
                let now = vollcrypt_shield_fs::agent::now_unix_ms()?;
                if interactive && !once {
                    print!("\x1b[2J\x1b[H");
                }
                print!(
                    "{}",
                    dashboard::render(
                        &status,
                        &scope_config,
                        &notifications,
                        now,
                        interactive && !no_color,
                    )
                );
                std::io::stdout().flush()?;
                if once || !interactive {
                    break;
                }
                std::thread::sleep(Duration::from_secs(refresh_secs));
            }
        }
        Command::Tui {
            config,
            scope,
            refresh_secs,
            no_color,
        } => {
            tui::require_interactive(
                std::io::stdin().is_terminal(),
                std::io::stdout().is_terminal(),
            )?;
            tui::run(config, scope, Duration::from_secs(refresh_secs), no_color)?;
        }
        Command::AuditVerify { config } => {
            let agent = ShieldAgent::load(load_config(&config)?)?;
            println!("{}", agent.verify_audit()?);
        }
        Command::PairWitness {
            config,
            listen,
            advertise,
            valid_minutes,
        } => {
            let mut agent = ShieldAgent::load(load_config(&config)?)?;
            let lifetime = valid_minutes
                .checked_mul(60)
                .ok_or("pairing validity overflow")?;
            let server = WitnessPairingServer::bind(
                listen,
                advertise,
                agent.agent_key_id(),
                Duration::from_secs(lifetime),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "invitation": server.invitation(),
                    "invitationUri": server.invitation_uri()?,
                }))?
            );
            std::io::stdout().flush()?;
            let witness = agent.complete_witness_pairing(server)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "paired": true,
                    "witnessId": witness.witness_id,
                    "witnessKeyId": hex::encode(witness.key_id),
                }))?
            );
        }
        Command::WitnessPolicyExport {
            config,
            threshold,
            output,
        } => {
            let agent = ShieldAgent::load(load_config(&config)?)?;
            let policy = agent.witness_policy(threshold)?;
            write_new(&output, &serde_json::to_vec_pretty(&policy)?)?;
            println!("{}", output.display());
        }
        Command::WitnessRequest {
            config,
            scope,
            epoch,
            output,
        } => {
            let agent = ShieldAgent::load(load_config(&config)?)?;
            let request = agent.attestation_request(&scope, epoch)?;
            write_new(&output, &request.to_cbor()?)?;
            println!("{}", output.display());
        }
        Command::FleetEnrollmentRequest {
            config,
            label,
            output,
        } => {
            let agent = ShieldAgent::load(load_config(&config)?)?;
            let request = agent
                .fleet_enrollment_request(&label, vollcrypt_shield_fs::agent::now_unix_ms()?)?;
            write_new(&output, &request.to_cbor()?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "output": output,
                    "agentKeyId": hex::encode(agent.agent_key_id()),
                    "retentionMode": "signed-summary",
                }))?
            );
        }
        Command::FleetSummary {
            config,
            scope,
            epoch,
            previous_hash,
            output,
        } => {
            let previous = fleet_previous_hash(epoch, previous_hash.as_deref())?;
            let mut agent = ShieldAgent::load(load_config(&config)?)?;
            let (summary, report) = agent.fleet_summary(&scope, epoch, previous)?;
            write_new(&output, &summary.to_cbor()?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "output": output,
                    "match": report.is_match(),
                    "summaryHash": hex::encode(summary.summary_hash()),
                    "observedRoot": hex::encode(report.observed_root),
                    "differenceCount": report.differences.len(),
                }))?
            );
        }
        Command::OfflinePack {
            config,
            kind,
            channel,
            input,
            sequence,
            previous_hash,
            valid_days,
            output,
        } => {
            let previous = fleet_previous_hash(sequence, previous_hash.as_deref())?;
            let payload = read_bounded_regular(&input, u64::try_from(MAX_OFFLINE_PAYLOAD_BYTES)?)?;
            let agent = ShieldAgent::load(load_config(&config)?)?;
            validate_offline_payload(kind, &payload, agent.agent_key_id())?;
            let now = vollcrypt_shield_fs::agent::now_unix_ms()?;
            let validity = valid_days
                .checked_mul(86_400_000)
                .ok_or("offline package validity overflow")?;
            let expires = now
                .checked_add(validity)
                .ok_or("offline package expiry overflow")?;
            let package = agent.sign_offline_package(OfflinePackageInput {
                kind: kind.protocol_kind(),
                channel_id: channel,
                created_at_unix_ms: now,
                expires_at_unix_ms: expires,
                sequence,
                previous_package_hash: previous,
                payload,
            })?;
            let verified = package.verify_at(now)?;
            write_new(&output, &package.to_cbor()?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "output": output,
                    "kind": verified.manifest.kind,
                    "channelId": verified.manifest.channel_id,
                    "sequence": verified.manifest.sequence,
                    "expiresAtUnixMs": verified.manifest.expires_at_unix_ms,
                    "packageHash": hex::encode(verified.package_hash),
                }))?
            );
        }
        Command::OfflineUnpack {
            package,
            expected_public_key,
            expected_sequence,
            previous_hash,
            output,
        } => {
            let previous = fleet_previous_hash(expected_sequence, previous_hash.as_deref())?;
            let package_limit = u64::try_from(MAX_OFFLINE_PAYLOAD_BYTES)?
                .checked_add(65_536)
                .ok_or("offline package limit overflow")?;
            let package =
                SignedOfflinePackage::from_cbor(&read_bounded_regular(&package, package_limit)?)?;
            let expected_public =
                MlDsa65PublicKey::from_bytes(&read_bounded_regular(&expected_public_key, 1_952)?)?;
            let verified = package.verify_at(vollcrypt_shield_fs::agent::now_unix_ms()?)?;
            if verified.sender_public_key.as_bytes() != expected_public.as_bytes()
                || verified.manifest.sequence != expected_sequence
                || verified.manifest.previous_package_hash != previous
            {
                return Err("offline package sender or chain position does not match".into());
            }
            write_new(&output, &verified.payload)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "output": output,
                    "kind": verified.manifest.kind,
                    "channelId": verified.manifest.channel_id,
                    "sequence": verified.manifest.sequence,
                    "packageHash": hex::encode(verified.package_hash),
                }))?
            );
        }
        Command::PolicyActivate { config, scope } => {
            let mut value = load_config(&config)?;
            let previous = value.clone();
            let agent = ShieldAgent::load(value.clone())?;
            if agent.is_contained(&scope) {
                return Err(format!("scope is contained: {scope}").into());
            }
            if !agent.has_dry_run_evidence(&scope)? {
                return Err(format!(
                    "scope has no verification evidence for the current dry-run policy: {scope}"
                )
                .into());
            }
            let policy = value
                .scopes
                .iter_mut()
                .find(|candidate| candidate.id == scope)
                .ok_or_else(|| format!("unknown scope id: {scope}"))?;
            policy.response.promote(
                agent.agent_key_id(),
                vollcrypt_shield_fs::agent::now_unix_ms()?,
            )?;
            replace_file(&config, value.to_toml()?.as_bytes())?;
            let record_result = ShieldAgent::load(value)?.record_policy_promotion(&scope);
            if let Err(error) = record_result {
                replace_file(&config, previous.to_toml()?.as_bytes())?;
                return Err(error.into());
            }
            println!("activated {scope}");
        }
        Command::BreakGlassCreate {
            key,
            scope,
            output,
            valid_minutes,
        } => {
            let validity = valid_minutes
                .checked_mul(60_000)
                .ok_or("validity overflow")?;
            let now = vollcrypt_shield_fs::agent::now_unix_ms()?;
            let secret = MlDsa65SecretKey::from_seed(&std::fs::read(key)?)?;
            let command = BreakGlassCommand::release(&scope, now, now + validity)?;
            let signed = SignedBreakGlassCommand::sign(&command, &secret)?;
            write_new(&output, &signed.to_cbor()?)?;
            println!("{}", output.display());
        }
        Command::BreakGlassApply {
            config,
            scope,
            command,
        } => {
            let mut agent = ShieldAgent::load(load_config(&config)?)?;
            agent.apply_break_glass(&std::fs::read(command)?, &scope)?;
            println!("released {scope}");
        }
    }
    Ok(())
}

fn load_status(
    value: AgentConfig,
    scope: &str,
) -> Result<vollcrypt_shield_fs::AgentStatus, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        match vollcrypt_shield_fs::query_local_status(&value.state_dir, scope) {
            Ok(status) => Ok(status),
            Err(error) if status_ipc_is_unavailable(&error) => {
                eprintln!(
                    "warning: live status IPC is unavailable ({error}); using signed persisted state"
                );
                Ok(ShieldAgent::load(value)?.status(scope)?)
            }
            Err(error) => Err(error.into()),
        }
    }
    #[cfg(not(unix))]
    {
        Ok(ShieldAgent::load(value)?.status(scope)?)
    }
}

#[cfg(unix)]
fn status_ipc_is_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::PermissionDenied
    )
}

fn load_config(path: &Path) -> Result<AgentConfig, Box<dyn std::error::Error>> {
    Ok(AgentConfig::from_toml(&std::fs::read_to_string(path)?)?)
}

fn canonical_new_path(path: &Path, label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute").into());
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{label} path has no final component"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent directory"))?
        .canonicalize()?;
    if !parent.is_dir() {
        return Err(format!("{label} parent is not a directory").into());
    }
    Ok(parent.join(file_name))
}

fn fleet_previous_hash(
    epoch: u64,
    value: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if epoch == 0 {
        return Err("fleet summary epoch must be greater than zero".into());
    }
    match value {
        None if epoch == 1 => Ok([0; 32]),
        None => Err("--previous-hash is required after epoch 1".into()),
        Some(value) => {
            let mut hash = [0_u8; 32];
            if value.len() != 64 || hex::decode_to_slice(value, &mut hash).is_err() {
                return Err("--previous-hash must be 64 lowercase hex characters".into());
            }
            if value.bytes().any(|byte| byte.is_ascii_uppercase())
                || (epoch == 1 && hash != [0; 32])
            {
                return Err("epoch 1 requires an absent or all-zero previous hash".into());
            }
            Ok(hash)
        }
    }
}

fn validate_offline_payload(
    kind: OfflineKind,
    payload: &[u8],
    agent_key_id: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = match kind {
        OfflineKind::FleetEnrollment => SignedEnrollmentRequest::from_cbor(payload)?.verify()?.1,
        OfflineKind::FleetSummary => SignedAgentSummary::from_cbor(payload)?.verify()?.1,
        OfflineKind::WitnessRequest => {
            AttestationRequest::from_cbor(payload)?.verify(agent_key_id)?;
            return Ok(());
        }
        OfflineKind::Snapshot => {
            let snapshot = SignedSnapshot::from_cbor(payload)?;
            snapshot.verify()?;
            snapshot.public_key()?
        }
    };
    if signer.key_id() != agent_key_id {
        return Err("offline payload signer does not match the configured agent".into());
    }
    Ok(())
}

fn read_bounded_regular(path: &Path, limit: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Read;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(format!("input is not a bounded regular file: {}", path.display()).into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    std::fs::File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > limit {
        return Err("input changed beyond its size limit".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    let backup = path.with_extension("previous");
    if backup.exists() {
        std::fs::remove_file(&backup)?;
    }
    std::fs::rename(path, &backup)?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::rename(&backup, path);
        return Err(error.into());
    }
    std::fs::remove_file(backup)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::status_ipc_is_unavailable;

    #[test]
    fn status_falls_back_only_when_local_ipc_is_unavailable() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::PermissionDenied,
        ] {
            assert!(status_ipc_is_unavailable(&std::io::Error::from(kind)));
        }

        assert!(!status_ipc_is_unavailable(&std::io::Error::from(
            std::io::ErrorKind::InvalidData,
        )));
        assert!(!status_ipc_is_unavailable(&std::io::Error::from(
            std::io::ErrorKind::TimedOut,
        )));
    }
}

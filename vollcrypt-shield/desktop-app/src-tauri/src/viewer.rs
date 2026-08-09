use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::Manager;
use vollcrypt_shield_core::{
    AuditEvent, AuditEventKind, DifferenceKind, EntryKind, MetadataPolicy, MlDsa65PublicKey,
    NormalizedPath, PolicyMode, ResponseAction, ResponsePolicy, ScanProfile, SignedSnapshot,
    Snapshot,
};
use vollcrypt_shield_fs::{
    AgentConfig, NotificationConfig, Scanner, ScopeConfig, ShieldAgent, audit_store::AuditStore,
    state::StateStore,
};
use vollcrypt_shield_protocol::witness::{
    QuorumExpectation, QuorumProof, SignedWitnessStatement, WitnessPolicy, verify_witness_quorum,
};
use vollcrypt_shield_protocol::{
    control_plane::{SignedAgentSummary, SignedEnrollmentRequest},
    offline::{MAX_OFFLINE_PAYLOAD_BYTES, OfflinePackageKind, SignedOfflinePackage},
    witness::AttestationRequest,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewerReport {
    config_path: String,
    state_dir: String,
    checked_at_unix_ms: u64,
    status: String,
    trust_score: u8,
    trust_level: String,
    trust_note: String,
    agent_key_id: String,
    audit_chain_valid: bool,
    state_signature_valid: bool,
    audit_error: Option<String>,
    state_error: Option<String>,
    witness: WitnessReport,
    events: Vec<EventReport>,
    scopes: Vec<ScopeReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflinePackageReport {
    package_path: String,
    kind: OfflinePackageKind,
    channel_id: String,
    sequence: u64,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    sender_key_id: String,
    package_hash: String,
    payload_bytes: usize,
    payload_status: String,
    scope_id: Option<String>,
    baseline_root: Option<String>,
    observed_root: Option<String>,
    epoch: Option<u64>,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderSetupReport {
    config_path: String,
    root_path: String,
    break_glass_secret_path: String,
    baseline_root: String,
    scope_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeReport {
    id: String,
    root: String,
    status: String,
    policy_mode: String,
    response_actions: Vec<String>,
    protected_system_path: bool,
    contained: bool,
    containment_reason: Option<String>,
    agent_online: bool,
    baseline_root: Option<String>,
    observed_root: Option<String>,
    baseline_created_at_unix_ms: Option<u64>,
    entry_count: usize,
    differences: Vec<DifferenceReport>,
    sample_paths: Vec<String>,
    error: Option<String>,
    witness_epoch: Option<u64>,
    accepted_witness_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WitnessReport {
    configured: bool,
    quorum_valid: bool,
    threshold: Option<usize>,
    registered_witnesses: usize,
    verified_scopes: usize,
    total_scopes: usize,
    policy_path: Option<String>,
    statements_dir: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DifferenceReport {
    path: String,
    absolute_path: String,
    kind: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileComparisonReport {
    relative_path: String,
    absolute_path: String,
    kind: String,
    baseline_digest: Option<String>,
    current_digest: Option<String>,
    baseline_size: Option<u64>,
    current_size: Option<u64>,
    baseline_text: Option<String>,
    current_text: Option<String>,
    content_status: String,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EventReport {
    sequence: u64,
    timestamp_unix_ms: u64,
    scope_id: String,
    kind: String,
    severity: String,
    path: Option<String>,
    detail: String,
}

#[tauri::command]
pub fn find_monitored_folder(
    app: tauri::AppHandle,
    root_path: String,
) -> Result<Option<String>, String> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    find_monitored_folder_at(Path::new(&root_path), &app_data).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn monitor_folder(
    app: tauri::AppHandle,
    root_path: String,
    break_glass_secret_path: String,
) -> Result<FolderSetupReport, String> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        monitor_folder_at(
            Path::new(&root_path),
            &app_data,
            Path::new(&break_glass_secret_path),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("folder setup worker failed: {error}"))?
}

fn find_monitored_folder_at(
    root_path: &Path,
    app_data: &Path,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let root = canonical_monitored_root(root_path)?;
    let (_, config_path) = managed_folder_paths(&root, app_data);
    if !config_path.exists() {
        return Ok(None);
    }
    let metadata = std::fs::symlink_metadata(&config_path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("managed folder configuration is not a regular file".into());
    }
    let text = String::from_utf8(read_bounded_regular(&config_path, 1_048_576)?)?;
    let config = AgentConfig::from_toml(&text)?;
    if config.scopes.len() != 1 || config.scopes[0].root.canonicalize()? != root {
        return Err("managed folder configuration does not match the selected folder".into());
    }
    Ok(Some(config_path.display().to_string()))
}

fn monitor_folder_at(
    root_path: &Path,
    app_data: &Path,
    break_glass_secret_path: &Path,
) -> Result<FolderSetupReport, Box<dyn std::error::Error>> {
    let root = canonical_monitored_root(root_path)?;
    if !app_data.is_absolute() {
        return Err("Shield application data path must be absolute".into());
    }
    let (state_dir, config_path) = managed_folder_paths(&root, app_data);
    if config_path.exists() || state_dir.exists() {
        return Err(
            "this folder already has managed Shield state; open its existing configuration".into(),
        );
    }

    let break_glass_secret_path = canonical_new_file_path(break_glass_secret_path)?;
    if break_glass_secret_path.starts_with(&root) {
        return Err(
            "the emergency recovery key must be stored outside the monitored folder".into(),
        );
    }
    let break_glass_public_path = break_glass_secret_path.with_extension("public");
    if break_glass_secret_path.exists() || break_glass_public_path.exists() {
        return Err("refusing to overwrite existing emergency recovery key material".into());
    }

    let scope_id = managed_scope_id(&root);
    let scope = ScopeConfig {
        id: scope_id.clone(),
        root: root.clone(),
        include: vec!["**".to_owned()],
        exclude: vec![],
        metadata: MetadataPolicy::default(),
        full_scan: ScanProfile::full_default(),
        incremental_scan: ScanProfile::incremental_default(),
        full_rescan_interval_secs: 300,
        response: ResponsePolicy::default(),
    };
    let config = AgentConfig {
        state_dir: state_dir.clone(),
        scopes: vec![scope.clone()],
        notifications: NotificationConfig::default(),
    };
    config.validate()?;

    // Preflight the complete tree before creating identity or recovery material.
    Scanner::new(&scope)?.full_scan(&scope)?;
    std::fs::create_dir_all(
        config_path
            .parent()
            .ok_or("managed configuration has no parent directory")?,
    )?;
    let mut agent = ShieldAgent::initialize(config.clone(), &break_glass_secret_path)?;
    let baseline = agent.create_baseline(&scope_id)?;
    write_new_private(&config_path, config.to_toml()?.as_bytes())?;

    Ok(FolderSetupReport {
        config_path: config_path.display().to_string(),
        root_path: root.display().to_string(),
        break_glass_secret_path: break_glass_secret_path.display().to_string(),
        baseline_root: hex::encode(baseline.root),
        scope_id,
    })
}

fn canonical_monitored_root(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("monitored folder path must be absolute".into());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("monitored folder must be a regular directory, not a symlink".into());
    }
    Ok(path.canonicalize()?)
}

fn canonical_new_file_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("emergency recovery key path must be absolute".into());
    }
    let file_name = path
        .file_name()
        .ok_or("emergency recovery key path has no file name")?;
    let parent = path
        .parent()
        .ok_or("emergency recovery key path has no parent directory")?
        .canonicalize()?;
    if !parent.is_dir() {
        return Err("emergency recovery key parent is not a directory".into());
    }
    Ok(parent.join(file_name))
}

fn managed_folder_paths(root: &Path, app_data: &Path) -> (PathBuf, PathBuf) {
    let digest = managed_folder_digest(root);
    let identifier = hex::encode(&digest[..12]);
    (
        app_data.join("agents").join(&identifier),
        app_data
            .join("configurations")
            .join(format!("{identifier}.toml")),
    )
}

fn managed_scope_id(root: &Path) -> String {
    let mut name = root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("folder")
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || matches!(value, '-' | '_' | '.') {
                value
            } else {
                '-'
            }
        })
        .collect::<String>();
    name.truncate(80);
    name = name.trim_matches('-').to_owned();
    if name.is_empty() {
        name = "folder".to_owned();
    }
    format!(
        "{}-{}",
        name,
        hex::encode(&managed_folder_digest(root)[..6])
    )
}

fn managed_folder_digest(root: &Path) -> [u8; 32] {
    let bytes = root.to_string_lossy();
    let mut hasher = Sha256::new();
    hasher.update(b"VOLLCRYPT-SHIELD-VIEWER-MANAGED-FOLDER-v1\0");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes.as_bytes());
    hasher.finalize().into()
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[tauri::command]
pub async fn inspect_agent(
    config_path: String,
    witness_policy_path: Option<String>,
    witness_statements_dir: Option<String>,
) -> Result<ViewerReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        inspect_agent_path(
            Path::new(&config_path),
            witness_policy_path.as_deref().map(Path::new),
            witness_statements_dir.as_deref().map(Path::new),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("verification worker failed: {error}"))?
}

#[tauri::command]
pub async fn inspect_offline_package(
    package_path: String,
    expected_public_key_path: String,
) -> Result<OfflinePackageReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        inspect_offline_package_path(
            Path::new(&package_path),
            Path::new(&expected_public_key_path),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("offline verification worker failed: {error}"))?
}

#[tauri::command]
pub async fn inspect_difference(
    config_path: String,
    scope_id: String,
    relative_path: String,
) -> Result<FileComparisonReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        inspect_difference_path(Path::new(&config_path), &scope_id, &relative_path)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("comparison worker failed: {error}"))?
}

fn inspect_offline_package_path(
    package_path: &Path,
    expected_public_key_path: &Path,
) -> Result<OfflinePackageReport, Box<dyn std::error::Error>> {
    let package_limit = u64::try_from(MAX_OFFLINE_PAYLOAD_BYTES)?
        .checked_add(65_536)
        .ok_or("offline package limit overflow")?;
    let package =
        SignedOfflinePackage::from_cbor(&read_bounded_regular(package_path, package_limit)?)?;
    let expected_public =
        MlDsa65PublicKey::from_bytes(&read_bounded_regular(expected_public_key_path, 1_952)?)?;
    let verified = package.verify_at(now_unix_ms()?)?;
    if verified.sender_public_key.as_bytes() != expected_public.as_bytes() {
        return Err("offline package signer does not match the selected trusted key".into());
    }

    let (payload_status, scope_id, baseline_root, observed_root, epoch, detail) =
        match verified.manifest.kind {
            OfflinePackageKind::FleetEnrollmentRequest => {
                let request = SignedEnrollmentRequest::from_cbor(&verified.payload)?;
                let (claim, signer) = request.verify()?;
                require_inner_signer(&signer, &expected_public)?;
                (
                    "valid enrollment request".to_owned(),
                    None,
                    None,
                    None,
                    None,
                    format!(
                        "Agent {} requests {:?} retention",
                        claim.agent_label, claim.retention_mode
                    ),
                )
            }
            OfflinePackageKind::FleetSummary => {
                let summary = SignedAgentSummary::from_cbor(&verified.payload)?;
                let (claim, signer) = summary.verify()?;
                require_inner_signer(&signer, &expected_public)?;
                (
                    "valid fleet summary".to_owned(),
                    Some(claim.scope_id),
                    Some(hex::encode(claim.baseline_root)),
                    Some(hex::encode(claim.observed_root)),
                    Some(claim.epoch),
                    format!(
                        "{:?}; {} reported differences",
                        claim.status, claim.difference_count
                    ),
                )
            }
            OfflinePackageKind::WitnessAttestationRequest => {
                let request = AttestationRequest::from_cbor(&verified.payload)?;
                let snapshot = request.verify(expected_public.key_id())?;
                (
                    "valid witness request".to_owned(),
                    Some(snapshot.scope_id),
                    Some(hex::encode(snapshot.root)),
                    None,
                    Some(request.epoch),
                    "Embedded signed snapshot verified".to_owned(),
                )
            }
            OfflinePackageKind::WitnessStatement => {
                let statement = SignedWitnessStatement::from_cbor(&verified.payload)?;
                let claim = statement.verify()?;
                require_inner_signer(&statement.public_key()?, &expected_public)?;
                (
                    "valid witness statement".to_owned(),
                    Some(claim.scope_id),
                    Some(hex::encode(claim.snapshot_root)),
                    None,
                    Some(claim.epoch),
                    format!("Witness {} statement verified", claim.witness_id),
                )
            }
            OfflinePackageKind::SnapshotEvidence => {
                let snapshot = SignedSnapshot::from_cbor(&verified.payload)?;
                require_inner_signer(&snapshot.public_key()?, &expected_public)?;
                let snapshot = snapshot.verify()?;
                (
                    "valid snapshot evidence".to_owned(),
                    Some(snapshot.scope_id),
                    Some(hex::encode(snapshot.root)),
                    None,
                    None,
                    format!("{} signed entries", snapshot.entries.len()),
                )
            }
        };

    Ok(OfflinePackageReport {
        package_path: package_path.display().to_string(),
        kind: verified.manifest.kind,
        channel_id: verified.manifest.channel_id,
        sequence: verified.manifest.sequence,
        created_at_unix_ms: verified.manifest.created_at_unix_ms,
        expires_at_unix_ms: verified.manifest.expires_at_unix_ms,
        sender_key_id: hex::encode(verified.manifest.sender_key_id),
        package_hash: hex::encode(verified.package_hash),
        payload_bytes: verified.payload.len(),
        payload_status,
        scope_id,
        baseline_root,
        observed_root,
        epoch,
        detail,
    })
}

fn require_inner_signer(
    inner: &MlDsa65PublicKey,
    expected: &MlDsa65PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if inner.as_bytes() != expected.as_bytes() {
        return Err("offline inner payload signer does not match the outer sender".into());
    }
    Ok(())
}

fn read_bounded_regular(path: &Path, limit: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

const MAX_COMPARISON_BYTES: u64 = 512 * 1024;
const FILE_CONTENT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-FILE-v1\0";

struct ContentPreview {
    text: Option<String>,
    status: &'static str,
}

fn inspect_difference_path(
    config_path: &Path,
    scope_id: &str,
    relative_path: &str,
) -> Result<FileComparisonReport, Box<dyn std::error::Error>> {
    let config_text = String::from_utf8(read_bounded_regular(config_path, 1_048_576)?)?;
    let config = AgentConfig::from_toml(&config_text)?;
    let scope = config
        .scopes
        .iter()
        .find(|scope| scope.id == scope_id)
        .ok_or("comparison scope is not configured")?;
    let normalized = NormalizedPath::new(relative_path.to_owned())?;
    let absolute_path = scope.root.join(normalized.as_str());

    let public_key = MlDsa65PublicKey::from_bytes(&read_bounded_regular(
        &config.state_dir.join("keys/agent.public"),
        1_952,
    )?)?;
    let snapshot_path = config
        .state_dir
        .join("snapshots")
        .join(format!("{}.snapshot.cbor", scope.id));
    let signed =
        SignedSnapshot::from_cbor(&read_bounded_regular(&snapshot_path, 64 * 1024 * 1024)?)?;
    if signed.public_key()?.key_id() != public_key.key_id() {
        return Err("baseline signer does not match the trusted agent key".into());
    }
    let snapshot = signed.verify()?;
    if snapshot.scope_id != scope.id {
        return Err("baseline scope does not match its configured scope".into());
    }
    let baseline = snapshot
        .entries
        .iter()
        .find(|entry| entry.path == normalized)
        .cloned();

    let current = match std::fs::symlink_metadata(&absolute_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
        Ok(_) => Scanner::new(scope)?
            .incremental_scan(scope, [absolute_path.clone()])?
            .into_iter()
            .find(|entry| entry.path == normalized),
    };

    let kind = match (&baseline, &current) {
        (None, Some(_)) => DifferenceKind::Added,
        (Some(_), None) => DifferenceKind::Removed,
        (Some(expected), Some(actual)) if expected != actual => DifferenceKind::Modified,
        _ => return Err("the selected path no longer differs from the signed baseline".into()),
    };

    let baseline_preview = match baseline.as_ref() {
        Some(entry) => {
            let object = config
                .state_dir
                .join("vault/objects")
                .join(hex::encode(entry.content_digest));
            verified_content_preview(&object, entry.kind, entry.size, &entry.content_digest)?
        }
        None => ContentPreview {
            text: None,
            status: "missing",
        },
    };
    let current_preview = match current.as_ref() {
        Some(entry) => verified_content_preview(
            &absolute_path,
            entry.kind,
            entry.size,
            &entry.content_digest,
        )?,
        None => ContentPreview {
            text: None,
            status: "missing",
        },
    };

    let content_status = if matches!(kind, DifferenceKind::Added)
        && current_preview.status == "text"
        || matches!(kind, DifferenceKind::Removed) && baseline_preview.status == "text"
        || matches!(kind, DifferenceKind::Modified)
            && baseline_preview.status == "text"
            && current_preview.status == "text"
    {
        "text"
    } else if baseline_preview.status == "too-large" || current_preview.status == "too-large" {
        "too-large"
    } else if baseline_preview.status == "binary" || current_preview.status == "binary" {
        "binary"
    } else {
        "not-text-file"
    };
    let detail = if content_status == "text"
        && baseline_preview.text.is_some()
        && baseline_preview.text == current_preview.text
    {
        "File contents match; the integrity difference is metadata-only."
    } else {
        match content_status {
            "text" => "Verified baseline and current text are available for comparison.",
            "too-large" => "Content comparison is limited to regular files of 512 KiB or less.",
            "binary" => "Binary content is not rendered; verified hashes and sizes are shown.",
            _ => "Content comparison is available only for regular text files.",
        }
    }
    .to_owned();

    Ok(FileComparisonReport {
        relative_path: normalized.to_string(),
        absolute_path: absolute_path.display().to_string(),
        kind: difference_kind(kind).to_owned(),
        baseline_digest: baseline
            .as_ref()
            .map(|entry| hex::encode(entry.content_digest)),
        current_digest: current
            .as_ref()
            .map(|entry| hex::encode(entry.content_digest)),
        baseline_size: baseline.as_ref().map(|entry| entry.size),
        current_size: current.as_ref().map(|entry| entry.size),
        baseline_text: baseline_preview.text,
        current_text: current_preview.text,
        content_status: content_status.to_owned(),
        detail,
    })
}

fn verified_content_preview(
    path: &Path,
    kind: EntryKind,
    size: u64,
    expected_digest: &[u8; 32],
) -> Result<ContentPreview, Box<dyn std::error::Error>> {
    if kind != EntryKind::File {
        return Ok(ContentPreview {
            text: None,
            status: "not-file",
        });
    }
    if size > MAX_COMPARISON_BYTES {
        return Ok(ContentPreview {
            text: None,
            status: "too-large",
        });
    }
    let bytes = read_bounded_regular(path, MAX_COMPARISON_BYTES)?;
    let mut hasher = Sha256::new();
    hasher.update(FILE_CONTENT_DOMAIN);
    hasher.update(&bytes);
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != *expected_digest {
        return Err(format!(
            "file changed while preparing comparison: {}",
            path.display()
        )
        .into());
    }
    match String::from_utf8(bytes) {
        Ok(text) if !text.contains('\0') => Ok(ContentPreview {
            text: Some(text),
            status: "text",
        }),
        _ => Ok(ContentPreview {
            text: None,
            status: "binary",
        }),
    }
}

fn inspect_agent_path(
    config_path: &Path,
    witness_policy_path: Option<&Path>,
    witness_statements_dir: Option<&Path>,
) -> Result<ViewerReport, Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml(&std::fs::read_to_string(config_path)?)?;
    let public_key =
        MlDsa65PublicKey::from_bytes(&std::fs::read(config.state_dir.join("keys/agent.public"))?)?;
    let agent_key_id = hex::encode(public_key.key_id());
    let witness_configured = witness_policy_path.is_some() || witness_statements_dir.is_some();
    let (witness_material, witness_error) =
        match load_witness_material(&config, witness_policy_path, witness_statements_dir) {
            Ok(material) => (material, None),
            Err(error) => (None, Some(error.to_string())),
        };

    let audit_path = config.state_dir.join("audit.log");
    let (audit_chain_valid, audit_error, events) = if audit_path.is_file() {
        match AuditStore::load_or_new(&audit_path, &public_key).and_then(|store| store.verify()) {
            Ok(events) => (
                true,
                None,
                events.iter().rev().take(500).map(event_report).collect(),
            ),
            Err(error) => (false, Some(error.to_string()), Vec::new()),
        }
    } else {
        (
            false,
            Some("signed audit log is not present".to_owned()),
            Vec::new(),
        )
    };

    let state_path = config.state_dir.join("state.cbor");
    let (state_signature_valid, state_error, state) = if state_path.is_file() {
        match StateStore::load_or_new(&state_path, &public_key) {
            Ok(state) => (true, None, Some(state)),
            Err(error) => (false, Some(error.to_string()), None),
        }
    } else {
        (
            false,
            Some("signed agent state is not present".to_owned()),
            None,
        )
    };

    let mut scopes = Vec::with_capacity(config.scopes.len());
    for scope in &config.scopes {
        let containment = state
            .as_ref()
            .and_then(|state| state.containment(&scope.id));
        let contained = containment.is_some();
        let containment_reason = containment.map(|value| value.reason.clone());
        let agent_online = local_agent_online(&config.state_dir, &scope.id);
        let snapshot_path = config
            .state_dir
            .join("snapshots")
            .join(format!("{}.snapshot.cbor", scope.id));

        let mut report = ScopeReport {
            id: scope.id.clone(),
            root: scope.root.display().to_string(),
            status: if contained { "contained" } else { "checking" }.to_owned(),
            policy_mode: policy_mode(scope.response.mode).to_owned(),
            response_actions: scope
                .response
                .actions
                .iter()
                .map(|action| response_action(*action).to_owned())
                .collect(),
            protected_system_path: scope.protects_system_path(),
            contained,
            containment_reason,
            agent_online,
            baseline_root: None,
            observed_root: None,
            baseline_created_at_unix_ms: None,
            entry_count: 0,
            differences: Vec::new(),
            sample_paths: Vec::new(),
            error: None,
            witness_epoch: None,
            accepted_witness_ids: Vec::new(),
        };

        let verification = (|| -> Result<_, Box<dyn std::error::Error>> {
            let signed = SignedSnapshot::from_cbor(&std::fs::read(&snapshot_path)?)?;
            if signed.public_key()?.key_id() != public_key.key_id() {
                return Err("baseline signer does not match the trusted agent key".into());
            }
            let snapshot = signed.verify()?;
            if snapshot.scope_id != scope.id {
                return Err("baseline scope does not match its configured scope".into());
            }
            let observed = Scanner::new(scope)?.full_scan(scope)?;
            let verification = Scanner::compare(&snapshot, &observed);
            Ok((snapshot, verification))
        })();

        match verification {
            Ok((snapshot, verification)) => {
                report.baseline_root = Some(hex::encode(snapshot.root));
                report.observed_root = Some(hex::encode(verification.observed_root));
                report.baseline_created_at_unix_ms = Some(snapshot.created_at_unix_ms);
                report.entry_count = snapshot.entries.len();
                report.sample_paths = snapshot
                    .entries
                    .iter()
                    .take(500)
                    .map(|entry| entry.path.to_string())
                    .collect();
                report.differences = verification
                    .differences
                    .iter()
                    .take(500)
                    .map(|difference| DifferenceReport {
                        path: difference.path.to_string(),
                        absolute_path: scope
                            .root
                            .join(difference.path.as_str())
                            .display()
                            .to_string(),
                        kind: difference_kind(difference.kind).to_owned(),
                    })
                    .collect();
                if let Some(material) = witness_material.as_ref()
                    && let Some(proof) =
                        verify_scope_quorum(material, public_key.key_id(), &snapshot)
                {
                    report.witness_epoch = Some(proof.epoch);
                    report.accepted_witness_ids = proof.accepted_witness_ids;
                }
                if !contained {
                    report.status = if verification.is_match() {
                        "verified"
                    } else {
                        "changed"
                    }
                    .to_owned();
                }
            }
            Err(error) => {
                report.status = if contained { "contained" } else { "invalid" }.to_owned();
                report.error = Some(error.to_string());
            }
        }
        scopes.push(report);
    }

    let has_invalid_trust = !audit_chain_valid || !state_signature_valid;
    let status = if has_invalid_trust || scopes.iter().any(|scope| scope.status == "invalid") {
        "invalid"
    } else if scopes.iter().any(|scope| scope.contained) {
        "contained"
    } else if scopes.iter().any(|scope| scope.status == "changed") {
        "attention"
    } else {
        "verified"
    };
    let verified_baselines = scopes
        .iter()
        .filter(|scope| scope.baseline_root.is_some() && scope.error.is_none())
        .count();
    let all_baselines_verified = verified_baselines == scopes.len();
    let witness_verified_scopes = scopes
        .iter()
        .filter(|scope| scope.witness_epoch.is_some())
        .count();
    let witness_quorum_valid =
        witness_material.is_some() && !scopes.is_empty() && witness_verified_scopes == scopes.len();
    let local_trust_score = if status == "invalid" {
        5
    } else {
        15 + u8::from(audit_chain_valid) * 10
            + u8::from(state_signature_valid) * 10
            + u8::from(all_baselines_verified) * 10
    };
    let trust_score = if status == "invalid" {
        local_trust_score
    } else if witness_quorum_valid {
        local_trust_score.saturating_add(35).min(100)
    } else if witness_verified_scopes > 0 {
        local_trust_score.saturating_add(15).min(100)
    } else {
        local_trust_score
    };
    let (trust_level, trust_note) = if witness_quorum_valid {
        (
            "witness-quorum",
            "Every baseline is independently anchored by the configured M-of-N witness policy.",
        )
    } else if witness_verified_scopes > 0 {
        (
            "partial-witness-quorum",
            "Some baselines have an independent witness quorum; unanchored scopes remain locally trusted.",
        )
    } else {
        (
            "local-unanchored",
            "Signatures are verified independently, but no complete external witness quorum anchors every baseline.",
        )
    };
    let witness = WitnessReport {
        configured: witness_configured,
        quorum_valid: witness_quorum_valid,
        threshold: witness_material
            .as_ref()
            .map(|material| material.policy.threshold),
        registered_witnesses: witness_material
            .as_ref()
            .map_or(0, |material| material.policy.witnesses.len()),
        verified_scopes: witness_verified_scopes,
        total_scopes: scopes.len(),
        policy_path: witness_policy_path.map(|path| path.display().to_string()),
        statements_dir: witness_statements_dir.map(|path| path.display().to_string()),
        error: witness_error,
    };

    Ok(ViewerReport {
        config_path: config_path.display().to_string(),
        state_dir: config.state_dir.display().to_string(),
        checked_at_unix_ms: now_unix_ms()?,
        status: status.to_owned(),
        trust_score,
        trust_level: trust_level.to_owned(),
        trust_note: trust_note.to_owned(),
        agent_key_id,
        audit_chain_valid,
        state_signature_valid,
        audit_error,
        state_error,
        witness,
        events,
        scopes,
    })
}

struct WitnessMaterial {
    policy: WitnessPolicy,
    statements: Vec<SignedWitnessStatement>,
}

fn load_witness_material(
    config: &AgentConfig,
    policy_path: Option<&Path>,
    statements_dir: Option<&Path>,
) -> Result<Option<WitnessMaterial>, Box<dyn std::error::Error>> {
    let (Some(policy_path), Some(statements_dir)) = (policy_path, statements_dir) else {
        if policy_path.is_none() && statements_dir.is_none() {
            return Ok(None);
        }
        return Err("witness policy and statements directory must be provided together".into());
    };

    let canonical_policy = policy_path.canonicalize()?;
    let canonical_state = config.state_dir.canonicalize()?;
    if canonical_policy.starts_with(&canonical_state) {
        return Err("witness policy must be pinned outside the agent state directory".into());
    }
    for scope in &config.scopes {
        if let Ok(root) = scope.root.canonicalize()
            && canonical_policy.starts_with(root)
        {
            return Err("witness policy must be pinned outside monitored scopes".into());
        }
    }

    let policy_metadata = std::fs::metadata(&canonical_policy)?;
    if !policy_metadata.is_file() || policy_metadata.len() > 1_048_576 {
        return Err("witness policy must be a regular JSON file no larger than 1 MiB".into());
    }
    let policy: WitnessPolicy = serde_json::from_slice(&std::fs::read(&canonical_policy)?)?;
    policy.validate()?;

    let canonical_statements = statements_dir.canonicalize()?;
    if !canonical_statements.is_dir() {
        return Err("witness statements path must be a directory".into());
    }
    let mut statement_paths = Vec::new();
    for entry in std::fs::read_dir(&canonical_statements)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "cbor")
        {
            statement_paths.push(entry.path());
        }
    }
    statement_paths.sort();
    if statement_paths.len() > 4_096 {
        return Err("witness statement directory exceeds the 4096-file limit".into());
    }
    let mut statements = Vec::with_capacity(statement_paths.len());
    for path in statement_paths {
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() > 1_048_576 {
            return Err(
                format!("witness statement is larger than 1 MiB: {}", path.display()).into(),
            );
        }
        statements.push(SignedWitnessStatement::from_cbor(&std::fs::read(path)?)?);
    }
    Ok(Some(WitnessMaterial { policy, statements }))
}

fn verify_scope_quorum(
    material: &WitnessMaterial,
    agent_key_id: [u8; 32],
    snapshot: &Snapshot,
) -> Option<QuorumProof> {
    let epochs: BTreeSet<u64> = material
        .statements
        .iter()
        .filter_map(|statement| statement.verify().ok())
        .filter(|claim| {
            claim.agent_key_id == agent_key_id
                && claim.scope_id == snapshot.scope_id
                && claim.snapshot_root == snapshot.root
                && claim.snapshot_created_at_unix_ms == snapshot.created_at_unix_ms
        })
        .map(|claim| claim.epoch)
        .collect();

    epochs.iter().rev().find_map(|epoch| {
        verify_witness_quorum(
            &material.policy,
            &QuorumExpectation {
                agent_key_id,
                scope_id: snapshot.scope_id.clone(),
                snapshot_root: snapshot.root,
                snapshot_created_at_unix_ms: snapshot.created_at_unix_ms,
                epoch: *epoch,
            },
            &material.statements,
        )
        .ok()
    })
}

fn event_report(event: &AuditEvent) -> EventReport {
    EventReport {
        sequence: event.sequence,
        timestamp_unix_ms: event.timestamp_unix_ms,
        scope_id: event.scope_id.clone(),
        kind: audit_kind(event.kind).to_owned(),
        severity: event_severity(event.kind).to_owned(),
        path: event.path.clone(),
        detail: event.detail.clone(),
    }
}

fn audit_kind(kind: AuditEventKind) -> &'static str {
    match kind {
        AuditEventKind::AgentStarted => "Agent started",
        AuditEventKind::BaselineCreated => "Baseline created",
        AuditEventKind::VerificationPassed => "Verification passed",
        AuditEventKind::VerificationFailed => "Verification failed",
        AuditEventKind::DryRunResponse => "Dry-run response",
        AuditEventKind::Quarantined => "Quarantined",
        AuditEventKind::RolledBack => "Rolled back",
        AuditEventKind::ScopeContained => "Scope contained",
        AuditEventKind::ContainmentReminder => "Containment reminder",
        AuditEventKind::BreakGlassReleased => "Break-glass released",
        AuditEventKind::PolicyPromoted => "Policy activated",
        AuditEventKind::AgentStopped => "Agent stopped",
        AuditEventKind::MonitoringFailed => "Monitoring failed",
    }
}

fn event_severity(kind: AuditEventKind) -> &'static str {
    match kind {
        AuditEventKind::VerificationFailed
        | AuditEventKind::ScopeContained
        | AuditEventKind::MonitoringFailed => "critical",
        AuditEventKind::Quarantined
        | AuditEventKind::RolledBack
        | AuditEventKind::ContainmentReminder
        | AuditEventKind::BreakGlassReleased => "warning",
        _ => "info",
    }
}

fn policy_mode(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::DryRun => "dry-run",
        PolicyMode::Active => "active",
    }
}

fn response_action(action: ResponseAction) -> &'static str {
    match action {
        ResponseAction::Warn => "warn",
        ResponseAction::Quarantine => "quarantine",
        ResponseAction::Rollback => "rollback",
        ResponseAction::ContainScope => "contain-scope",
    }
}

fn difference_kind(kind: DifferenceKind) -> &'static str {
    match kind {
        DifferenceKind::Added => "added",
        DifferenceKind::Removed => "removed",
        DifferenceKind::Modified => "modified",
    }
}

#[cfg(unix)]
fn local_agent_online(state_dir: &Path, scope_id: &str) -> bool {
    vollcrypt_shield_fs::query_local_status(state_dir, scope_id).is_ok()
}

#[cfg(not(unix))]
fn local_agent_online(_state_dir: &Path, _scope_id: &str) -> bool {
    false
}

fn now_unix_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::{MetadataPolicy, MlDsa65KeyPair, ResponsePolicy, ScanProfile};
    use vollcrypt_shield_fs::{NotificationConfig, ScopeConfig, ShieldAgent};
    use vollcrypt_shield_protocol::witness::{WitnessIdentity, WitnessLedger};
    use vollcrypt_shield_protocol::{
        control_plane::{
            AgentIntegrityStatus, AgentSummaryClaim, AgentSummaryInput, SignedAgentSummary,
        },
        offline::{OfflinePackageInput, OfflinePackageKind, SignedOfflinePackage},
    };

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("watched");
        let state_dir = directory.path().join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("app.conf"), b"approved").unwrap();
        let config = AgentConfig {
            state_dir,
            scopes: vec![ScopeConfig {
                id: "application".to_owned(),
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
        let config_path = directory.path().join("shield.toml");
        std::fs::write(&config_path, config.to_toml().unwrap()).unwrap();
        let break_glass = directory.path().join("break-glass.seed");
        let mut agent = ShieldAgent::initialize(config, &break_glass).unwrap();
        agent.create_baseline("application").unwrap();
        (directory, config_path)
    }

    #[test]
    fn independently_verifies_local_agent_artifacts() {
        let (_directory, config_path) = fixture();
        let report = inspect_agent_path(&config_path, None, None).unwrap();
        assert_eq!(report.status, "verified");
        assert!(report.audit_chain_valid);
        assert!(report.state_signature_valid);
        assert_eq!(report.scopes[0].status, "verified");
        assert_eq!(report.trust_level, "local-unanchored");
    }

    #[test]
    fn direct_folder_setup_creates_dry_run_baseline_and_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("project");
        let app_data = directory.path().join("viewer-data");
        let recovery = directory.path().join("recovery/shield-break-glass.seed");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(recovery.parent().unwrap()).unwrap();
        std::fs::write(root.join("app.conf"), b"approved").unwrap();

        let setup = monitor_folder_at(&root, &app_data, &recovery).unwrap();
        let config_path = PathBuf::from(&setup.config_path);
        let config =
            AgentConfig::from_toml(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(config.scopes.len(), 1);
        assert_eq!(config.scopes[0].response.mode, PolicyMode::DryRun);
        assert_eq!(
            config.scopes[0].response.actions,
            vec![ResponseAction::Warn]
        );
        assert!(recovery.is_file());
        assert!(recovery.with_extension("public").is_file());
        assert_eq!(
            find_monitored_folder_at(&root, &app_data).unwrap(),
            Some(setup.config_path.clone())
        );

        let report = inspect_agent_path(&config_path, None, None).unwrap();
        assert_eq!(report.status, "verified");
        assert_eq!(
            report.scopes[0].root,
            root.canonicalize().unwrap().display().to_string()
        );
        assert_eq!(report.scopes[0].policy_mode, "dry-run");
    }

    #[test]
    fn direct_folder_setup_rejects_recovery_key_inside_scope() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("project");
        let app_data = directory.path().join("viewer-data");
        std::fs::create_dir(&root).unwrap();
        let recovery = root.join("shield-break-glass.seed");

        let error = monitor_folder_at(&root, &app_data, &recovery)
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside the monitored folder"));
        assert!(!app_data.exists());
        assert!(!recovery.exists());
    }

    #[test]
    fn reports_filesystem_drift_without_mutating_the_agent() {
        let (directory, config_path) = fixture();
        std::fs::write(directory.path().join("watched/app.conf"), b"changed").unwrap();
        let report = inspect_agent_path(&config_path, None, None).unwrap();
        assert_eq!(report.status, "attention");
        assert_eq!(report.scopes[0].status, "changed");
        assert_eq!(report.scopes[0].differences.len(), 1);
        assert_eq!(
            report.scopes[0].differences[0].absolute_path,
            directory
                .path()
                .join("watched")
                .join("app.conf")
                .display()
                .to_string()
        );
    }

    #[test]
    fn comparison_returns_verified_text_for_modified_added_and_removed_files() {
        let (directory, config_path) = fixture();
        let watched = directory.path().join("watched");

        std::fs::write(watched.join("app.conf"), b"changed\nsecond line\n").unwrap();
        let modified = inspect_difference_path(&config_path, "application", "app.conf").unwrap();
        assert_eq!(modified.kind, "modified");
        assert_eq!(modified.content_status, "text");
        assert_eq!(modified.baseline_text.as_deref(), Some("approved"));
        assert_eq!(
            modified.current_text.as_deref(),
            Some("changed\nsecond line\n")
        );
        assert_eq!(
            modified.absolute_path,
            watched.join("app.conf").display().to_string()
        );

        std::fs::write(watched.join("new.txt"), b"new content").unwrap();
        let added = inspect_difference_path(&config_path, "application", "new.txt").unwrap();
        assert_eq!(added.kind, "added");
        assert!(added.baseline_text.is_none());
        assert_eq!(added.current_text.as_deref(), Some("new content"));

        std::fs::remove_file(watched.join("app.conf")).unwrap();
        let removed = inspect_difference_path(&config_path, "application", "app.conf").unwrap();
        assert_eq!(removed.kind, "removed");
        assert_eq!(removed.baseline_text.as_deref(), Some("approved"));
        assert!(removed.current_text.is_none());
    }

    #[test]
    fn rejects_tampered_baseline_signature() {
        let (directory, config_path) = fixture();
        let baseline = directory
            .path()
            .join("state/snapshots/application.snapshot.cbor");
        let mut bytes = std::fs::read(&baseline).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(baseline, bytes).unwrap();
        let report = inspect_agent_path(&config_path, None, None).unwrap();
        assert_eq!(report.status, "invalid");
        assert_eq!(report.scopes[0].status, "invalid");
    }

    #[test]
    fn independently_verifies_two_of_two_witness_quorum() {
        let (directory, config_path) = fixture();
        let config =
            AgentConfig::from_toml(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let agent = ShieldAgent::load(config).unwrap();
        let request = agent.attestation_request("application", 1).unwrap();
        let witness_a = MlDsa65KeyPair::generate().unwrap();
        let witness_b = MlDsa65KeyPair::generate().unwrap();
        let mut ledger_a = WitnessLedger::default();
        let mut ledger_b = WitnessLedger::default();
        let statement_a = ledger_a
            .attest(
                &request,
                agent.agent_key_id(),
                "witness-a",
                &witness_a.secret,
                100,
            )
            .unwrap();
        let statement_b = ledger_b
            .attest(
                &request,
                agent.agent_key_id(),
                "witness-b",
                &witness_b.secret,
                101,
            )
            .unwrap();
        let policy = WitnessPolicy {
            threshold: 2,
            witnesses: vec![
                WitnessIdentity {
                    id: "witness-a".to_owned(),
                    public_key: witness_a.public.as_bytes().to_vec(),
                },
                WitnessIdentity {
                    id: "witness-b".to_owned(),
                    public_key: witness_b.public.as_bytes().to_vec(),
                },
            ],
        };
        let policy_path = directory.path().join("trusted-witness-policy.json");
        std::fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
        let statements_dir = directory.path().join("statements");
        std::fs::create_dir(&statements_dir).unwrap();
        std::fs::write(
            statements_dir.join("witness-a.cbor"),
            statement_a.to_cbor().unwrap(),
        )
        .unwrap();
        std::fs::write(
            statements_dir.join("witness-b.cbor"),
            statement_b.to_cbor().unwrap(),
        )
        .unwrap();

        let report =
            inspect_agent_path(&config_path, Some(&policy_path), Some(&statements_dir)).unwrap();
        assert!(report.witness.quorum_valid);
        assert_eq!(report.witness.verified_scopes, 1);
        assert_eq!(report.trust_level, "witness-quorum");
        assert_eq!(report.scopes[0].accepted_witness_ids.len(), 2);
    }

    #[test]
    fn independently_verifies_offline_outer_and_inner_signatures() {
        let directory = tempfile::tempdir().unwrap();
        let agent = MlDsa65KeyPair::generate().unwrap();
        let now = now_unix_ms().unwrap();
        let claim = AgentSummaryClaim::new(AgentSummaryInput {
            agent_key_id: agent.public.key_id(),
            scope_id: "offline-app".to_owned(),
            baseline_root: [3; 32],
            observed_root: [4; 32],
            observed_at_unix_ms: now,
            epoch: 1,
            status: AgentIntegrityStatus::Mismatch,
            difference_count: 1,
            previous_summary_hash: [0; 32],
        })
        .unwrap();
        let summary = SignedAgentSummary::sign(&claim, &agent.secret).unwrap();
        let package = SignedOfflinePackage::sign(
            OfflinePackageInput {
                kind: OfflinePackageKind::FleetSummary,
                channel_id: "viewer-offline".to_owned(),
                created_at_unix_ms: now,
                expires_at_unix_ms: now + 60_000,
                sequence: 1,
                previous_package_hash: [0; 32],
                payload: summary.to_cbor().unwrap(),
            },
            &agent.secret,
        )
        .unwrap();
        let package_path = directory.path().join("summary.vcsp");
        let public_path = directory.path().join("agent.public");
        std::fs::write(&package_path, package.to_cbor().unwrap()).unwrap();
        std::fs::write(&public_path, agent.public.as_bytes()).unwrap();

        let report = inspect_offline_package_path(&package_path, &public_path).unwrap();
        assert_eq!(report.kind, OfflinePackageKind::FleetSummary);
        assert_eq!(report.scope_id.as_deref(), Some("offline-app"));
        assert_eq!(report.sequence, 1);

        let other = MlDsa65KeyPair::generate().unwrap();
        std::fs::write(&public_path, other.public.as_bytes()).unwrap();
        assert!(inspect_offline_package_path(&package_path, &public_path).is_err());
    }
}

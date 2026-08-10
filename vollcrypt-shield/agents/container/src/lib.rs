#![forbid(unsafe_code)]

mod runtime;

pub use runtime::{
    MonitorSummary, RuntimeDecision, RuntimeKind, RuntimePolicy, SidecarEvidence, check_sidecar,
    monitor_containerd, monitor_docker, serve_sidecar,
};

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{
    DifferenceKind, EntryKind, IntegrityEntry, MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey,
    NormalizedPath, SignedSnapshot, Snapshot, VerificationDifference, VerificationReport,
};

const BASELINE_FILE: &str = "baseline.snapshot.cbor";
const KEY_DIRECTORY: &str = "keys";
const PUBLIC_KEY_FILE: &str = "agent.public";
const SCOPE_FILE: &str = "scope.id";
const SECRET_KEY_FILE: &str = "agent.seed";
const MAX_BASELINE_BYTES: u64 = 134_217_728;

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid OCI layout: {0}")]
    InvalidLayout(String),
    #[error("OCI scan limit exceeded: {0}")]
    Limit(String),
    #[error("invalid container agent state: {0}")]
    State(String),
    #[error(transparent)]
    Core(#[from] vollcrypt_shield_core::ShieldError),
}

pub type Result<T> = std::result::Result<T, ContainerError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrationMode {
    HostAgent,
    Sidecar,
    AdmissionController,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuaranteeLevel {
    Strong,
    Constrained,
    BuildTimeOnly,
}

impl IntegrationMode {
    pub const fn guarantee(self) -> GuaranteeLevel {
        match self {
            Self::HostAgent => GuaranteeLevel::Strong,
            Self::Sidecar => GuaranteeLevel::Constrained,
            Self::AdmissionController => GuaranteeLevel::BuildTimeOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciScanLimits {
    pub max_descriptors: usize,
    pub max_json_bytes: u64,
    pub max_blob_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for OciScanLimits {
    fn default() -> Self {
        Self {
            max_descriptors: 100_000,
            max_json_bytes: 4_194_304,
            max_blob_bytes: 17_179_869_184,
            max_total_bytes: 68_719_476_736,
        }
    }
}

impl OciScanLimits {
    fn validate(&self) -> Result<()> {
        if self.max_descriptors == 0
            || self.max_json_bytes == 0
            || self.max_blob_bytes == 0
            || self.max_total_bytes < self.max_blob_bytes
        {
            return Err(ContainerError::InvalidLayout(
                "OCI limits must be non-zero and total bytes must cover one blob".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciScanReport {
    pub integration_mode: IntegrationMode,
    pub guarantee_level: GuaranteeLevel,
    pub descriptors_verified: usize,
    pub bytes_verified: u64,
    pub snapshot: Snapshot,
}

pub struct OciLayoutScanner {
    root: PathBuf,
    limits: OciScanLimits,
}

pub struct ContainerAgent {
    state_dir: PathBuf,
    scope_id: String,
    secret: MlDsa65SecretKey,
    public: MlDsa65PublicKey,
}

impl ContainerAgent {
    pub fn initialize(state_dir: &Path, scope_id: &str) -> Result<Self> {
        validate_scope_id(scope_id)?;
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
            return Err(ContainerError::State(
                "refusing to overwrite existing container agent identity".to_owned(),
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
        if secret.public_key()?.key_id() != public.key_id() {
            return Err(ContainerError::State(
                "container agent secret and public keys do not match".to_owned(),
            ));
        }
        let scope_bytes = read_regular(&state_dir.join(SCOPE_FILE), 128)?;
        let scope_id = String::from_utf8(scope_bytes)
            .map_err(|_| ContainerError::State("scope id is not UTF-8".to_owned()))?;
        validate_scope_id(&scope_id)?;
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
        layout: &Path,
        limits: OciScanLimits,
        replace: bool,
    ) -> Result<OciScanReport> {
        self.ensure_disjoint(layout)?;
        let baseline_path = self.baseline_path();
        if baseline_path.exists() {
            self.load_baseline()?;
            if !replace {
                return Err(ContainerError::State(
                    "baseline exists; pass --replace to approve replacement".to_owned(),
                ));
            }
        }
        let mut report = OciLayoutScanner::new(layout, limits)?.scan(now_unix_ms()?)?;
        report.snapshot.scope_id.clone_from(&self.scope_id);
        report.snapshot.validate()?;
        let signed = SignedSnapshot::sign(&report.snapshot, &self.secret)?;
        write_atomic(&baseline_path, &signed.to_cbor()?, replace)?;
        Ok(report)
    }

    pub fn load_baseline(&self) -> Result<Snapshot> {
        let signed =
            SignedSnapshot::from_cbor(&read_regular(&self.baseline_path(), MAX_BASELINE_BYTES)?)?;
        if signed.public_key()?.key_id() != self.public.key_id() {
            return Err(ContainerError::State(
                "baseline signer does not match container agent identity".to_owned(),
            ));
        }
        let snapshot = signed.verify()?;
        if snapshot.scope_id != self.scope_id {
            return Err(ContainerError::State(
                "baseline scope does not match container agent scope".to_owned(),
            ));
        }
        Ok(snapshot)
    }

    pub fn verify_layout(
        &self,
        layout: &Path,
        limits: OciScanLimits,
    ) -> Result<(OciScanReport, VerificationReport)> {
        self.ensure_disjoint(layout)?;
        let baseline = self.load_baseline()?;
        let mut observed = OciLayoutScanner::new(layout, limits)?.scan(now_unix_ms()?)?;
        observed.snapshot.scope_id.clone_from(&self.scope_id);
        observed.snapshot.validate()?;
        let verification = compare_snapshots(&baseline, &observed.snapshot);
        Ok((observed, verification))
    }

    fn baseline_path(&self) -> PathBuf {
        self.state_dir.join(BASELINE_FILE)
    }

    fn ensure_disjoint(&self, layout: &Path) -> Result<()> {
        let layout = layout.canonicalize()?;
        if self.state_dir.starts_with(&layout) || layout.starts_with(&self.state_dir) {
            return Err(ContainerError::State(
                "state directory and OCI layout must not contain one another".to_owned(),
            ));
        }
        Ok(())
    }
}

impl OciLayoutScanner {
    pub fn new(root: &Path, limits: OciScanLimits) -> Result<Self> {
        limits.validate()?;
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(ContainerError::InvalidLayout(
                "OCI layout root must be a directory".to_owned(),
            ));
        }
        Ok(Self { root, limits })
    }

    pub fn scan(&self, created_at_unix_ms: u64) -> Result<OciScanReport> {
        let layout_bytes = self.read_control_file("oci-layout", 65_536)?;
        let layout: OciLayout = serde_json::from_slice(&layout_bytes)
            .map_err(|error| ContainerError::InvalidLayout(error.to_string()))?;
        if layout.image_layout_version != "1.0.0" {
            return Err(ContainerError::InvalidLayout(
                "unsupported OCI image layout version".to_owned(),
            ));
        }
        let index_bytes = self.read_control_file("index.json", self.limits.max_json_bytes)?;
        let index: OciIndex = parse_json(&index_bytes, "index.json")?;
        if index.schema_version != 2 || index.manifests.is_empty() {
            return Err(ContainerError::InvalidLayout(
                "OCI index must use schemaVersion 2 and contain a descriptor".to_owned(),
            ));
        }

        let mut entries = vec![
            entry_for_bytes("oci-layout", &layout_bytes)?,
            entry_for_bytes("index.json", &index_bytes)?,
        ];
        let mut queue: VecDeque<_> = index.manifests.into();
        let mut visited = BTreeMap::new();
        let mut descriptors_seen = 0_usize;
        let layout_size = u64::try_from(layout_bytes.len())
            .map_err(|_| ContainerError::Limit("layout size exceeds u64".to_owned()))?;
        let index_size = u64::try_from(index_bytes.len())
            .map_err(|_| ContainerError::Limit("index size exceeds u64".to_owned()))?;
        let mut bytes_verified = layout_size
            .checked_add(index_size)
            .ok_or_else(|| ContainerError::Limit("verified byte count overflow".to_owned()))?;

        while let Some(descriptor) = queue.pop_front() {
            descriptor.validate(&self.limits)?;
            descriptors_seen = descriptors_seen
                .checked_add(1)
                .ok_or_else(|| ContainerError::Limit("descriptor count overflow".to_owned()))?;
            if descriptors_seen > self.limits.max_descriptors {
                return Err(ContainerError::Limit(format!(
                    "descriptor count exceeds {}",
                    self.limits.max_descriptors
                )));
            }
            let binding = (descriptor.media_type.clone(), descriptor.size);
            if let Some(existing) = visited.get(&descriptor.digest) {
                if existing != &binding {
                    return Err(ContainerError::InvalidLayout(format!(
                        "descriptor digest has conflicting mediaType or size: {}",
                        descriptor.digest
                    )));
                }
                continue;
            }
            visited.insert(descriptor.digest.clone(), binding);
            let digest = descriptor.digest_hex()?;
            let relative = format!("blobs/sha256/{digest}");
            let path = self.safe_regular_file(&relative)?;
            let metadata = std::fs::metadata(&path)?;
            if metadata.len() != descriptor.size {
                return Err(ContainerError::InvalidLayout(format!(
                    "descriptor size mismatch for {}",
                    descriptor.digest
                )));
            }
            bytes_verified = bytes_verified
                .checked_add(metadata.len())
                .ok_or_else(|| ContainerError::Limit("verified byte count overflow".to_owned()))?;
            if bytes_verified > self.limits.max_total_bytes {
                return Err(ContainerError::Limit(format!(
                    "verified bytes exceed {}",
                    self.limits.max_total_bytes
                )));
            }
            let (actual_digest, bytes) = hash_and_maybe_read(
                &path,
                metadata.len(),
                is_json_media_type(&descriptor.media_type),
                self.limits.max_json_bytes,
            )?;
            if actual_digest != digest {
                return Err(ContainerError::InvalidLayout(format!(
                    "descriptor digest mismatch for {}",
                    descriptor.digest
                )));
            }
            entries.push(IntegrityEntry::new(
                NormalizedPath::new(relative)?,
                EntryKind::File,
                actual_digest_bytes(&actual_digest)?,
                [0; 32],
                metadata.len(),
            ));

            if matches!(descriptor.media_type.as_str(), OCI_INDEX | DOCKER_INDEX) {
                let nested: OciIndex = parse_json(&bytes, "nested OCI index")?;
                if nested.schema_version != 2 {
                    return Err(ContainerError::InvalidLayout(
                        "nested OCI index must use schemaVersion 2".to_owned(),
                    ));
                }
                queue.extend(nested.manifests);
            } else if matches!(
                descriptor.media_type.as_str(),
                OCI_MANIFEST | DOCKER_MANIFEST
            ) {
                let manifest: OciManifest = parse_json(&bytes, "OCI manifest")?;
                if manifest.schema_version != 2 {
                    return Err(ContainerError::InvalidLayout(
                        "OCI manifest must use schemaVersion 2".to_owned(),
                    ));
                }
                queue.push_back(manifest.config);
                queue.extend(manifest.layers);
            }
        }

        let snapshot = Snapshot::new("oci-image-layout", entries, created_at_unix_ms)?;
        Ok(OciScanReport {
            integration_mode: IntegrationMode::HostAgent,
            guarantee_level: IntegrationMode::HostAgent.guarantee(),
            descriptors_verified: visited.len(),
            bytes_verified,
            snapshot,
        })
    }

    fn read_control_file(&self, relative: &str, limit: u64) -> Result<Vec<u8>> {
        let path = self.safe_regular_file(relative)?;
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() > limit {
            return Err(ContainerError::Limit(format!(
                "control file {relative} exceeds {limit} bytes"
            )));
        }
        let capacity = usize::try_from(metadata.len())
            .map_err(|_| ContainerError::Limit("control file exceeds address space".to_owned()))?;
        let mut bytes = Vec::with_capacity(capacity);
        File::open(path)?
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(ContainerError::Limit(format!(
                "control file {relative} changed beyond its size limit"
            )));
        }
        Ok(bytes)
    }

    fn safe_regular_file(&self, relative: &str) -> Result<PathBuf> {
        let mut path = self.root.clone();
        let mut components = Path::new(relative).components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(component) = component else {
                return Err(ContainerError::InvalidLayout(format!(
                    "OCI entry has an unsafe path: {relative}"
                )));
            };
            path.push(component);
            let metadata = std::fs::symlink_metadata(&path)?;
            let is_final = components.peek().is_none();
            if metadata.file_type().is_symlink()
                || (is_final && !metadata.is_file())
                || (!is_final && !metadata.is_dir())
            {
                return Err(ContainerError::InvalidLayout(format!(
                    "OCI entry has a non-regular or symlink path component: {relative}"
                )));
            }
        }
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&self.root) {
            return Err(ContainerError::InvalidLayout(
                "OCI entry resolves outside layout root".to_owned(),
            ));
        }
        Ok(canonical)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OciLayout {
    image_layout_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciIndex {
    schema_version: u32,
    manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifest {
    schema_version: u32,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciDescriptor {
    media_type: String,
    digest: String,
    size: u64,
}

impl OciDescriptor {
    fn validate(&self, limits: &OciScanLimits) -> Result<()> {
        if self.media_type.is_empty() || self.media_type.len() > 256 {
            return Err(ContainerError::InvalidLayout(
                "descriptor mediaType is invalid".to_owned(),
            ));
        }
        self.digest_hex()?;
        if self.size > limits.max_blob_bytes {
            return Err(ContainerError::Limit(format!(
                "descriptor blob exceeds {} bytes",
                limits.max_blob_bytes
            )));
        }
        Ok(())
    }

    fn digest_hex(&self) -> Result<String> {
        let value = self.digest.strip_prefix("sha256:").ok_or_else(|| {
            ContainerError::InvalidLayout("only sha256 OCI descriptors are supported".to_owned())
        })?;
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(ContainerError::InvalidLayout(
                "descriptor digest must be lowercase sha256 hex".to_owned(),
            ));
        }
        Ok(value.to_owned())
    }
}

fn parse_json<'bytes, Value: Deserialize<'bytes>>(
    bytes: &'bytes [u8],
    label: &str,
) -> Result<Value> {
    serde_json::from_slice(bytes)
        .map_err(|error| ContainerError::InvalidLayout(format!("{label}: {error}")))
}

fn is_json_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        OCI_INDEX | DOCKER_INDEX | OCI_MANIFEST | DOCKER_MANIFEST
    )
}

fn hash_and_maybe_read(
    path: &Path,
    size: u64,
    retain: bool,
    retain_limit: u64,
) -> Result<(String, Vec<u8>)> {
    if retain && size > retain_limit {
        return Err(ContainerError::Limit(
            "JSON descriptor blob exceeds parse limit".to_owned(),
        ));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut retained = if retain {
        Vec::with_capacity(
            usize::try_from(size)
                .map_err(|_| ContainerError::Limit("JSON blob exceeds address space".to_owned()))?,
        )
    } else {
        Vec::new()
    };
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if retain {
            retained.extend_from_slice(&buffer[..read]);
        }
    }
    Ok((hex::encode(hasher.finalize()), retained))
}

fn entry_for_bytes(path: &str, bytes: &[u8]) -> Result<IntegrityEntry> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Ok(IntegrityEntry::new(
        NormalizedPath::new(path)?,
        EntryKind::File,
        digest,
        [0; 32],
        u64::try_from(bytes.len())
            .map_err(|_| ContainerError::Limit("entry size exceeds u64".to_owned()))?,
    ))
}

fn compare_snapshots(baseline: &Snapshot, observed: &Snapshot) -> VerificationReport {
    use std::collections::BTreeMap;

    let baseline_entries: BTreeMap<_, _> = baseline
        .entries
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect();
    let observed_entries: BTreeMap<_, _> = observed
        .entries
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect();
    let mut differences = Vec::new();

    for (path, expected) in &baseline_entries {
        match observed_entries.get(path) {
            None => differences.push(VerificationDifference {
                path: (*path).clone(),
                kind: DifferenceKind::Removed,
            }),
            Some(actual) if *actual != *expected => differences.push(VerificationDifference {
                path: (*path).clone(),
                kind: DifferenceKind::Modified,
            }),
            Some(_) => {}
        }
    }
    for path in observed_entries.keys() {
        if !baseline_entries.contains_key(path) {
            differences.push(VerificationDifference {
                path: (*path).clone(),
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

fn validate_scope_id(scope_id: &str) -> Result<()> {
    if scope_id.is_empty()
        || scope_id.len() > 128
        || !scope_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ContainerError::State(
            "scope id must be 1-128 ASCII identifier characters".to_owned(),
        ));
    }
    Ok(())
}

fn now_unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ContainerError::State(error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| ContainerError::State("system time exceeds u64 milliseconds".to_owned()))
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ContainerError::State(format!(
            "state entry is not a regular non-symlink file: {}",
            path.display()
        )));
    }
    if metadata.len() > limit {
        return Err(ContainerError::State(format!(
            "state entry exceeds {limit} bytes: {}",
            path.display()
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| ContainerError::State("state entry exceeds address space".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(ContainerError::State(
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
    if temporary.exists() {
        return Err(ContainerError::State(format!(
            "stale temporary state file blocks update: {}",
            temporary.display()
        )));
    }
    write_new(&temporary, bytes, false)?;
    if !replace {
        match std::fs::hard_link(&temporary, path) {
            Ok(()) => {
                std::fs::remove_file(temporary)?;
                return Ok(());
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
    }
    if path.exists() {
        #[cfg(windows)]
        {
            let backup = path.with_extension("previous");
            if backup.exists() {
                let _ = std::fs::remove_file(&temporary);
                return Err(ContainerError::State(
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
    }
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn secure_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ContainerError::State(format!(
                "state path is not a regular non-symlink directory: {}",
                path.display()
            )));
        }
    } else {
        std::fs::create_dir_all(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn actual_digest_bytes(digest: &str) -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(digest, &mut bytes)
        .map_err(|_| ContainerError::InvalidLayout("invalid computed digest".to_owned()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verifies_complete_oci_descriptor_chain_and_rejects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let layer_digest = create_layout(directory.path());

        let scanner = OciLayoutScanner::new(directory.path(), OciScanLimits::default()).unwrap();
        let report = scanner.scan(10).unwrap();
        assert_eq!(report.guarantee_level, GuaranteeLevel::Strong);
        assert_eq!(report.descriptors_verified, 3);
        assert_eq!(report.snapshot.entries.len(), 5);

        std::fs::write(
            directory
                .path()
                .join(format!("blobs/sha256/{layer_digest}")),
            b"tampered-data",
        )
        .unwrap();
        assert!(scanner.scan(11).is_err());
    }

    #[test]
    fn agent_pins_identity_and_requires_explicit_baseline_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let layout = directory.path().join("layout");
        let state = directory.path().join("state");
        create_layout(&layout);

        let agent = ContainerAgent::initialize(&state, "release-image").unwrap();
        let baseline = agent
            .create_baseline(&layout, OciScanLimits::default(), false)
            .unwrap();
        let (_, verification) = agent
            .verify_layout(&layout, OciScanLimits::default())
            .unwrap();
        assert!(verification.is_match());
        assert_eq!(baseline.snapshot.scope_id, "release-image");
        assert!(
            agent
                .create_baseline(&layout, OciScanLimits::default(), false)
                .is_err()
        );
        agent
            .create_baseline(&layout, OciScanLimits::default(), true)
            .unwrap();

        let baseline_path = state.join(BASELINE_FILE);
        let mut encoded = std::fs::read(&baseline_path).unwrap();
        let midpoint = encoded.len() / 2;
        encoded[midpoint] ^= 1;
        std::fs::write(baseline_path, encoded).unwrap();
        assert!(agent.load_baseline().is_err());
    }

    #[test]
    fn agent_state_cannot_be_nested_in_the_monitored_layout() {
        let directory = tempfile::tempdir().unwrap();
        create_layout(directory.path());
        let state = directory.path().join("shield-state");
        let agent = ContainerAgent::initialize(&state, "nested-state").unwrap();
        assert!(
            agent
                .create_baseline(directory.path(), OciScanLimits::default(), false)
                .is_err()
        );
    }

    #[test]
    fn rejects_descriptor_rebinding_and_counts_duplicate_queue_entries() {
        let directory = tempfile::tempdir().unwrap();
        create_layout(directory.path());
        let index_path = directory.path().join("index.json");
        let mut index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
        let manifest = index["manifests"][0].clone();
        let mut rebound = manifest.clone();
        rebound["mediaType"] = json!("application/vnd.oci.image.config.v1+json");
        index["manifests"] = json!([rebound, manifest]);
        std::fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();

        let scanner = OciLayoutScanner::new(directory.path(), OciScanLimits::default()).unwrap();
        assert!(matches!(
            scanner.scan(12),
            Err(ContainerError::InvalidLayout(message))
                if message.contains("conflicting mediaType or size")
        ));

        let manifest = index["manifests"][1].clone();
        index["manifests"] = json!([manifest.clone(), manifest]);
        std::fs::write(index_path, serde_json::to_vec(&index).unwrap()).unwrap();
        let limits = OciScanLimits {
            max_descriptors: 1,
            ..OciScanLimits::default()
        };
        let scanner = OciLayoutScanner::new(directory.path(), limits).unwrap();
        assert!(matches!(scanner.scan(13), Err(ContainerError::Limit(_))));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_intermediate_oci_directory() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        create_layout(directory.path());
        std::fs::rename(
            directory.path().join("blobs"),
            directory.path().join("real-blobs"),
        )
        .unwrap();
        symlink("real-blobs", directory.path().join("blobs")).unwrap();
        let scanner = OciLayoutScanner::new(directory.path(), OciScanLimits::default()).unwrap();
        assert!(scanner.scan(14).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_agent_key_directory() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        ContainerAgent::initialize(&state, "symlinked-keys").unwrap();
        std::fs::rename(state.join(KEY_DIRECTORY), state.join("real-keys")).unwrap();
        symlink("real-keys", state.join(KEY_DIRECTORY)).unwrap();
        assert!(ContainerAgent::load(&state).is_err());
    }

    fn create_layout(root: &Path) -> String {
        std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        std::fs::write(
            root.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        let config = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
        let layer = b"layer-content".to_vec();
        let config_descriptor =
            write_blob(root, "application/vnd.oci.image.config.v1+json", &config);
        let layer_descriptor = write_blob(root, "application/vnd.oci.image.layer.v1.tar", &layer);
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": config_descriptor,
            "layers": [layer_descriptor]
        }))
        .unwrap();
        let manifest_descriptor = write_blob(root, OCI_MANIFEST, &manifest);
        std::fs::write(
            root.join("index.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "manifests": [manifest_descriptor]
            }))
            .unwrap(),
        )
        .unwrap();
        hex::encode(Sha256::digest(&layer))
    }

    fn write_blob(root: &Path, media_type: &str, bytes: &[u8]) -> serde_json::Value {
        let digest = hex::encode(Sha256::digest(bytes));
        std::fs::write(root.join(format!("blobs/sha256/{digest}")), bytes).unwrap();
        json!({
            "mediaType": media_type,
            "digest": format!("sha256:{digest}"),
            "size": bytes.len()
        })
    }
}

use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use bollard::Docker;
use bollard::models::EventMessage;
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder};
use fs2::FileExt;
use futures_util::StreamExt;
use minicbor::{Decode, Encode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{
    AuditEvent, AuditEventKind, FORMAT_VERSION, MlDsa65PublicKey, MlDsa65Signature,
    SignedAuditRecord, verify_audit_chain,
};

use super::{
    ContainerAgent, ContainerError, GuaranteeLevel, IntegrationMode, Result, now_unix_ms,
    read_regular, write_atomic,
};

mod admission;
mod containerd;
mod sidecar;

pub use admission::{AdmissionOutcome, check_admission, check_admission_file, serve_admission};
pub use containerd::monitor_containerd;
pub use sidecar::{SidecarEvidence, check_sidecar, serve_sidecar};

const POLICY_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Container Runtime Policy v1";
const POLICY_HASH_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-CONTAINER-RUNTIME-POLICY-v1\0";
const POLICY_MAX_BYTES: u64 = 1_048_576;
const AUDIT_MAX_BYTES: u64 = 134_217_728;
const AUDIT_MAX_RECORD_BYTES: usize = 1_048_576;
const DOCKER_POLICY_FILE: &str = "runtime.docker.policy.cbor";
const RUNTIME_AUDIT_FILE: &str = "runtime.audit.cborseq";
const RUNTIME_AUDIT_LOCK: &str = "runtime.audit.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Encode, Decode)]
#[serde(rename_all = "kebab-case")]
#[cbor(index_only)]
#[repr(u8)]
pub enum RuntimeKind {
    #[n(1)]
    Docker = 1,
    #[n(2)]
    Containerd = 2,
    #[n(3)]
    Sidecar = 3,
    #[n(4)]
    Admission = 4,
}

impl RuntimeKind {
    fn policy_file(self) -> &'static str {
        match self {
            Self::Docker => DOCKER_POLICY_FILE,
            Self::Containerd => "runtime.containerd.policy.cbor",
            Self::Sidecar => "runtime.sidecar.policy.cbor",
            Self::Admission => "runtime.admission.policy.cbor",
        }
    }

    fn audit_file(self) -> &'static str {
        match self {
            Self::Docker => RUNTIME_AUDIT_FILE,
            Self::Containerd => "runtime.containerd.audit.cborseq",
            Self::Sidecar => "runtime.sidecar.audit.cborseq",
            Self::Admission => "runtime.admission.audit.cborseq",
        }
    }

    fn audit_lock(self) -> &'static str {
        match self {
            Self::Docker => RUNTIME_AUDIT_LOCK,
            Self::Containerd => "runtime.containerd.audit.lock",
            Self::Sidecar => "runtime.sidecar.audit.lock",
            Self::Admission => "runtime.admission.audit.lock",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct RuntimePolicy {
    #[n(0)]
    version: u16,
    #[n(1)]
    scope_id: String,
    #[n(2)]
    runtime: RuntimeKind,
    #[n(3)]
    created_at_unix_ms: u64,
    #[n(4)]
    approved_image_digests: Vec<String>,
    #[n(5)]
    namespace: Option<String>,
}

impl RuntimePolicy {
    fn new(
        scope_id: String,
        runtime: RuntimeKind,
        created_at_unix_ms: u64,
        digests: &[String],
        namespace: Option<String>,
    ) -> Result<Self> {
        if digests.is_empty() || digests.len() > 10_000 {
            return Err(ContainerError::State(
                "runtime policy requires 1-10000 approved image digests".to_owned(),
            ));
        }
        let approved_image_digests = digests
            .iter()
            .map(|digest| normalize_image_digest(digest))
            .collect::<Result<BTreeSet<_>>>()?
            .into_iter()
            .collect();
        let policy = Self {
            version: FORMAT_VERSION,
            scope_id,
            runtime,
            created_at_unix_ms,
            approved_image_digests,
            namespace,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            return Err(ContainerError::State(format!(
                "unsupported runtime policy version {}",
                self.version
            )));
        }
        if self.scope_id.is_empty() || self.scope_id.len() > 128 {
            return Err(ContainerError::State(
                "runtime policy scope is invalid".to_owned(),
            ));
        }
        if self.approved_image_digests.is_empty() || self.approved_image_digests.len() > 10_000 {
            return Err(ContainerError::State(
                "runtime policy digest count is invalid".to_owned(),
            ));
        }
        let mut previous: Option<&str> = None;
        for digest in &self.approved_image_digests {
            if normalize_image_digest(digest)? != *digest
                || previous.is_some_and(|value| value >= digest.as_str())
            {
                return Err(ContainerError::State(
                    "runtime policy digests must be unique and canonical".to_owned(),
                ));
            }
            previous = Some(digest);
        }
        match (self.runtime, self.namespace.as_deref()) {
            (RuntimeKind::Docker, None) => {}
            (RuntimeKind::Containerd, Some(namespace)) => validate_namespace(namespace)?,
            (RuntimeKind::Sidecar, Some(binding)) => validate_sidecar_binding(binding)?,
            (RuntimeKind::Admission, Some(namespace)) => validate_namespace(namespace)?,
            _ => {
                return Err(ContainerError::State(
                    "runtime policy namespace binding is invalid".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ContainerError::State(error.to_string()))
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let policy = decoder
            .decode::<Self>()
            .map_err(|error| ContainerError::State(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(ContainerError::State(
                "trailing bytes after runtime policy".to_owned(),
            ));
        }
        policy.validate()?;
        Ok(policy)
    }

    pub fn runtime(&self) -> RuntimeKind {
        self.runtime
    }

    pub fn approved_image_digests(&self) -> &[String] {
        &self.approved_image_digests
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn binding(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn permits(&self, digest: &str) -> bool {
        self.approved_image_digests
            .binary_search_by(|approved| approved.as_str().cmp(digest))
            .is_ok()
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
struct SignedRuntimePolicy {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

impl SignedRuntimePolicy {
    fn sign(policy: &RuntimePolicy, agent: &ContainerAgent) -> Result<Self> {
        let payload = policy.to_cbor()?;
        let digest = policy_digest(&payload);
        let signature = agent
            .secret
            .sign_with_context(&digest, POLICY_SIGNATURE_CONTEXT)?;
        Ok(Self {
            payload,
            public_key: agent.public.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    fn verify(&self) -> Result<RuntimePolicy> {
        let public = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public.verify_with_context(
            &policy_digest(&self.payload),
            POLICY_SIGNATURE_CONTEXT,
            &signature,
        )?;
        RuntimePolicy::from_cbor(&self.payload)
    }

    fn public_key(&self) -> Result<MlDsa65PublicKey> {
        Ok(MlDsa65PublicKey::from_bytes(&self.public_key)?)
    }

    fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ContainerError::State(error.to_string()))
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let signed = decoder
            .decode::<Self>()
            .map_err(|error| ContainerError::State(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(ContainerError::State(
                "trailing bytes after signed runtime policy".to_owned(),
            ));
        }
        Ok(signed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDecision {
    pub runtime: RuntimeKind,
    pub integration_mode: IntegrationMode,
    pub guarantee_level: GuaranteeLevel,
    pub timestamp_unix_ms: u64,
    pub action: String,
    pub object_id: String,
    pub image_digest: Option<String>,
    pub approved: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeObservation {
    runtime: RuntimeKind,
    timestamp_unix_ms: u64,
    action: String,
    object_id: String,
    image_digest: Option<String>,
}

impl RuntimeObservation {
    fn evaluate(
        self,
        policy: &RuntimePolicy,
        integration_mode: IntegrationMode,
    ) -> RuntimeDecision {
        let (approved, reason) = match self.image_digest.as_deref() {
            Some(digest) if policy.permits(digest) => (
                true,
                "immutable image digest is approved by signed policy".to_owned(),
            ),
            Some(_) => (false, "immutable image digest is not approved".to_owned()),
            None => (
                false,
                "runtime did not provide a canonical immutable image digest".to_owned(),
            ),
        };
        RuntimeDecision {
            runtime: self.runtime,
            integration_mode,
            guarantee_level: integration_mode.guarantee(),
            timestamp_unix_ms: self.timestamp_unix_ms,
            action: self.action,
            object_id: self.object_id,
            image_digest: self.image_digest,
            approved,
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorSummary {
    pub observations: usize,
    pub violations: usize,
}

impl ContainerAgent {
    pub fn create_runtime_policy(
        &self,
        runtime: RuntimeKind,
        image_digests: &[String],
        replace: bool,
    ) -> Result<RuntimePolicy> {
        let path = self.state_dir.join(runtime.policy_file());
        if path.exists() {
            self.load_runtime_policy(runtime)?;
            if !replace {
                return Err(ContainerError::State(
                    "runtime policy exists; pass --replace to approve replacement".to_owned(),
                ));
            }
        }
        let policy = RuntimePolicy::new(
            self.scope_id.clone(),
            runtime,
            now_unix_ms()?,
            image_digests,
            None,
        )?;
        let signed = SignedRuntimePolicy::sign(&policy, self)?;
        write_atomic(&path, &signed.to_cbor()?, replace)?;
        Ok(policy)
    }

    pub fn create_containerd_runtime_policy(
        &self,
        namespace: &str,
        image_digests: &[String],
        replace: bool,
    ) -> Result<RuntimePolicy> {
        validate_namespace(namespace)?;
        let runtime = RuntimeKind::Containerd;
        let path = self.state_dir.join(runtime.policy_file());
        if path.exists() {
            self.load_runtime_policy(runtime)?;
            if !replace {
                return Err(ContainerError::State(
                    "runtime policy exists; pass --replace to approve replacement".to_owned(),
                ));
            }
        }
        let policy = RuntimePolicy::new(
            self.scope_id.clone(),
            runtime,
            now_unix_ms()?,
            image_digests,
            Some(namespace.to_owned()),
        )?;
        let signed = SignedRuntimePolicy::sign(&policy, self)?;
        write_atomic(&path, &signed.to_cbor()?, replace)?;
        Ok(policy)
    }

    pub fn create_sidecar_runtime_policy(
        &self,
        binding: &str,
        image_digests: &[String],
        replace: bool,
    ) -> Result<RuntimePolicy> {
        validate_sidecar_binding(binding)?;
        let runtime = RuntimeKind::Sidecar;
        let path = self.state_dir.join(runtime.policy_file());
        if path.exists() {
            self.load_runtime_policy(runtime)?;
            if !replace {
                return Err(ContainerError::State(
                    "runtime policy exists; pass --replace to approve replacement".to_owned(),
                ));
            }
        }
        let policy = RuntimePolicy::new(
            self.scope_id.clone(),
            runtime,
            now_unix_ms()?,
            image_digests,
            Some(binding.to_owned()),
        )?;
        let signed = SignedRuntimePolicy::sign(&policy, self)?;
        write_atomic(&path, &signed.to_cbor()?, replace)?;
        Ok(policy)
    }

    pub fn create_admission_runtime_policy(
        &self,
        namespace: &str,
        image_digests: &[String],
        replace: bool,
    ) -> Result<RuntimePolicy> {
        validate_namespace(namespace)?;
        let runtime = RuntimeKind::Admission;
        let path = self.state_dir.join(runtime.policy_file());
        if path.exists() {
            self.load_runtime_policy(runtime)?;
            if !replace {
                return Err(ContainerError::State(
                    "runtime policy exists; pass --replace to approve replacement".to_owned(),
                ));
            }
        }
        let policy = RuntimePolicy::new(
            self.scope_id.clone(),
            runtime,
            now_unix_ms()?,
            image_digests,
            Some(namespace.to_owned()),
        )?;
        let signed = SignedRuntimePolicy::sign(&policy, self)?;
        write_atomic(&path, &signed.to_cbor()?, replace)?;
        Ok(policy)
    }

    pub fn load_runtime_policy(&self, runtime: RuntimeKind) -> Result<RuntimePolicy> {
        let signed = SignedRuntimePolicy::from_cbor(&read_regular(
            &self.state_dir.join(runtime.policy_file()),
            POLICY_MAX_BYTES,
        )?)?;
        if signed.public_key()?.key_id() != self.public.key_id() {
            return Err(ContainerError::State(
                "runtime policy signer does not match agent identity".to_owned(),
            ));
        }
        let policy = signed.verify()?;
        if policy.scope_id != self.scope_id || policy.runtime != runtime {
            return Err(ContainerError::State(
                "runtime policy scope or runtime does not match agent".to_owned(),
            ));
        }
        Ok(policy)
    }

    pub fn verify_runtime_audit(&self) -> Result<Vec<AuditEvent>> {
        self.verify_runtime_audit_for(RuntimeKind::Docker)
    }

    pub fn verify_runtime_audit_for(&self, runtime: RuntimeKind) -> Result<Vec<AuditEvent>> {
        let path = self.state_dir.join(runtime.audit_file());
        if !path.exists() {
            return Ok(Vec::new());
        }
        let records = read_audit_records(&path)?;
        let events = verify_audit_chain(&records)?;
        for record in &records {
            if record.public_key()?.key_id() != self.public.key_id() {
                return Err(ContainerError::State(
                    "runtime audit signer does not match agent identity".to_owned(),
                ));
            }
        }
        if events.iter().any(|event| event.scope_id != self.scope_id) {
            return Err(ContainerError::State(
                "runtime audit contains a foreign scope".to_owned(),
            ));
        }
        Ok(events)
    }
}

pub async fn monitor_docker<F>(
    agent: &ContainerAgent,
    max_observations: Option<usize>,
    mut report: F,
) -> Result<MonitorSummary>
where
    F: FnMut(&RuntimeDecision),
{
    if max_observations == Some(0) {
        return Err(ContainerError::State(
            "max observations must be greater than zero".to_owned(),
        ));
    }
    let policy = agent.load_runtime_policy(RuntimeKind::Docker)?;
    let mut audit = RuntimeAuditWriter::open(agent, RuntimeKind::Docker)?;
    let docker = match Docker::connect_with_local_defaults() {
        Ok(docker) => docker,
        Err(error) => {
            audit.append_status(
                AuditEventKind::MonitoringFailed,
                "Docker connection failed closed",
            )?;
            return Err(runtime_error("Docker connection", error));
        }
    };
    if let Err(error) = docker.ping().await {
        audit.append_status(
            AuditEventKind::MonitoringFailed,
            "Docker ping failed closed",
        )?;
        return Err(runtime_error("Docker ping", error));
    }
    audit.append_status(
        AuditEventKind::AgentStarted,
        "docker host runtime monitor started",
    )?;

    let since = now_unix_ms()? / 1000;
    let mut summary = MonitorSummary {
        observations: 0,
        violations: 0,
    };
    let list_options = ListContainersOptionsBuilder::default().all(false).build();
    let containers = match docker.list_containers(Some(list_options)).await {
        Ok(containers) => containers,
        Err(error) => {
            audit.append_status(
                AuditEventKind::MonitoringFailed,
                "Docker inventory failed closed",
            )?;
            return Err(runtime_error("Docker inventory", error));
        }
    };
    for container in containers {
        let object_id = bounded_identifier(container.id.as_deref(), "container id")?;
        let image_digest = container
            .image_id
            .as_deref()
            .and_then(|value| normalize_image_digest(value).ok());
        let decision = RuntimeObservation {
            runtime: RuntimeKind::Docker,
            timestamp_unix_ms: now_unix_ms()?,
            action: "inventory".to_owned(),
            object_id,
            image_digest,
        }
        .evaluate(&policy, IntegrationMode::HostAgent);
        process_decision(&mut audit, &decision, &mut summary, &mut report)?;
        if max_observations == Some(summary.observations) {
            audit.append_status(AuditEventKind::AgentStopped, "observation limit reached")?;
            return Ok(summary);
        }
    }

    let since = since.to_string();
    let mut filters: HashMap<&str, Vec<&str>> = HashMap::new();
    filters.insert("type", vec!["container"]);
    filters.insert("event", vec!["create", "start"]);
    let options = EventsOptionsBuilder::default()
        .since(&since)
        .filters(&filters)
        .build();
    let mut events = Box::pin(docker.events(Some(options)));
    while let Some(event) = events.next().await {
        let event = match event {
            Ok(event) => event,
            Err(error) => {
                audit.append_status(
                    AuditEventKind::MonitoringFailed,
                    "Docker event stream failed closed",
                )?;
                return Err(runtime_error("Docker event stream", error));
            }
        };
        let observation = match docker_observation(&docker, event).await {
            Ok(observation) => observation,
            Err(error) => {
                audit.append_status(
                    AuditEventKind::MonitoringFailed,
                    "malformed Docker event failed closed",
                )?;
                return Err(error);
            }
        };
        let decision = observation.evaluate(&policy, IntegrationMode::HostAgent);
        process_decision(&mut audit, &decision, &mut summary, &mut report)?;
        if max_observations == Some(summary.observations) {
            audit.append_status(AuditEventKind::AgentStopped, "observation limit reached")?;
            return Ok(summary);
        }
    }
    audit.append_status(
        AuditEventKind::MonitoringFailed,
        "Docker event stream ended unexpectedly",
    )?;
    Err(ContainerError::State(
        "Docker event stream ended unexpectedly".to_owned(),
    ))
}

async fn docker_observation(docker: &Docker, event: EventMessage) -> Result<RuntimeObservation> {
    let timestamp_unix_ms = docker_timestamp_ms(&event)?;
    let actor = event
        .actor
        .ok_or_else(|| ContainerError::State("Docker event is missing its actor".to_owned()))?;
    let object_id = bounded_identifier(actor.id.as_deref(), "container id")?;
    let action = bounded_action(event.action.as_deref())?;
    let image_digest = match docker.inspect_container(&object_id, None).await {
        Ok(container) => container
            .image
            .as_deref()
            .and_then(|value| normalize_image_digest(value).ok()),
        Err(_) => None,
    };
    Ok(RuntimeObservation {
        runtime: RuntimeKind::Docker,
        timestamp_unix_ms,
        action,
        object_id,
        image_digest,
    })
}

fn process_decision<F>(
    audit: &mut RuntimeAuditWriter,
    decision: &RuntimeDecision,
    summary: &mut MonitorSummary,
    report: &mut F,
) -> Result<()>
where
    F: FnMut(&RuntimeDecision),
{
    audit.append_decision(decision)?;
    summary.observations = summary
        .observations
        .checked_add(1)
        .ok_or_else(|| ContainerError::State("runtime observation count overflow".to_owned()))?;
    if !decision.approved {
        summary.violations = summary
            .violations
            .checked_add(1)
            .ok_or_else(|| ContainerError::State("runtime violation count overflow".to_owned()))?;
    }
    report(decision);
    Ok(())
}

struct RuntimeAuditWriter {
    file: File,
    _lock: File,
    scope_id: String,
    secret: vollcrypt_shield_core::MlDsa65SecretKey,
    next_sequence: u64,
    previous_hash: [u8; 32],
}

impl RuntimeAuditWriter {
    fn open(agent: &ContainerAgent, runtime: RuntimeKind) -> Result<Self> {
        let lock_path = agent.state_dir.join(runtime.audit_lock());
        let lock = open_private_file(&lock_path, true)?;
        lock.try_lock_exclusive().map_err(|error| {
            ContainerError::State(format!(
                "another runtime monitor holds {}: {error}",
                lock_path.display()
            ))
        })?;
        let path = agent.state_dir.join(runtime.audit_file());
        let records = if path.exists() {
            read_audit_records(&path)?
        } else {
            Vec::new()
        };
        let events = verify_audit_chain(&records)?;
        for record in &records {
            if record.public_key()?.key_id() != agent.public.key_id() {
                return Err(ContainerError::State(
                    "runtime audit signer does not match agent identity".to_owned(),
                ));
            }
        }
        if events.iter().any(|event| event.scope_id != agent.scope_id) {
            return Err(ContainerError::State(
                "runtime audit contains a foreign scope".to_owned(),
            ));
        }
        let previous_hash = records
            .last()
            .map_or([0; 32], SignedAuditRecord::event_hash);
        let next_sequence = u64::try_from(records.len())
            .map_err(|_| ContainerError::State("runtime audit is too long".to_owned()))?;
        let mut file = open_private_file(&path, true)?;
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file,
            _lock: lock,
            scope_id: agent.scope_id.clone(),
            secret: agent.secret.clone(),
            next_sequence,
            previous_hash,
        })
    }

    fn append_status(&mut self, kind: AuditEventKind, detail: &str) -> Result<()> {
        self.append(kind, None, detail)
    }

    fn append_decision(&mut self, decision: &RuntimeDecision) -> Result<()> {
        let detail = serde_json::to_string(decision)
            .map_err(|error| ContainerError::State(error.to_string()))?;
        let kind = if decision.approved {
            AuditEventKind::VerificationPassed
        } else {
            AuditEventKind::VerificationFailed
        };
        self.append(kind, Some(decision.object_id.clone()), &detail)
    }

    fn append(&mut self, kind: AuditEventKind, path: Option<String>, detail: &str) -> Result<()> {
        if detail.len() > 16_384 {
            return Err(ContainerError::Limit(
                "runtime audit detail exceeds 16384 bytes".to_owned(),
            ));
        }
        let event = AuditEvent::new(
            self.next_sequence,
            now_unix_ms()?,
            self.scope_id.clone(),
            kind,
            path,
            detail,
            self.previous_hash,
        );
        let record = SignedAuditRecord::sign(&event, &self.secret)?;
        let encoded = record.to_cbor()?;
        if encoded.len() > AUDIT_MAX_RECORD_BYTES {
            return Err(ContainerError::Limit(
                "runtime audit record exceeds framing limit".to_owned(),
            ));
        }
        let length = u32::try_from(encoded.len())
            .map_err(|_| ContainerError::Limit("runtime audit record is too large".to_owned()))?;
        self.file.write_all(&length.to_be_bytes())?;
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.previous_hash = record.event_hash();
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| ContainerError::State("runtime audit sequence overflow".to_owned()))?;
        Ok(())
    }
}

fn read_audit_records(path: &Path) -> Result<Vec<SignedAuditRecord>> {
    let bytes = read_regular(path, AUDIT_MAX_BYTES)?;
    let mut cursor = 0_usize;
    let mut records = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < 4 {
            return Err(ContainerError::State(
                "truncated runtime audit length".to_owned(),
            ));
        }
        let length = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| ContainerError::State("invalid runtime audit length".to_owned()))?,
        ) as usize;
        cursor += 4;
        if length == 0 || length > AUDIT_MAX_RECORD_BYTES || bytes.len() - cursor < length {
            return Err(ContainerError::State(
                "invalid or truncated runtime audit record".to_owned(),
            ));
        }
        records.push(SignedAuditRecord::from_cbor(
            &bytes[cursor..cursor + length],
        )?);
        cursor += length;
    }
    Ok(records)
}

fn open_private_file(path: &Path, create: bool) -> Result<File> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ContainerError::State(format!(
                "runtime state entry is not a regular non-symlink file: {}",
                path.display()
            )));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn normalize_image_digest(value: &str) -> Result<String> {
    let hex = value.strip_prefix("sha256:").ok_or_else(|| {
        ContainerError::State("image identity must be an immutable sha256 digest".to_owned())
    })?;
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hex.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(ContainerError::State(
            "image digest must be canonical lowercase sha256 hex".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn bounded_identifier(value: Option<&str>, label: &str) -> Result<String> {
    let value = value.ok_or_else(|| ContainerError::State(format!("missing {label}")))?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ContainerError::State(format!("invalid {label}")));
    }
    Ok(value.to_owned())
}

fn bounded_action(value: Option<&str>) -> Result<String> {
    let value = value.ok_or_else(|| ContainerError::State("missing Docker action".to_owned()))?;
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ContainerError::State("invalid Docker action".to_owned()));
    }
    Ok(value.to_owned())
}

fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty()
        || namespace.len() > 128
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ContainerError::State(
            "containerd namespace must be 1-128 ASCII identifier characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sidecar_binding(binding: &str) -> Result<()> {
    let Some((namespace, container)) = binding.split_once('/') else {
        return Err(ContainerError::State(
            "sidecar binding must use namespace/container format".to_owned(),
        ));
    };
    if binding.len() > 257 || container.contains('/') {
        return Err(ContainerError::State(
            "sidecar binding must contain one bounded namespace/container pair".to_owned(),
        ));
    }
    validate_namespace(namespace)?;
    validate_namespace(container)
}

fn docker_timestamp_ms(event: &EventMessage) -> Result<u64> {
    if let Some(nanoseconds) = event.time_nano {
        if nanoseconds < 0 {
            return Err(ContainerError::State(
                "Docker event timestamp is negative".to_owned(),
            ));
        }
        return u64::try_from(nanoseconds / 1_000_000)
            .map_err(|_| ContainerError::State("Docker timestamp overflow".to_owned()));
    }
    let seconds = event
        .time
        .ok_or_else(|| ContainerError::State("Docker event has no timestamp".to_owned()))?;
    if seconds < 0 {
        return Err(ContainerError::State(
            "Docker event timestamp is negative".to_owned(),
        ));
    }
    u64::try_from(seconds)
        .ok()
        .and_then(|value| value.checked_mul(1000))
        .ok_or_else(|| ContainerError::State("Docker timestamp overflow".to_owned()))
}

fn policy_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_HASH_DOMAIN);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn runtime_error(context: &str, error: impl std::fmt::Display) -> ContainerError {
    ContainerError::State(format!("{context} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Encode)]
    #[cbor(array)]
    struct LegacyRuntimePolicy {
        #[n(0)]
        version: u16,
        #[n(1)]
        scope_id: String,
        #[n(2)]
        runtime: RuntimeKind,
        #[n(3)]
        created_at_unix_ms: u64,
        #[n(4)]
        approved_image_digests: Vec<String>,
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn signed_runtime_policy_is_canonical_and_rejects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let agent = ContainerAgent::initialize(&state, "runtime-policy").unwrap();
        let second = digest('b');
        let first = digest('a');
        let policy = agent
            .create_runtime_policy(
                RuntimeKind::Docker,
                &[second.clone(), first.clone(), second],
                false,
            )
            .unwrap();
        assert_eq!(policy.approved_image_digests(), &[first, digest('b')]);
        assert!(
            agent
                .create_runtime_policy(RuntimeKind::Docker, &[digest('c')], false)
                .is_err()
        );

        let path = state.join(DOCKER_POLICY_FILE);
        let mut encoded = std::fs::read(&path).unwrap();
        let midpoint = encoded.len() / 2;
        encoded[midpoint] ^= 1;
        std::fs::write(path, encoded).unwrap();
        assert!(agent.load_runtime_policy(RuntimeKind::Docker).is_err());
    }

    #[test]
    fn runtime_policy_keeps_legacy_docker_payload_compatibility() {
        let approved = digest('a');
        let legacy = LegacyRuntimePolicy {
            version: FORMAT_VERSION,
            scope_id: "legacy".to_owned(),
            runtime: RuntimeKind::Docker,
            created_at_unix_ms: 1,
            approved_image_digests: vec![approved.clone()],
        };
        let encoded = minicbor::to_vec(legacy).unwrap();
        let decoded = RuntimePolicy::from_cbor(&encoded).unwrap();
        assert_eq!(decoded.namespace(), None);
        assert_eq!(decoded.approved_image_digests(), &[approved]);
    }

    #[test]
    fn containerd_policy_binds_namespace_and_rejects_filter_injection() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let agent = ContainerAgent::initialize(&state, "containerd-policy").unwrap();
        let policy = agent
            .create_containerd_runtime_policy("k8s.io", &[digest('a')], false)
            .unwrap();
        assert_eq!(policy.namespace(), Some("k8s.io"));
        assert_eq!(policy.runtime(), RuntimeKind::Containerd);
        assert!(
            agent
                .create_containerd_runtime_policy(
                    "k8s.io,topic==/tasks/start",
                    &[digest('a')],
                    true,
                )
                .is_err()
        );
    }

    #[test]
    fn immutable_digest_policy_denies_tags_unknown_and_unapproved_images() {
        let approved = digest('a');
        let policy = RuntimePolicy::new(
            "scope".to_owned(),
            RuntimeKind::Docker,
            1,
            std::slice::from_ref(&approved),
            None,
        )
        .unwrap();
        let observation = |image_digest| RuntimeObservation {
            runtime: RuntimeKind::Docker,
            timestamp_unix_ms: 1,
            action: "start".to_owned(),
            object_id: "container".to_owned(),
            image_digest,
        };
        assert!(
            observation(Some(approved))
                .evaluate(&policy, IntegrationMode::HostAgent)
                .approved
        );
        assert!(
            !observation(Some(digest('b')))
                .evaluate(&policy, IntegrationMode::HostAgent)
                .approved
        );
        assert!(
            !observation(None)
                .evaluate(&policy, IntegrationMode::HostAgent)
                .approved
        );
        assert!(normalize_image_digest("alpine:latest").is_err());
        assert!(normalize_image_digest(&format!("sha256:{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn runtime_audit_is_signed_chained_and_detects_truncation() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let agent = ContainerAgent::initialize(&state, "runtime-audit").unwrap();
        {
            let mut audit = RuntimeAuditWriter::open(&agent, RuntimeKind::Docker).unwrap();
            assert!(RuntimeAuditWriter::open(&agent, RuntimeKind::Docker).is_err());
            audit
                .append_status(AuditEventKind::AgentStarted, "started")
                .unwrap();
            audit
                .append_decision(&RuntimeDecision {
                    runtime: RuntimeKind::Docker,
                    integration_mode: IntegrationMode::HostAgent,
                    guarantee_level: GuaranteeLevel::Strong,
                    timestamp_unix_ms: 2,
                    action: "start".to_owned(),
                    object_id: "container".to_owned(),
                    image_digest: Some(digest('a')),
                    approved: false,
                    reason: "not approved".to_owned(),
                })
                .unwrap();
        }
        let events = agent.verify_runtime_audit().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].kind, AuditEventKind::VerificationFailed);

        let path = state.join(RUNTIME_AUDIT_FILE);
        let mut encoded = std::fs::read(&path).unwrap();
        encoded.pop();
        std::fs::write(path, encoded).unwrap();
        assert!(agent.verify_runtime_audit().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_audit_rejects_a_symlinked_lock_file() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let agent = ContainerAgent::initialize(&state, "runtime-lock").unwrap();
        let target = state.join("target");
        std::fs::write(&target, b"do-not-touch").unwrap();
        let lock = state.join(RUNTIME_AUDIT_LOCK);
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        assert!(RuntimeAuditWriter::open(&agent, RuntimeKind::Docker).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"do-not-touch");
    }

    #[test]
    fn rejects_unbounded_runtime_fields_and_invalid_limits() {
        assert!(bounded_identifier(Some(&"x".repeat(129)), "id").is_err());
        assert!(bounded_action(Some(&"x".repeat(65))).is_err());
        assert!(bounded_action(Some("start\nforged")).is_err());
        assert!(RuntimePolicy::new("scope".to_owned(), RuntimeKind::Docker, 1, &[], None).is_err());
        assert!(validate_namespace("k8s.io").is_ok());
        assert!(validate_namespace("k8s.io,topic==/tasks/start").is_err());
    }
}

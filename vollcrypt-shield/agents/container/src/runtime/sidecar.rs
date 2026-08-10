use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{MissedTickBehavior, interval, timeout};

use super::{
    ContainerAgent, ContainerError, GuaranteeLevel, IntegrationMode, MonitorSummary, Result,
    RuntimeAuditWriter, RuntimeDecision, RuntimeKind, bounded_identifier, normalize_image_digest,
    process_decision, read_regular, validate_namespace,
};

const SIDECAR_EVIDENCE_MAX_BYTES: u64 = 16_384;
const SIDECAR_HTTP_MAX_REQUEST_BYTES: usize = 2_048;
const SIDECAR_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const SIDECAR_MAX_CONNECTIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SidecarEvidence {
    pub version: u16,
    pub pod_uid: String,
    pub namespace: String,
    pub container_name: String,
    pub image_digest: String,
}

impl SidecarEvidence {
    pub fn from_file(path: &Path) -> Result<Self> {
        let encoded = read_regular(path, SIDECAR_EVIDENCE_MAX_BYTES)?;
        let evidence: Self = serde_json::from_slice(&encoded)
            .map_err(|error| ContainerError::State(format!("invalid sidecar evidence: {error}")))?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn from_environment() -> Result<Self> {
        let value = |name: &str| {
            std::env::var(name)
                .map_err(|_| ContainerError::State(format!("missing sidecar environment {name}")))
        };
        let evidence = Self {
            version: 1,
            pod_uid: value("SHIELD_POD_UID")?,
            namespace: value("SHIELD_NAMESPACE")?,
            container_name: value("SHIELD_CONTAINER_NAME")?,
            image_digest: value("SHIELD_IMAGE_DIGEST")?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn binding(&self) -> String {
        format!("{}/{}", self.namespace, self.container_name)
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(ContainerError::State(
                "unsupported sidecar evidence version".to_owned(),
            ));
        }
        bounded_identifier(Some(&self.pod_uid), "pod uid")?;
        validate_namespace(&self.namespace)?;
        validate_namespace(&self.container_name)?;
        normalize_image_digest(&self.image_digest)?;
        Ok(())
    }
}

pub fn check_sidecar(
    agent: &ContainerAgent,
    evidence_file: Option<&Path>,
) -> Result<RuntimeDecision> {
    let policy = agent.load_runtime_policy(RuntimeKind::Sidecar)?;
    let mut audit = RuntimeAuditWriter::open(agent, RuntimeKind::Sidecar)?;
    audit.append_status(
        vollcrypt_shield_core::AuditEventKind::AgentStarted,
        "constrained sidecar evidence check started",
    )?;
    let decision = evaluate_evidence(&policy, load_evidence(evidence_file));
    let mut summary = MonitorSummary {
        observations: 0,
        violations: 0,
    };
    process_decision(&mut audit, &decision, &mut summary, &mut |_| {})?;
    audit.append_status(
        vollcrypt_shield_core::AuditEventKind::AgentStopped,
        "constrained sidecar evidence check completed",
    )?;
    Ok(decision)
}

pub async fn serve_sidecar(
    agent: &ContainerAgent,
    evidence_file: Option<&Path>,
    listen: SocketAddr,
    poll_interval: Duration,
) -> Result<()> {
    if !(1..=3_600).contains(&poll_interval.as_secs()) {
        return Err(ContainerError::State(
            "sidecar poll interval must be 1-3600 seconds".to_owned(),
        ));
    }
    let policy = agent.load_runtime_policy(RuntimeKind::Sidecar)?;
    let mut audit = RuntimeAuditWriter::open(agent, RuntimeKind::Sidecar)?;
    let listener = TcpListener::bind(listen).await.map_err(|error| {
        ContainerError::State(format!("sidecar readiness listener failed: {error}"))
    })?;
    let ready = Arc::new(AtomicBool::new(false));
    let connections = Arc::new(Semaphore::new(SIDECAR_MAX_CONNECTIONS));
    let mut ticker = interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous: Option<RuntimeDecision> = None;

    audit.append_status(
        vollcrypt_shield_core::AuditEventKind::AgentStarted,
        "constrained sidecar monitor started",
    )?;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let decision = evaluate_evidence(&policy, load_evidence(evidence_file));
                ready.store(decision.approved, Ordering::Release);
                if previous
                    .as_ref()
                    .is_none_or(|last| !same_outcome(last, &decision))
                {
                    let mut summary = MonitorSummary {
                        observations: 0,
                        violations: 0,
                    };
                    process_decision(&mut audit, &decision, &mut summary, &mut |_| {})?;
                    previous = Some(decision);
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|error| {
                    ContainerError::State(format!("sidecar readiness accept failed: {error}"))
                })?;
                if let Ok(permit) = Arc::clone(&connections).try_acquire_owned() {
                    let ready = Arc::clone(&ready);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = handle_readiness(stream, ready).await;
                    });
                }
            }
        }
    }
}

fn same_outcome(left: &RuntimeDecision, right: &RuntimeDecision) -> bool {
    left.runtime == right.runtime
        && left.integration_mode == right.integration_mode
        && left.guarantee_level == right.guarantee_level
        && left.action == right.action
        && left.object_id == right.object_id
        && left.image_digest == right.image_digest
        && left.approved == right.approved
        && left.reason == right.reason
}

fn load_evidence(evidence_file: Option<&Path>) -> Result<SidecarEvidence> {
    match evidence_file {
        Some(path) => SidecarEvidence::from_file(path),
        None => SidecarEvidence::from_environment(),
    }
}

fn evaluate_evidence(
    policy: &super::RuntimePolicy,
    evidence: Result<SidecarEvidence>,
) -> RuntimeDecision {
    let timestamp_unix_ms = super::now_unix_ms().unwrap_or(0);
    let Ok(evidence) = evidence else {
        return RuntimeDecision {
            runtime: RuntimeKind::Sidecar,
            integration_mode: IntegrationMode::Sidecar,
            guarantee_level: GuaranteeLevel::Constrained,
            timestamp_unix_ms,
            action: "attest".to_owned(),
            object_id: "sidecar-evidence".to_owned(),
            image_digest: None,
            approved: false,
            reason: "sidecar-declared evidence is missing or invalid".to_owned(),
        };
    };
    let binding_matches = policy.binding() == Some(evidence.binding().as_str());
    let digest_approved = policy.permits(&evidence.image_digest);
    let (approved, reason) = if !binding_matches {
        (
            false,
            "sidecar namespace/container binding does not match signed policy".to_owned(),
        )
    } else if !digest_approved {
        (
            false,
            "sidecar-declared immutable image digest is not approved".to_owned(),
        )
    } else {
        (
            true,
            "sidecar-declared immutable image digest is approved by signed policy".to_owned(),
        )
    };
    RuntimeDecision {
        runtime: RuntimeKind::Sidecar,
        integration_mode: IntegrationMode::Sidecar,
        guarantee_level: GuaranteeLevel::Constrained,
        timestamp_unix_ms,
        action: "attest".to_owned(),
        object_id: evidence.pod_uid,
        image_digest: Some(evidence.image_digest),
        approved,
        reason,
    }
}

async fn handle_readiness(mut stream: TcpStream, ready: Arc<AtomicBool>) -> std::io::Result<()> {
    let mut request = [0_u8; SIDECAR_HTTP_MAX_REQUEST_BYTES];
    let read = timeout(SIDECAR_HTTP_TIMEOUT, stream.read(&mut request)).await;
    let bytes_read = match read {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    };
    let request = &request[..bytes_read];
    let response = readiness_response(request, ready.load(Ordering::Acquire));
    stream.write_all(response).await?;
    stream.shutdown().await
}

fn readiness_response(request: &[u8], ready: bool) -> &'static [u8] {
    if !(request.starts_with(b"GET /readyz HTTP/1.0\r\n")
        || request.starts_with(b"GET /readyz HTTP/1.1\r\n"))
    {
        return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    }
    if ready {
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 44\r\nConnection: close\r\n\r\n{\"status\":\"ready\",\"assurance\":\"constrained\"}"
    } else {
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 48\r\nConnection: close\r\n\r\n{\"status\":\"not-ready\",\"assurance\":\"constrained\"}"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn approved_evidence_is_constrained_and_audited() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let evidence_path = directory.path().join("evidence.json");
        let agent = ContainerAgent::initialize(&state, "sidecar-test").unwrap();
        agent
            .create_sidecar_runtime_policy("default/app", &[digest('a')], false)
            .unwrap();
        std::fs::write(
            &evidence_path,
            serde_json::to_vec(&SidecarEvidence {
                version: 1,
                pod_uid: "pod-123".to_owned(),
                namespace: "default".to_owned(),
                container_name: "app".to_owned(),
                image_digest: digest('a'),
            })
            .unwrap(),
        )
        .unwrap();

        let decision = check_sidecar(&agent, Some(&evidence_path)).unwrap();
        assert!(decision.approved);
        assert_eq!(decision.integration_mode, IntegrationMode::Sidecar);
        assert_eq!(decision.guarantee_level, GuaranteeLevel::Constrained);
        assert_eq!(
            agent
                .verify_runtime_audit_for(RuntimeKind::Sidecar)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn binding_mismatch_and_malformed_evidence_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let evidence_path = directory.path().join("evidence.json");
        let agent = ContainerAgent::initialize(&state, "sidecar-fail-closed").unwrap();
        agent
            .create_sidecar_runtime_policy("production/app", &[digest('a')], false)
            .unwrap();
        std::fs::write(
            &evidence_path,
            format!(
                "{{\"version\":1,\"podUid\":\"pod-1\",\"namespace\":\"default\",\"containerName\":\"app\",\"imageDigest\":\"{}\"}}",
                digest('a')
            ),
        )
        .unwrap();
        assert!(
            !check_sidecar(&agent, Some(&evidence_path))
                .unwrap()
                .approved
        );

        std::fs::write(&evidence_path, b"{\"version\":1}").unwrap();
        assert!(
            !check_sidecar(&agent, Some(&evidence_path))
                .unwrap()
                .approved
        );
    }

    #[test]
    fn readiness_endpoint_is_bounded_and_explicit() {
        assert!(
            readiness_response(b"GET /readyz HTTP/1.1\r\n\r\n", true).starts_with(b"HTTP/1.1 200")
        );
        assert!(
            readiness_response(b"GET /readyz HTTP/1.1\r\n\r\n", false).starts_with(b"HTTP/1.1 503")
        );
        assert!(
            readiness_response(b"GET /status HTTP/1.1\r\n\r\n", true).starts_with(b"HTTP/1.1 404")
        );
    }
}

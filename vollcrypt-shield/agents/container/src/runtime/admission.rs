use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Semaphore};

use super::{
    ContainerAgent, ContainerError, GuaranteeLevel, IntegrationMode, MonitorSummary, Result,
    RuntimeAuditWriter, RuntimeDecision, RuntimeKind, RuntimePolicy, bounded_identifier,
    normalize_image_digest, process_decision, read_regular, validate_namespace,
};

const ADMISSION_MAX_BODY_BYTES: usize = 1_048_576;
const ADMISSION_MAX_CONTAINERS: usize = 256;
const ADMISSION_MAX_IMAGE_BYTES: usize = 1_024;
const ADMISSION_MAX_CONNECTIONS: usize = 64;
const TLS_CERT_MAX_BYTES: u64 = 1_048_576;
const TLS_KEY_MAX_BYTES: u64 = 65_536;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionOutcome {
    pub allowed: bool,
    pub response: Value,
    pub decisions: Vec<RuntimeDecision>,
}

pub fn check_admission(agent: &ContainerAgent, review: &[u8]) -> Result<AdmissionOutcome> {
    let policy = agent.load_runtime_policy(RuntimeKind::Admission)?;
    let mut audit = RuntimeAuditWriter::open(agent, RuntimeKind::Admission)?;
    audit.append_status(
        vollcrypt_shield_core::AuditEventKind::AgentStarted,
        "Kubernetes admission check started",
    )?;
    let outcome = evaluate_review(&policy, review)?;
    audit_outcome(&mut audit, &outcome)?;
    audit.append_status(
        vollcrypt_shield_core::AuditEventKind::AgentStopped,
        "Kubernetes admission check completed",
    )?;
    Ok(outcome)
}

pub fn check_admission_file(
    agent: &ContainerAgent,
    review_file: &Path,
) -> Result<AdmissionOutcome> {
    let review = read_regular(review_file, ADMISSION_MAX_BODY_BYTES as u64)?;
    check_admission(agent, &review)
}

pub async fn serve_admission(
    agent: &ContainerAgent,
    listen: SocketAddr,
    tls_cert: &Path,
    tls_key: &Path,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = read_regular(tls_cert, TLS_CERT_MAX_BYTES)?;
    let private_key = read_regular(tls_key, TLS_KEY_MAX_BYTES)?;
    let tls = RustlsConfig::from_pem(certificate, private_key)
        .await
        .map_err(|error| {
            ContainerError::State(format!("invalid admission TLS identity: {error}"))
        })?;
    let policy = agent.load_runtime_policy(RuntimeKind::Admission)?;
    let mut audit = RuntimeAuditWriter::open(agent, RuntimeKind::Admission)?;
    audit.append_status(
        vollcrypt_shield_core::AuditEventKind::AgentStarted,
        "Kubernetes admission webhook started",
    )?;
    let state = AdmissionState {
        service: Arc::new(Mutex::new(AdmissionService { policy, audit })),
    };
    let permits = Arc::new(Semaphore::new(ADMISSION_MAX_CONNECTIONS));
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/validate", post(validate))
        .layer(DefaultBodyLimit::max(ADMISSION_MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(permits, concurrency_gate))
        .with_state(state);
    axum_server::bind_rustls(listen, tls)
        .serve(app.into_make_service())
        .await
        .map_err(|error| ContainerError::State(format!("admission HTTPS server failed: {error}")))
}

#[derive(Clone)]
struct AdmissionState {
    service: Arc<Mutex<AdmissionService>>,
}

struct AdmissionService {
    policy: RuntimePolicy,
    audit: RuntimeAuditWriter,
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn concurrency_gate(
    State(permits): State<Arc<Semaphore>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Ok(_permit) = permits.try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "admission capacity exhausted",
        )
            .into_response();
    };
    next.run(request).await
}

async fn validate(State(state): State<AdmissionState>, body: Bytes) -> Response {
    let mut service = state.service.lock().await;
    let outcome = match evaluate_review(&service.policy, &body) {
        Ok(outcome) => outcome,
        Err(_) => {
            let _ = service.audit.append_status(
                vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
                "malformed Kubernetes AdmissionReview failed closed",
            );
            return (StatusCode::BAD_REQUEST, "invalid AdmissionReview").into_response();
        }
    };
    if audit_outcome(&mut service.audit, &outcome).is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "admission audit unavailable",
        )
            .into_response();
    }
    (StatusCode::OK, Json(outcome.response)).into_response()
}

fn evaluate_review(policy: &RuntimePolicy, encoded: &[u8]) -> Result<AdmissionOutcome> {
    if encoded.is_empty() || encoded.len() > ADMISSION_MAX_BODY_BYTES {
        return Err(ContainerError::Limit(
            "AdmissionReview body exceeds its bounds".to_owned(),
        ));
    }
    let review: Value = serde_json::from_slice(encoded)
        .map_err(|error| ContainerError::State(format!("invalid AdmissionReview: {error}")))?;
    if string_at(&review, "apiVersion")? != "admission.k8s.io/v1"
        || string_at(&review, "kind")? != "AdmissionReview"
    {
        return Err(ContainerError::State(
            "unsupported AdmissionReview version or kind".to_owned(),
        ));
    }
    let request = review
        .get("request")
        .and_then(Value::as_object)
        .ok_or_else(|| ContainerError::State("AdmissionReview request is missing".to_owned()))?;
    let uid = bounded_identifier(
        request.get("uid").and_then(Value::as_str),
        "admission request uid",
    )?;
    let namespace = request
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| ContainerError::State("admission namespace is missing".to_owned()))?;
    validate_namespace(namespace)?;
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| ContainerError::State("admission operation is missing".to_owned()))?;
    let object = request
        .get("object")
        .and_then(Value::as_object)
        .ok_or_else(|| ContainerError::State("admission object is missing".to_owned()))?;
    if object.get("kind").and_then(Value::as_str) != Some("Pod")
        || object.get("apiVersion").and_then(Value::as_str) != Some("v1")
    {
        return Err(ContainerError::State(
            "admission object must be a v1 Pod".to_owned(),
        ));
    }
    let timestamp = super::now_unix_ms()?;
    let mut decisions = Vec::new();
    if !matches!(operation, "CREATE" | "UPDATE") {
        decisions.push(denied_decision(
            timestamp,
            &uid,
            "admission operation is not CREATE or UPDATE",
        ));
    } else if policy.namespace() != Some(namespace) {
        decisions.push(denied_decision(
            timestamp,
            &uid,
            "pod namespace does not match signed admission policy",
        ));
    } else {
        collect_container_decisions(object, policy, timestamp, &mut decisions)?;
    }
    if decisions.is_empty() {
        return Err(ContainerError::State(
            "Pod contains no container image evidence".to_owned(),
        ));
    }
    let allowed = decisions.iter().all(|decision| decision.approved);
    let response = if allowed {
        json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {"uid": uid, "allowed": true}
        })
    } else {
        json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": false,
                "status": {
                    "code": 403,
                    "reason": "Forbidden",
                    "message": "image evidence rejected by signed Vollcrypt Shield policy"
                }
            }
        })
    };
    Ok(AdmissionOutcome {
        allowed,
        response,
        decisions,
    })
}

fn collect_container_decisions(
    object: &serde_json::Map<String, Value>,
    policy: &RuntimePolicy,
    timestamp: u64,
    decisions: &mut Vec<RuntimeDecision>,
) -> Result<()> {
    let spec = object
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| ContainerError::State("Pod spec is missing".to_owned()))?;
    for field in ["containers", "initContainers", "ephemeralContainers"] {
        let Some(entries) = spec.get(field) else {
            continue;
        };
        let entries = entries
            .as_array()
            .ok_or_else(|| ContainerError::State(format!("Pod {field} must be an array")))?;
        for entry in entries {
            if decisions.len() >= ADMISSION_MAX_CONTAINERS {
                return Err(ContainerError::Limit(
                    "Pod container count exceeds admission limit".to_owned(),
                ));
            }
            let entry = entry.as_object().ok_or_else(|| {
                ContainerError::State(format!("Pod {field} entry must be an object"))
            })?;
            let name =
                bounded_identifier(entry.get("name").and_then(Value::as_str), "container name")?;
            let object_id = format!("{field}:{name}");
            let image = entry
                .get("image")
                .and_then(Value::as_str)
                .ok_or_else(|| ContainerError::State("container image is missing".to_owned()))?;
            let digest = pinned_image_digest(image).ok();
            let approved = digest.as_deref().is_some_and(|value| policy.permits(value));
            let reason = match digest.as_deref() {
                Some(_) if approved => "digest-pinned image is approved by signed admission policy",
                Some(_) => "digest-pinned image is not approved",
                None => "container image is not pinned to a canonical sha256 digest",
            };
            decisions.push(RuntimeDecision {
                runtime: RuntimeKind::Admission,
                integration_mode: IntegrationMode::AdmissionController,
                guarantee_level: GuaranteeLevel::BuildTimeOnly,
                timestamp_unix_ms: timestamp,
                action: "admit".to_owned(),
                object_id,
                image_digest: digest,
                approved,
                reason: reason.to_owned(),
            });
        }
    }
    Ok(())
}

fn pinned_image_digest(image: &str) -> Result<String> {
    if image.is_empty()
        || image.len() > ADMISSION_MAX_IMAGE_BYTES
        || image
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ContainerError::State(
            "invalid container image reference".to_owned(),
        ));
    }
    let (repository, digest) = image
        .rsplit_once('@')
        .ok_or_else(|| ContainerError::State("container image must be digest pinned".to_owned()))?;
    if repository.is_empty() || repository.contains('@') {
        return Err(ContainerError::State("invalid image repository".to_owned()));
    }
    normalize_image_digest(digest)
}

fn denied_decision(timestamp: u64, object_id: &str, reason: &str) -> RuntimeDecision {
    RuntimeDecision {
        runtime: RuntimeKind::Admission,
        integration_mode: IntegrationMode::AdmissionController,
        guarantee_level: GuaranteeLevel::BuildTimeOnly,
        timestamp_unix_ms: timestamp,
        action: "admit".to_owned(),
        object_id: object_id.to_owned(),
        image_digest: None,
        approved: false,
        reason: reason.to_owned(),
    }
}

fn audit_outcome(audit: &mut RuntimeAuditWriter, outcome: &AdmissionOutcome) -> Result<()> {
    let mut summary = MonitorSummary {
        observations: 0,
        violations: 0,
    };
    for decision in &outcome.decisions {
        process_decision(audit, decision, &mut summary, &mut |_| {})?;
    }
    Ok(())
}

fn string_at<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ContainerError::State(format!("AdmissionReview {key} is missing")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn review(namespace: &str, image: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "request-1",
                "namespace": namespace,
                "operation": "CREATE",
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "spec": {
                        "containers": [{"name": "app", "image": image}]
                    }
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn approves_only_digest_pinned_images_in_bound_namespace() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let agent = ContainerAgent::initialize(&state, "admission-test").unwrap();
        let approved = digest('a');
        agent
            .create_admission_runtime_policy("production", std::slice::from_ref(&approved), false)
            .unwrap();
        let image = format!("registry.example/app@{approved}");
        let outcome = check_admission(&agent, &review("production", &image)).unwrap();
        assert!(outcome.allowed);
        assert_eq!(
            outcome.decisions[0].guarantee_level,
            GuaranteeLevel::BuildTimeOnly
        );
    }

    #[test]
    fn tags_unknown_digests_and_foreign_namespaces_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let agent = ContainerAgent::initialize(&state, "admission-deny").unwrap();
        agent
            .create_admission_runtime_policy("production", &[digest('a')], false)
            .unwrap();
        assert!(
            !check_admission(&agent, &review("production", "app:latest"))
                .unwrap()
                .allowed
        );
        assert!(
            !check_admission(
                &agent,
                &review("production", &format!("app@{}", digest('b')))
            )
            .unwrap()
            .allowed
        );
        assert!(
            !check_admission(&agent, &review("staging", &format!("app@{}", digest('a'))))
                .unwrap()
                .allowed
        );
    }
}

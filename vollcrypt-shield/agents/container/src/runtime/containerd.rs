use std::path::Path;

use super::{ContainerAgent, ContainerError, MonitorSummary, Result, RuntimeDecision};
#[cfg(unix)]
use super::{
    RuntimeAuditWriter, RuntimeKind, RuntimeObservation, bounded_identifier,
    normalize_image_digest, process_decision, runtime_error,
};

#[cfg(unix)]
use containerd_client::Client;
#[cfg(unix)]
use containerd_client::events::{ContainerCreate, TaskStart};
#[cfg(unix)]
use containerd_client::services::v1::{
    GetContainerRequest, GetImageRequest, ListTasksRequest, SubscribeRequest,
};
#[cfg(unix)]
use containerd_client::tonic::Request;
#[cfg(unix)]
use containerd_client::types::Envelope;

pub async fn monitor_containerd<F>(
    agent: &ContainerAgent,
    socket: &Path,
    max_observations: Option<usize>,
    report: F,
) -> Result<MonitorSummary>
where
    F: FnMut(&RuntimeDecision),
{
    #[cfg(unix)]
    {
        monitor_unix(agent, socket, max_observations, report).await
    }
    #[cfg(not(unix))]
    {
        let _ = (agent, socket, max_observations, report);
        Err(ContainerError::State(
            "containerd host monitoring is currently supported on Unix only".to_owned(),
        ))
    }
}

#[cfg(unix)]
async fn monitor_unix<F>(
    agent: &ContainerAgent,
    socket: &Path,
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
    let policy = agent.load_runtime_policy(RuntimeKind::Containerd)?;
    let namespace = policy.namespace().ok_or_else(|| {
        ContainerError::State("containerd policy is missing its namespace".to_owned())
    })?;
    let mut audit = RuntimeAuditWriter::open(agent, RuntimeKind::Containerd)?;
    if let Err(error) = validate_containerd_socket(socket) {
        audit.append_status(
            vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
            "containerd socket trust validation failed closed",
        )?;
        return Err(error);
    }
    let client = match Client::from_path(socket).await {
        Ok(client) => client,
        Err(error) => {
            audit.append_status(
                vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
                "containerd connection failed closed",
            )?;
            return Err(runtime_error("containerd connection", error));
        }
    };

    let filters = vec![
        format!("namespace==\"{namespace}\",topic==\"/containers/create\""),
        format!("namespace==\"{namespace}\",topic==\"/tasks/start\""),
    ];
    let subscription = namespaced(SubscribeRequest { filters }, namespace)?;
    let mut stream = match client.events().subscribe(subscription).await {
        Ok(response) => response.into_inner(),
        Err(error) => {
            audit.append_status(
                vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
                "containerd event subscription failed closed",
            )?;
            return Err(runtime_error("containerd event subscription", error));
        }
    };
    audit.append_status(
        vollcrypt_shield_core::AuditEventKind::AgentStarted,
        "containerd host runtime monitor started",
    )?;

    let mut summary = MonitorSummary {
        observations: 0,
        violations: 0,
    };
    let request = namespaced(
        ListTasksRequest {
            filter: String::new(),
        },
        namespace,
    )?;
    let tasks = match client.tasks().list(request).await {
        Ok(response) => response.into_inner().tasks,
        Err(error) => {
            audit.append_status(
                vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
                "containerd task inventory failed closed",
            )?;
            return Err(runtime_error("containerd task inventory", error));
        }
    };
    let mut inventoried = std::collections::BTreeSet::new();
    for task in tasks {
        if !inventoried.insert(task.container_id.clone()) {
            continue;
        }
        let object_id = bounded_identifier(Some(&task.container_id), "container id")?;
        let image_digest = resolve_container_image(&client, namespace, &object_id).await;
        let decision = RuntimeObservation {
            runtime: RuntimeKind::Containerd,
            timestamp_unix_ms: super::now_unix_ms()?,
            action: "inventory".to_owned(),
            object_id,
            image_digest,
        }
        .evaluate(&policy);
        process_decision(&mut audit, &decision, &mut summary, &mut report)?;
        if max_observations == Some(summary.observations) {
            audit.append_status(
                vollcrypt_shield_core::AuditEventKind::AgentStopped,
                "observation limit reached",
            )?;
            return Ok(summary);
        }
    }

    loop {
        let envelope = match stream.message().await {
            Ok(Some(envelope)) => envelope,
            Ok(None) => {
                audit.append_status(
                    vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
                    "containerd event stream ended unexpectedly",
                )?;
                return Err(ContainerError::State(
                    "containerd event stream ended unexpectedly".to_owned(),
                ));
            }
            Err(error) => {
                audit.append_status(
                    vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
                    "containerd event stream failed closed",
                )?;
                return Err(runtime_error("containerd event stream", error));
            }
        };
        let observation = match containerd_observation(&client, namespace, envelope).await {
            Ok(observation) => observation,
            Err(error) => {
                audit.append_status(
                    vollcrypt_shield_core::AuditEventKind::MonitoringFailed,
                    "malformed containerd event failed closed",
                )?;
                return Err(error);
            }
        };
        let decision = observation.evaluate(&policy);
        process_decision(&mut audit, &decision, &mut summary, &mut report)?;
        if max_observations == Some(summary.observations) {
            audit.append_status(
                vollcrypt_shield_core::AuditEventKind::AgentStopped,
                "observation limit reached",
            )?;
            return Ok(summary);
        }
    }
}

#[cfg(unix)]
async fn containerd_observation(
    client: &Client,
    namespace: &str,
    envelope: Envelope,
) -> Result<RuntimeObservation> {
    let decoded = decode_event(namespace, envelope)?;
    let image_digest = match decoded.image_reference {
        Some(reference) => resolve_image_reference(client, namespace, &reference).await,
        None => resolve_container_image(client, namespace, &decoded.object_id).await,
    };
    Ok(RuntimeObservation {
        runtime: RuntimeKind::Containerd,
        timestamp_unix_ms: decoded.timestamp_unix_ms,
        action: decoded.action,
        object_id: decoded.object_id,
        image_digest,
    })
}

#[cfg(unix)]
struct DecodedEvent {
    timestamp_unix_ms: u64,
    action: String,
    object_id: String,
    image_reference: Option<String>,
}

#[cfg(unix)]
fn decode_event(namespace: &str, envelope: Envelope) -> Result<DecodedEvent> {
    if envelope.namespace != namespace {
        return Err(ContainerError::State(
            "containerd event namespace does not match signed policy".to_owned(),
        ));
    }
    let timestamp_unix_ms = containerd_timestamp_ms(envelope.timestamp.as_ref())?;
    let mut payload = envelope.event.ok_or_else(|| {
        ContainerError::State("containerd event is missing its payload".to_owned())
    })?;
    if payload.type_url.is_empty()
        || payload.type_url.len() > 256
        || payload.value.len() > 1_048_576
    {
        return Err(ContainerError::Limit(
            "containerd event payload exceeds its bounds".to_owned(),
        ));
    }
    if !payload.type_url.starts_with('/') {
        payload.type_url.insert(0, '/');
    }
    match envelope.topic.as_str() {
        "/containers/create" => {
            let create: ContainerCreate = payload.to_msg().map_err(|error| {
                ContainerError::State(format!("invalid ContainerCreate payload: {error}"))
            })?;
            let object_id = bounded_identifier(Some(&create.id), "container id")?;
            let image_reference = bounded_image_reference(&create.image)?;
            Ok(DecodedEvent {
                timestamp_unix_ms,
                action: "container-create".to_owned(),
                object_id,
                image_reference: Some(image_reference),
            })
        }
        "/tasks/start" => {
            let start: TaskStart = payload.to_msg().map_err(|error| {
                ContainerError::State(format!("invalid TaskStart payload: {error}"))
            })?;
            Ok(DecodedEvent {
                timestamp_unix_ms,
                action: "task-start".to_owned(),
                object_id: bounded_identifier(Some(&start.container_id), "container id")?,
                image_reference: None,
            })
        }
        _ => Err(ContainerError::State(
            "containerd emitted an unexpected subscribed topic".to_owned(),
        )),
    }
}

#[cfg(unix)]
async fn resolve_container_image(
    client: &Client,
    namespace: &str,
    container_id: &str,
) -> Option<String> {
    let request = namespaced(
        GetContainerRequest {
            id: container_id.to_owned(),
        },
        namespace,
    )
    .ok()?;
    let container = client
        .containers()
        .get(request)
        .await
        .ok()?
        .into_inner()
        .container?;
    let reference = bounded_image_reference(&container.image).ok()?;
    resolve_image_reference(client, namespace, &reference).await
}

#[cfg(unix)]
async fn resolve_image_reference(
    client: &Client,
    namespace: &str,
    reference: &str,
) -> Option<String> {
    if let Ok(digest) = normalize_image_digest(reference) {
        return Some(digest);
    }
    let request = namespaced(
        GetImageRequest {
            name: reference.to_owned(),
        },
        namespace,
    )
    .ok()?;
    let image = client
        .images()
        .get(request)
        .await
        .ok()?
        .into_inner()
        .image?;
    normalize_image_digest(&image.target?.digest).ok()
}

#[cfg(unix)]
fn namespaced<T>(message: T, namespace: &str) -> Result<Request<T>> {
    let mut request = Request::new(message);
    let metadata = namespace.parse().map_err(|_| {
        ContainerError::State("containerd namespace is invalid gRPC metadata".to_owned())
    })?;
    request
        .metadata_mut()
        .insert("containerd-namespace", metadata);
    Ok(request)
}

#[cfg(unix)]
fn bounded_image_reference(reference: &str) -> Result<String> {
    if reference.is_empty()
        || reference.len() > 1024
        || reference
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ContainerError::State(
            "containerd image reference is invalid".to_owned(),
        ));
    }
    Ok(reference.to_owned())
}

#[cfg(unix)]
fn containerd_timestamp_ms(timestamp: Option<&prost_types::Timestamp>) -> Result<u64> {
    let timestamp = timestamp
        .ok_or_else(|| ContainerError::State("containerd event has no timestamp".to_owned()))?;
    if timestamp.seconds < 0 || !(0..1_000_000_000).contains(&timestamp.nanos) {
        return Err(ContainerError::State(
            "containerd event timestamp is invalid".to_owned(),
        ));
    }
    u64::try_from(timestamp.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|milliseconds| {
            milliseconds.checked_add(u64::try_from(timestamp.nanos / 1_000_000).ok()?)
        })
        .ok_or_else(|| ContainerError::State("containerd timestamp overflow".to_owned()))
}

#[cfg(unix)]
fn validate_containerd_socket(socket: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    if socket.as_os_str().is_empty() || socket.as_os_str().len() > 4096 {
        return Err(ContainerError::State(
            "containerd socket path is invalid".to_owned(),
        ));
    }
    let metadata = std::fs::symlink_metadata(socket)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(ContainerError::State(
            "containerd endpoint must be a non-symlink Unix socket".to_owned(),
        ));
    }
    if metadata.uid() != 0 || metadata.mode() & 0o002 != 0 {
        return Err(ContainerError::State(
            "strong containerd monitoring requires a root-owned, non-world-writable socket"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use containerd_client::events::{ContainerCreate, TaskStart};
    use containerd_client::to_any;
    use prost_types::Timestamp;

    fn envelope(topic: &str, event: prost_types::Any) -> Envelope {
        Envelope {
            timestamp: Some(Timestamp {
                seconds: 10,
                nanos: 250_000_000,
            }),
            namespace: "k8s.io".to_owned(),
            topic: topic.to_owned(),
            event: Some(event),
        }
    }

    #[test]
    fn decodes_bounded_create_and_start_events() {
        let create = ContainerCreate {
            id: "container-a".to_owned(),
            image: "registry.example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            runtime: None,
        };
        let decoded =
            decode_event("k8s.io", envelope("/containers/create", to_any(&create))).unwrap();
        assert_eq!(decoded.timestamp_unix_ms, 10_250);
        assert_eq!(decoded.object_id, "container-a");
        assert_eq!(decoded.action, "container-create");
        assert!(decoded.image_reference.unwrap().contains("@sha256:"));

        let start = TaskStart {
            container_id: "container-a".to_owned(),
            pid: 42,
        };
        let decoded = decode_event("k8s.io", envelope("/tasks/start", to_any(&start))).unwrap();
        assert_eq!(decoded.action, "task-start");
        assert_eq!(decoded.image_reference, None);
    }

    #[test]
    fn rejects_namespace_type_topic_and_timestamp_confusion() {
        let start = TaskStart {
            container_id: "container-a".to_owned(),
            pid: 42,
        };
        let wrong_namespace = envelope("/tasks/start", to_any(&start));
        assert!(decode_event("default", wrong_namespace).is_err());

        let wrong_type = envelope("/containers/create", to_any(&start));
        assert!(decode_event("k8s.io", wrong_type).is_err());

        let unexpected_topic = envelope("/images/create", to_any(&start));
        assert!(decode_event("k8s.io", unexpected_topic).is_err());

        assert!(
            containerd_timestamp_ms(Some(&Timestamp {
                seconds: -1,
                nanos: 0,
            }))
            .is_err()
        );
        assert!(
            containerd_timestamp_ms(Some(&Timestamp {
                seconds: 1,
                nanos: 1_000_000_000,
            }))
            .is_err()
        );
    }
}

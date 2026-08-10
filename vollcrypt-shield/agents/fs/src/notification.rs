use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::NotificationConfig;
use crate::error::{AgentError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub scope_id: String,
    pub kind: String,
    pub timestamp_unix_ms: u64,
    pub message: String,
    pub repeated: bool,
}

pub trait Notifier: Send + Sync {
    fn send(&self, notification: &Notification) -> Result<()>;
}

pub struct LogNotifier {
    path: PathBuf,
}

impl LogNotifier {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Notifier for LogNotifier {
    fn send(&self, notification: &Notification) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_vec(notification)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;
        file.sync_data()?;
        Ok(())
    }
}

pub struct WebhookNotifier {
    url: String,
    agent: ureq::Agent,
}

impl WebhookNotifier {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1")) {
            return Err(AgentError::Config(
                "webhook must use HTTPS, except loopback test endpoints".to_owned(),
            ));
        }
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(std::time::Duration::from_secs(5)))
            .build();
        Ok(Self {
            url,
            agent: config.into(),
        })
    }
}

impl Notifier for WebhookNotifier {
    fn send(&self, notification: &Notification) -> Result<()> {
        self.agent
            .post(&self.url)
            .send_json(notification)
            .map_err(|error| AgentError::Notification(error.to_string()))?;
        Ok(())
    }
}

pub struct NotificationHub {
    log: LogNotifier,
    webhook: Option<WebhookNotifier>,
}

impl NotificationHub {
    pub fn new(state_dir: &std::path::Path, config: &NotificationConfig) -> Result<Self> {
        Ok(Self {
            log: LogNotifier::new(state_dir.join("notifications.jsonl")),
            webhook: config
                .webhook_url
                .as_ref()
                .map(WebhookNotifier::new)
                .transpose()?,
        })
    }

    pub fn send(&self, notification: &Notification) -> Result<()> {
        self.log.send(notification)?;
        if let Some(webhook) = &self.webhook {
            webhook.send(notification)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn log_notifications_are_persistent_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let notifier = LogNotifier::new(dir.path().join("events.jsonl"));
        notifier
            .send(&Notification {
                scope_id: "scope".to_owned(),
                kind: "containment".to_owned(),
                timestamp_unix_ms: 1,
                message: "contained".to_owned(),
                repeated: false,
            })
            .unwrap();
        let text = std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        assert!(text.contains("\"scope_id\":\"scope\""));
    }

    #[test]
    fn insecure_remote_webhook_is_rejected() {
        assert!(WebhookNotifier::new("http://example.com/hook").is_err());
        assert!(WebhookNotifier::new("http://127.0.0.1:8080/hook").is_ok());
    }

    #[test]
    fn notification_delivery_soak_preserves_log_and_webhook_events() {
        const EVENT_COUNT: usize = 128;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..EVENT_COUNT {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                let header_end = loop {
                    let read = stream.read(&mut buffer).unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(position) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                while request.len() < header_end + content_length {
                    let read = stream.read(&mut buffer).unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buffer[..read]);
                }
                assert!(request.starts_with(b"POST /shield HTTP/1.1\r\n"));
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .unwrap();
            }
        });

        let directory = tempfile::tempdir().unwrap();
        let hub = NotificationHub::new(
            directory.path(),
            &NotificationConfig {
                webhook_url: Some(format!("http://{address}/shield")),
            },
        )
        .unwrap();
        for sequence in 0..EVENT_COUNT {
            hub.send(&Notification {
                scope_id: "scope".to_owned(),
                kind: "dry-run-response".to_owned(),
                timestamp_unix_ms: sequence as u64 + 1,
                message: format!("event {sequence}"),
                repeated: sequence > 0,
            })
            .unwrap();
        }
        server.join().unwrap();

        let log = std::fs::read_to_string(directory.path().join("notifications.jsonl")).unwrap();
        let records = log
            .lines()
            .map(|line| serde_json::from_str::<Notification>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), EVENT_COUNT);
        assert_eq!(records.first().unwrap().timestamp_unix_ms, 1);
        assert_eq!(
            records.last().unwrap().timestamp_unix_ms,
            EVENT_COUNT as u64
        );
    }
}

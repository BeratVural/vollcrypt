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
}

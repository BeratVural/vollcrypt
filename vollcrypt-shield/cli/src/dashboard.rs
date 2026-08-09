use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use vollcrypt_shield_fs::{AgentStatus, ScopeConfig, notification::Notification};

const MAX_NOTIFICATION_TAIL_BYTES: u64 = 1_048_576;
const RECENT_NOTIFICATION_LIMIT: usize = 5;
pub const TUI_NOTIFICATION_LIMIT: usize = 500;

#[derive(Debug, Default)]
pub struct NotificationTail {
    pub events: Vec<Notification>,
    pub invalid_records: usize,
    pub unavailable: Option<String>,
}

pub fn read_notification_tail(state_dir: &Path, scope: &str) -> NotificationTail {
    read_notification_tail_with_limit(state_dir, scope, RECENT_NOTIFICATION_LIMIT)
}

pub fn read_notification_tail_with_limit(
    state_dir: &Path,
    scope: &str,
    limit: usize,
) -> NotificationTail {
    let path = state_dir.join("notifications.jsonl");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return NotificationTail::default();
        }
        Err(error) => return unavailable(error.to_string()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return unavailable("notification log is not a regular file".to_owned());
    }

    let start = metadata.len().saturating_sub(MAX_NOTIFICATION_TAIL_BYTES);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) => return unavailable(error.to_string()),
    };
    if let Err(error) = file.seek(SeekFrom::Start(start)) {
        return unavailable(error.to_string());
    }
    let mut bytes = Vec::new();
    if let Err(error) = file
        .take(MAX_NOTIFICATION_TAIL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        return unavailable(error.to_string());
    }
    if start > 0
        && let Some(newline) = bytes.iter().position(|byte| *byte == b'\n')
    {
        bytes.drain(..=newline);
    }

    let mut result = NotificationTail::default();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match serde_json::from_slice::<Notification>(line) {
            Ok(event) if event.scope_id == scope => result.events.push(event),
            Ok(_) => {}
            Err(_) => result.invalid_records += 1,
        }
    }
    let limit = limit.clamp(1, TUI_NOTIFICATION_LIMIT);
    if result.events.len() > limit {
        result.events.drain(..result.events.len() - limit);
    }
    result
}

pub fn render(
    status: &AgentStatus,
    scope: &ScopeConfig,
    notifications: &NotificationTail,
    refreshed_at_unix_ms: u64,
    color: bool,
) -> String {
    let state = if status.contained {
        paint("CONTAINED", "31;1", color)
    } else {
        paint("MONITORING", "32;1", color)
    };
    let response_mode = if scope.protects_system_path() {
        "passive (protected system path)"
    } else if !cfg!(unix) {
        "dry-run (active response unavailable)"
    } else if scope.response.mode == vollcrypt_shield_core::PolicyMode::Active {
        "active"
    } else {
        "dry-run"
    };

    let mut output = String::new();
    output.push_str("Vollcrypt Shield - Local Integrity Dashboard\n");
    output.push_str("================================================\n");
    output.push_str(&format!("Status          : {state}\n"));
    output.push_str(&format!("Scope           : {}\n", status.scope));
    output.push_str(&format!("Root            : {}\n", scope.root.display()));
    output.push_str(&format!("Response mode   : {response_mode}\n"));
    output.push_str(&format!("Audit records   : {}\n", status.audit_records));
    output.push_str(&format!("Refreshed (ms)  : {refreshed_at_unix_ms}\n"));
    if let Some(reason) = &status.reason {
        output.push_str(&format!("Containment     : {reason}\n"));
    }
    output.push_str("\nRecent notifications\n");
    output.push_str("--------------------\n");
    if let Some(error) = &notifications.unavailable {
        output.push_str(&format!("WARNING: notification log unavailable: {error}\n"));
    } else if notifications.events.is_empty() {
        output.push_str("No notifications recorded for this scope.\n");
    } else {
        for event in &notifications.events {
            let repeated = if event.repeated { " repeated" } else { "" };
            output.push_str(&format!(
                "{}  {}{}  {}\n",
                event.timestamp_unix_ms, event.kind, repeated, event.message
            ));
        }
    }
    if notifications.invalid_records > 0 {
        output.push_str(&format!(
            "WARNING: {} malformed notification record(s) detected.\n",
            notifications.invalid_records
        ));
    }
    output
}

fn unavailable(message: String) -> NotificationTail {
    NotificationTail {
        unavailable: Some(message),
        ..NotificationTail::default()
    }
}

fn paint(value: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use vollcrypt_shield_core::{MetadataPolicy, ResponsePolicy, ScanProfile};

    fn scope(root: PathBuf) -> ScopeConfig {
        ScopeConfig {
            id: "app".to_owned(),
            root,
            include: vec!["**".to_owned()],
            exclude: vec![],
            metadata: MetadataPolicy::default(),
            full_scan: ScanProfile::full_default(),
            incremental_scan: ScanProfile::incremental_default(),
            full_rescan_interval_secs: 300,
            response: ResponsePolicy::default(),
        }
    }

    #[test]
    fn dashboard_shows_containment_and_malformed_notifications() {
        let status = AgentStatus {
            scope: "app".to_owned(),
            contained: true,
            reason: Some("integrity difference at app.conf".to_owned()),
            audit_records: 9,
        };
        let notifications = NotificationTail {
            events: vec![Notification {
                scope_id: "app".to_owned(),
                kind: "scope-contained".to_owned(),
                timestamp_unix_ms: 42,
                message: "contained".to_owned(),
                repeated: false,
            }],
            invalid_records: 1,
            unavailable: None,
        };
        let rendered = render(
            &status,
            &scope(PathBuf::from("/srv/app")),
            &notifications,
            100,
            false,
        );
        assert!(rendered.contains("CONTAINED"));
        assert!(rendered.contains("integrity difference at app.conf"));
        assert!(rendered.contains("scope-contained"));
        assert!(rendered.contains("1 malformed notification record"));
    }

    #[test]
    fn notification_tail_is_scope_filtered_and_bounded_to_recent_events() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notifications.jsonl");
        let mut text = String::new();
        for index in 0..8 {
            text.push_str(
                &serde_json::to_string(&Notification {
                    scope_id: if index == 0 { "other" } else { "app" }.to_owned(),
                    kind: "integrity-warning".to_owned(),
                    timestamp_unix_ms: index,
                    message: format!("event-{index}"),
                    repeated: false,
                })
                .unwrap(),
            );
            text.push('\n');
        }
        std::fs::write(path, text).unwrap();
        let tail = read_notification_tail(directory.path(), "app");
        assert_eq!(tail.events.len(), 5);
        assert_eq!(tail.events[0].message, "event-3");
        assert_eq!(tail.events[4].message, "event-7");
    }

    #[test]
    fn notification_tail_bounds_high_volume_and_counts_malformed_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notifications.jsonl");
        let mut text = String::from("not-json\n");
        for index in 0..750 {
            text.push_str(
                &serde_json::to_string(&Notification {
                    scope_id: "app".to_owned(),
                    kind: "integrity-warning".to_owned(),
                    timestamp_unix_ms: index,
                    message: format!("event-{index}"),
                    repeated: false,
                })
                .unwrap(),
            );
            text.push('\n');
        }
        std::fs::write(path, text).unwrap();

        let tail = read_notification_tail_with_limit(directory.path(), "app", 500);
        assert_eq!(tail.events.len(), 500);
        assert_eq!(tail.events.first().unwrap().message, "event-250");
        assert_eq!(tail.events.last().unwrap().message, "event-749");
        assert_eq!(tail.invalid_records, 1);
    }
}

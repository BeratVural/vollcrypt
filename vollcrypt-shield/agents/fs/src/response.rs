use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vollcrypt_shield_core::{
    AuditEventKind, DifferenceKind, IntegrityEntry, MlDsa65PublicKey, MlDsa65SecretKey, PolicyMode,
    ResponseAction, Snapshot, VerificationReport,
};

use crate::audit_store::AuditStore;
use crate::config::{NotificationConfig, ScopeConfig};
use crate::error::Result;
use crate::notification::{Notification, NotificationHub};
use crate::state::StateStore;
use crate::vault::Vault;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseOutcome {
    Warned(String),
    DryRun(String),
    Quarantined(String),
    RolledBack(String),
    ScopeContained(String),
}

pub struct ResponseEngine {
    vault: Vault,
    notifications: NotificationHub,
}

pub struct ResponseContext<'a> {
    pub state: &'a mut StateStore,
    pub audit: &'a mut AuditStore,
    pub agent_secret: &'a MlDsa65SecretKey,
    pub agent_public: &'a MlDsa65PublicKey,
}

impl ResponseEngine {
    pub fn new(state_dir: &Path, notification_config: &NotificationConfig) -> Result<Self> {
        Ok(Self {
            vault: Vault::new(state_dir)?,
            notifications: NotificationHub::new(state_dir, notification_config)?,
        })
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn handle(
        &self,
        scope: &ScopeConfig,
        snapshot: &Snapshot,
        observed_entries: &[IntegrityEntry],
        report: &VerificationReport,
        now_unix_ms: u64,
        context: &mut ResponseContext<'_>,
    ) -> Result<Vec<ResponseOutcome>> {
        if report.is_match() {
            return Ok(Vec::new());
        }
        scope.response.validate()?;
        let baseline: BTreeMap<_, _> = snapshot
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        let observed: BTreeMap<_, _> = observed_entries
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        let force_dry_run = scope.protects_system_path() || !cfg!(unix);
        let mut outcomes = Vec::new();

        for difference in &report.differences {
            let path = difference.path.to_string();
            if scope.response.mode == PolicyMode::DryRun || force_dry_run {
                let reason = if scope.protects_system_path() {
                    "protected system root forces passive response"
                } else if !cfg!(unix) {
                    "Phase 2 active response is Linux/Unix-only"
                } else {
                    "response policy is in mandatory dry-run"
                };
                context.audit.append(
                    now_unix_ms,
                    &scope.id,
                    AuditEventKind::DryRunResponse,
                    Some(path.clone()),
                    format!("{reason}; difference={:?}", difference.kind),
                    context.agent_secret,
                )?;
                self.notifications.send(&Notification {
                    scope_id: scope.id.clone(),
                    kind: "dry-run-response".to_owned(),
                    timestamp_unix_ms: now_unix_ms,
                    message: format!("{reason}: {path}"),
                    repeated: false,
                })?;
                outcomes.push(ResponseOutcome::DryRun(path));
                continue;
            }

            for action in &scope.response.actions {
                match action {
                    ResponseAction::Warn => {
                        self.warn(scope, &path, now_unix_ms, context)?;
                        outcomes.push(ResponseOutcome::Warned(path.clone()));
                    }
                    ResponseAction::Quarantine => {
                        if let Some(current) = observed.get(&difference.path) {
                            self.vault.quarantine_regular_file(
                                scope,
                                &difference.path,
                                current.content_digest,
                                baseline
                                    .get(&difference.path)
                                    .map(|entry| entry.content_digest),
                                now_unix_ms,
                                context.agent_secret,
                            )?;
                            context.audit.append(
                                now_unix_ms,
                                &scope.id,
                                AuditEventKind::Quarantined,
                                Some(path.clone()),
                                "reversible quarantine completed",
                                context.agent_secret,
                            )?;
                            outcomes.push(ResponseOutcome::Quarantined(path.clone()));
                        }
                    }
                    ResponseAction::Rollback => {
                        if difference.kind == DifferenceKind::Added {
                            continue;
                        }
                        let destination = scope.root.join(difference.path.as_str());
                        if (destination.exists() || std::fs::symlink_metadata(&destination).is_ok())
                            && let Some(current) = observed.get(&difference.path)
                        {
                            self.vault.quarantine_regular_file(
                                scope,
                                &difference.path,
                                current.content_digest,
                                baseline
                                    .get(&difference.path)
                                    .map(|entry| entry.content_digest),
                                now_unix_ms,
                                context.agent_secret,
                            )?;
                        }
                        self.vault.restore_regular_file(
                            scope,
                            &difference.path,
                            context.agent_public,
                        )?;
                        context.audit.append(
                            now_unix_ms,
                            &scope.id,
                            AuditEventKind::RolledBack,
                            Some(path.clone()),
                            "baseline object restored atomically",
                            context.agent_secret,
                        )?;
                        outcomes.push(ResponseOutcome::RolledBack(path.clone()));
                    }
                    ResponseAction::ContainScope => {
                        self.contain(
                            scope,
                            format!("integrity difference at {path}"),
                            now_unix_ms,
                            context,
                        )?;
                        outcomes.push(ResponseOutcome::ScopeContained(scope.id.clone()));
                    }
                }
            }
        }
        Ok(outcomes)
    }

    pub fn contain_after_failure(
        &self,
        scope: &ScopeConfig,
        reason: impl Into<String>,
        now_unix_ms: u64,
        context: &mut ResponseContext<'_>,
    ) -> Result<()> {
        self.contain(scope, reason, now_unix_ms, context)
    }

    pub fn notify_containment_reminder(
        &self,
        scope_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<()> {
        self.notifications.send(&Notification {
            scope_id: scope_id.to_owned(),
            kind: "containment-reminder".to_owned(),
            timestamp_unix_ms: now_unix_ms,
            message: reason.to_owned(),
            repeated: true,
        })
    }

    pub fn notify_break_glass_release(&self, scope_id: &str, now_unix_ms: u64) -> Result<()> {
        self.notifications.send(&Notification {
            scope_id: scope_id.to_owned(),
            kind: "break-glass-release".to_owned(),
            timestamp_unix_ms: now_unix_ms,
            message: "scope containment released by signed break-glass command".to_owned(),
            repeated: false,
        })
    }

    pub fn notify_monitoring_failure(
        &self,
        scope_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<()> {
        self.notifications.send(&Notification {
            scope_id: scope_id.to_owned(),
            kind: "monitoring-failure".to_owned(),
            timestamp_unix_ms: now_unix_ms,
            message: reason.to_owned(),
            repeated: false,
        })
    }

    fn warn(
        &self,
        scope: &ScopeConfig,
        path: &str,
        now_unix_ms: u64,
        _context: &mut ResponseContext<'_>,
    ) -> Result<()> {
        self.notifications.send(&Notification {
            scope_id: scope.id.clone(),
            kind: "integrity-warning".to_owned(),
            timestamp_unix_ms: now_unix_ms,
            message: format!("integrity difference: {path}"),
            repeated: false,
        })?;
        Ok(())
    }

    fn contain(
        &self,
        scope: &ScopeConfig,
        reason: impl Into<String>,
        now_unix_ms: u64,
        context: &mut ResponseContext<'_>,
    ) -> Result<()> {
        let reason = reason.into();
        let was_contained = context.state.is_contained(&scope.id);
        context
            .state
            .contain_scope(&scope.id, reason.clone(), now_unix_ms);
        if !was_contained {
            context.audit.append(
                now_unix_ms,
                &scope.id,
                AuditEventKind::ScopeContained,
                None,
                &reason,
                context.agent_secret,
            )?;
            self.notifications.send(&Notification {
                scope_id: scope.id.clone(),
                kind: "scope-contained".to_owned(),
                timestamp_unix_ms: now_unix_ms,
                message: reason,
                repeated: false,
            })?;
        }
        Ok(())
    }
}

use serde::{Deserialize, Serialize};

use crate::error::{Result, ShieldError};
use crate::model::{MetadataPolicy, NormalizedPath};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    DryRun,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseAction {
    Warn,
    Quarantine,
    Rollback,
    ContainScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub mode: PolicyMode,
    pub actions: Vec<ResponseAction>,
    pub reminder_interval_secs: u64,
    pub activated_at_unix_ms: Option<u64>,
    pub approved_by_key_id: Option<[u8; 32]>,
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
            mode: PolicyMode::DryRun,
            actions: vec![ResponseAction::Warn],
            reminder_interval_secs: 300,
            activated_at_unix_ms: None,
            approved_by_key_id: None,
        }
    }
}

impl ResponsePolicy {
    pub fn validate(&self) -> Result<()> {
        if self.actions.is_empty() {
            return Err(ShieldError::InvalidPolicy(
                "at least one response action is required".to_owned(),
            ));
        }
        if !(60..=86_400).contains(&self.reminder_interval_secs) {
            return Err(ShieldError::InvalidPolicy(
                "reminder interval must be between 60 and 86400 seconds".to_owned(),
            ));
        }
        if self.mode == PolicyMode::Active
            && (self.activated_at_unix_ms.is_none() || self.approved_by_key_id.is_none())
        {
            return Err(ShieldError::InvalidPolicy(
                "active policy requires explicit timestamp and approving key".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn promote(&mut self, approved_by_key_id: [u8; 32], timestamp_unix_ms: u64) -> Result<()> {
        if self.mode != PolicyMode::DryRun {
            return Err(ShieldError::InvalidPolicy(
                "only a dry-run policy can be promoted".to_owned(),
            ));
        }
        self.mode = PolicyMode::Active;
        self.approved_by_key_id = Some(approved_by_key_id);
        self.activated_at_unix_ms = Some(timestamp_unix_ms);
        self.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanProfile {
    pub max_threads: usize,
    pub max_cpu_percent: u8,
    pub io_yield_every_files: usize,
    pub max_incremental_paths: usize,
}

impl ScanProfile {
    pub fn full_default() -> Self {
        Self {
            max_threads: 4,
            max_cpu_percent: 80,
            io_yield_every_files: 1_000,
            max_incremental_paths: 10_000,
        }
    }

    pub fn incremental_default() -> Self {
        Self {
            max_threads: 2,
            max_cpu_percent: 25,
            io_yield_every_files: 100,
            max_incremental_paths: 1_000,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_threads == 0 || self.max_threads > 256 {
            return Err(ShieldError::InvalidPolicy(
                "max_threads must be between 1 and 256".to_owned(),
            ));
        }
        if !(1..=100).contains(&self.max_cpu_percent) {
            return Err(ShieldError::InvalidPolicy(
                "max_cpu_percent must be between 1 and 100".to_owned(),
            ));
        }
        if self.io_yield_every_files == 0 || self.max_incremental_paths == 0 {
            return Err(ShieldError::InvalidPolicy(
                "scan bounds must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityPolicy {
    pub scope_id: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub metadata: MetadataPolicy,
    pub full_scan: ScanProfile,
    pub incremental_scan: ScanProfile,
    pub response: ResponsePolicy,
}

impl IntegrityPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.scope_id.is_empty()
            || self.scope_id.len() > 128
            || !self
                .scope_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ShieldError::InvalidPolicy(
                "scope_id must be 1-128 ASCII identifier characters".to_owned(),
            ));
        }
        self.full_scan.validate()?;
        self.incremental_scan.validate()?;
        self.response.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DifferenceKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationDifference {
    pub path: NormalizedPath,
    pub kind: DifferenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub scope_id: String,
    pub baseline_root: [u8; 32],
    pub observed_root: [u8; 32],
    pub differences: Vec<VerificationDifference>,
}

impl VerificationReport {
    pub fn is_match(&self) -> bool {
        self.baseline_root == self.observed_root && self.differences.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_policy_requires_explicit_promotion() {
        let mut policy = ResponsePolicy {
            actions: vec![ResponseAction::Warn, ResponseAction::ContainScope],
            ..ResponsePolicy::default()
        };
        assert_eq!(policy.mode, PolicyMode::DryRun);
        policy.promote([7; 32], 42).unwrap();
        assert_eq!(policy.mode, PolicyMode::Active);
        assert!(policy.promote([8; 32], 43).is_err());
    }

    #[test]
    fn reminder_interval_cannot_be_disabled() {
        let policy = ResponsePolicy {
            reminder_interval_secs: 0,
            ..ResponsePolicy::default()
        };
        assert!(policy.validate().is_err());
    }
}

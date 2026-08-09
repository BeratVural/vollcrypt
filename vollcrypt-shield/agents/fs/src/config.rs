use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{IntegrityPolicy, MetadataPolicy, ResponsePolicy, ScanProfile};

use crate::error::{AgentError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NotificationConfig {
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeConfig {
    pub id: String,
    pub root: PathBuf,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub metadata: MetadataPolicy,
    pub full_scan: ScanProfile,
    pub incremental_scan: ScanProfile,
    #[serde(default = "default_full_rescan_interval_secs")]
    pub full_rescan_interval_secs: u64,
    pub response: ResponsePolicy,
}

impl ScopeConfig {
    pub fn integrity_policy(&self) -> IntegrityPolicy {
        IntegrityPolicy {
            scope_id: self.id.clone(),
            include: self.include.clone(),
            exclude: self.exclude.clone(),
            metadata: self.metadata.clone(),
            full_scan: self.full_scan.clone(),
            incremental_scan: self.incremental_scan.clone(),
            response: self.response.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.integrity_policy().validate()?;
        if !self.root.is_absolute() {
            return Err(AgentError::Config(format!(
                "scope {} root must be absolute",
                self.id
            )));
        }
        if !self.root.is_dir() {
            return Err(AgentError::Config(format!(
                "scope {} root is not a directory: {}",
                self.id,
                self.root.display()
            )));
        }
        if self.full_rescan_interval_secs < 60 {
            return Err(AgentError::Config(format!(
                "scope {} full_rescan_interval_secs must be at least 60",
                self.id
            )));
        }
        Ok(())
    }

    pub fn protects_system_path(&self) -> bool {
        is_protected_system_path(&self.root)
    }

    pub fn dry_run_fingerprint(&self) -> Result<[u8; 32]> {
        let mut policy = self.integrity_policy();
        policy.response.mode = vollcrypt_shield_core::PolicyMode::DryRun;
        policy.response.activated_at_unix_ms = None;
        policy.response.approved_by_key_id = None;
        let encoded = serde_json::to_vec(&(self.root.as_path(), policy))
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"VOLLCRYPT-SHIELD-DRY-RUN-POLICY-v1\0");
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfig {
    pub state_dir: PathBuf,
    pub scopes: Vec<ScopeConfig>,
    pub notifications: NotificationConfig,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.state_dir.is_absolute() {
            return Err(AgentError::Config(
                "state_dir must be an absolute path".to_owned(),
            ));
        }
        if self.scopes.is_empty() {
            return Err(AgentError::Config(
                "at least one monitoring scope is required".to_owned(),
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for scope in &self.scopes {
            scope.validate()?;
            if !ids.insert(&scope.id) {
                return Err(AgentError::Config(format!(
                    "duplicate scope id: {}",
                    scope.id
                )));
            }
            if scope.root.starts_with(&self.state_dir) || self.state_dir.starts_with(&scope.root) {
                return Err(AgentError::Config(format!(
                    "state_dir and scope {} must not contain one another",
                    scope.id
                )));
            }
        }
        Ok(())
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let value: Self =
            toml::from_str(text).map_err(|error| AgentError::Serialization(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn to_toml(&self) -> Result<String> {
        self.validate()?;
        toml::to_string_pretty(self).map_err(|error| AgentError::Serialization(error.to_string()))
    }
}

fn is_protected_system_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        const PROTECTED: &[&str] = &[
            "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run",
            "/sbin", "/sys", "/usr", "/var/lib",
        ];
        if PROTECTED.iter().any(|prefix| {
            let prefix = Path::new(prefix);
            (prefix == Path::new("/") && path == prefix)
                || (prefix != Path::new("/") && path.starts_with(prefix))
        }) {
            return true;
        }
    }
    #[cfg(windows)]
    {
        if let Some(system_root) = std::env::var_os("SystemRoot")
            && path.starts_with(PathBuf::from(system_root))
        {
            return true;
        }
        if let Some(program_files) = std::env::var_os("ProgramFiles")
            && path.starts_with(PathBuf::from(program_files))
        {
            return true;
        }
    }
    false
}

pub const fn default_full_rescan_interval_secs() -> u64 {
    300
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn protected_system_descendants_are_passive() {
        assert!(is_protected_system_path(Path::new("/etc/vollcrypt")));
        assert!(is_protected_system_path(Path::new("/usr/local/bin")));
        assert!(!is_protected_system_path(Path::new("/home/user/project")));
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Core(#[from] vollcrypt_shield_core::ShieldError),
    #[error(transparent)]
    Protocol(#[from] vollcrypt_shield_protocol::ProtocolError),
    #[cfg(windows)]
    #[error(transparent)]
    WindowsBackup(#[from] vollcrypt_shield_windows::WindowsBackupError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("scan error: {0}")]
    Scan(String),
    #[error("scope is contained: {0}")]
    ScopeContained(String),
    #[error("unsafe response target: {0}")]
    UnsafeResponseTarget(String),
    #[error("quarantine error: {0}")]
    Quarantine(String),
    #[error("notification error: {0}")]
    Notification(String),
    #[error("break-glass command was already used")]
    BreakGlassReplay,
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;

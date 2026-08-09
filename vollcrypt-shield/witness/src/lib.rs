#![forbid(unsafe_code)]

mod node;

pub use node::{WitnessNode, WitnessStatus, now_unix_ms};

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("invalid witness configuration: {0}")]
    Config(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Core(#[from] vollcrypt_shield_core::ShieldError),
    #[error(transparent)]
    Protocol(#[from] vollcrypt_shield_protocol::ProtocolError),
}

pub type Result<T> = std::result::Result<T, WitnessError>;

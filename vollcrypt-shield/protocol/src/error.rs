#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid pairing code")]
    InvalidPairingCode,
    #[error("pairing session expired")]
    PairingExpired,
    #[error("pairing transcript is invalid: {0}")]
    InvalidPairing(String),
    #[error("pairing authentication failed")]
    AuthenticationFailed,
    #[error("invalid witness policy: {0}")]
    InvalidWitnessPolicy(String),
    #[error("invalid control-plane record: {0}")]
    InvalidControlPlane(String),
    #[error("invalid fleet API record: {0}")]
    InvalidFleetApi(String),
    #[error("invalid offline package: {0}")]
    InvalidOfflinePackage(String),
    #[error("witness quorum was not reached: accepted {accepted}, required {required}")]
    QuorumNotReached { accepted: usize, required: usize },
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error(transparent)]
    Core(#[from] vollcrypt_shield_core::ShieldError),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

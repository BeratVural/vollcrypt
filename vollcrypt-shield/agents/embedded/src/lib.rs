#![no_std]
#![forbid(unsafe_code)]

mod agent;
mod audit;
mod checkpoint;
mod containment;
mod measurement;

pub use agent::EmbeddedShield;
pub use audit::{AuditChain, AuditEventKind, AuditRecord};
pub use checkpoint::{
    CHECKPOINT_LEN, Checkpoint, CheckpointSignError, CheckpointSigner, SignedCheckpoint,
    SigningError, sign_checkpoint,
};
pub use containment::{
    Containment, RELEASE_COMMAND_LEN, ReleaseCommand, ReleaseVerifier, ScopeState,
};
pub use measurement::{Measurement, MeasurementKind, MeasurementSet};

pub const FORMAT_VERSION: u16 = 1;
pub const HASH_ALGORITHM_SHA256: u8 = 1;
pub const SIGNATURE_ALGORITHM_ML_DSA_65: u8 = 1;

pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddedError {
    CapacityExceeded,
    MeasurementNotFound,
    CounterRollback,
    SequenceExhausted,
    EpochRollback,
    InvalidPersistedState,
    ScopeContained,
    AlreadyContained,
    NotContained,
    WrongScope,
    WrongContainment,
    ReleaseNotYetValid,
    ReleaseExpired,
    InvalidReleaseSignature,
}

pub(crate) fn hash_parts(parts: &[&[u8]]) -> Digest {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

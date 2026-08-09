#![forbid(unsafe_code)]

pub mod algorithm;
pub mod audit;
pub mod break_glass;
pub mod crypto;
pub mod error;
pub mod merkle;
pub mod model;
pub mod policy;
pub mod resource;
pub mod snapshot;

pub use algorithm::{FORMAT_VERSION, HashAlgorithm, SignatureAlgorithm};
pub use audit::{AuditEvent, AuditEventKind, SignedAuditRecord, verify_audit_chain};
pub use break_glass::{BreakGlassAction, BreakGlassCommand, SignedBreakGlassCommand};
pub use crypto::{MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
pub use error::{Result, ShieldError};
pub use merkle::{IntegrityProof, SparseMerkleTree};
pub use model::{EntryKind, IntegrityEntry, MetadataPolicy, NormalizedPath};
pub use policy::{
    DifferenceKind, IntegrityPolicy, PolicyMode, ResponseAction, ResponsePolicy, ScanProfile,
    VerificationDifference, VerificationReport,
};
pub use resource::ResourceGovernor;
pub use snapshot::{SignedSnapshot, Snapshot};

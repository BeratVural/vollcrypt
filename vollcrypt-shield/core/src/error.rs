#[derive(Debug, thiserror::Error)]
pub enum ShieldError {
    #[error("invalid normalized path: {0}")]
    InvalidPath(String),
    #[error("duplicate integrity path: {0}")]
    DuplicatePath(String),
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported algorithm identifier")]
    UnsupportedAlgorithm,
    #[error("invalid ML-DSA-65 key or signature length")]
    InvalidSignatureMaterial,
    #[error("ML-DSA-65 key generation or signing failed")]
    SignatureOperation,
    #[error("signature verification failed")]
    SignatureVerification,
    #[error("CBOR encoding failed: {0}")]
    CborEncode(String),
    #[error("CBOR decoding failed: {0}")]
    CborDecode(String),
    #[error("Merkle proof is malformed")]
    InvalidMerkleProof,
    #[error("audit chain is invalid at sequence {0}")]
    InvalidAuditChain(u64),
    #[error("policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ShieldError>;

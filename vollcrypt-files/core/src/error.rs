use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum FileFormatError {
    #[error("Invalid magic bytes")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid mode: {0}")]
    InvalidMode(u8),

    #[error("Invalid cipher ID: {0}")]
    InvalidCipherId(u8),

    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(u8),

    #[error("Invalid wrap type: {0}")]
    InvalidWrapType(u8),

    #[error("Truncated header: expected {expected} bytes, got {got} bytes")]
    TruncatedHeader { expected: usize, got: usize },

    #[error("Truncated chunk: expected {expected} bytes, got {got} bytes")]
    TruncatedChunk { expected: usize, got: usize },

    #[error("Wrap payload length mismatch for type {wrap_type}: expected {expected} bytes, got {got} bytes")]
    WrapPayloadLengthMismatch {
        wrap_type: u8,
        expected: u16,
        got: u16,
    },

    #[error("AES-GCM decryption failed")]
    AesGcmDecryptFailed,

    #[error("Chunk index out of order: expected {expected}, got {got}")]
    ChunkIndexOutOfOrder { expected: u32, got: u32 },

    #[error("Invalid proof length: expected {expected}, got {got}")]
    InvalidProofLength { expected: usize, got: usize },

    #[error("Wrong password / AES-KW verification failed")]
    WrongPassword,

    #[error("Wrong wrap type for password mode")]
    WrongWrapType,

    #[error("KDF parameter out of range: {0}")]
    KdfParameterOutOfRange(String),

    #[error("Wrong recipient key / decapsulation failed")]
    WrongRecipientKey,

    #[error("Invalid wrap payload size")]
    InvalidWrapPayload,

    #[error("Invalid cryptographic signature")]
    SignatureInvalid,

    #[error("Invalid manifest magic bytes")]
    InvalidManifestMagic,

    #[error("Unsupported manifest version: {0}")]
    UnsupportedManifestVersion(u8),

    #[error("Invalid manifest operation chain / hash link")]
    InvalidManifestChain,

    #[error("Group manifest has no operations / genesis block")]
    EmptyManifest,

    #[error("Member not found in group")]
    MemberNotFound,

    #[error("Operation signer not authorized / not an admin")]
    NotAuthorized,

    #[error("Wrong group key / group decryption failed")]
    WrongGroupKey,

    #[error("Unknown manifest operation type: {0}")]
    UnknownOperationType(u8),

    #[error("Group key version {0} has been shredded")]
    GroupKeyShredded(u32),

    #[error("Wrap entry version not found: version {gk_version}")]
    WrapVersionNotFound { gk_version: u32 },

    #[error("Group key version has already been shredded")]
    AlreadyShredded,

    #[error("Invalid shred reason (must be <= 256 bytes)")]
    InvalidShredReason,

    #[error("Header is not signed")]
    HeaderNotSigned,

    #[error("Unsupported KEM suite ID: {0}")]
    UnsupportedSuite(u8),

    #[error("Integrity error: {0}")]
    IntegrityError(String),

    #[error("Rollback detected: expected epoch >= {expected}, got {got}")]
    RollbackError { expected: u64, got: u64 },

    #[error("Manifest epoch out of sequence: expected {expected}, got {got}")]
    ManifestEpochOutOfSequence { expected: u64, got: u64 },

    #[error("Header is sealed")]
    HeaderSealed,

    #[error("Header is not sealed")]
    HeaderNotSealed,

    #[error("Invalid sealed payload")]
    InvalidSealedPayload,

    #[error("Label too long")]
    LabelTooLong,

    #[error("Device not found")]
    DeviceNotFound,

    #[error("Device already revoked")]
    DeviceAlreadyRevoked,

    #[error("Key log entry not found")]
    KeyLogEntryNotFound,

    #[error("Invalid key log magic")]
    InvalidKeyLogMagic,

    #[error("Unsupported key log version: {0}")]
    UnsupportedKeyLogVersion(u8),

    #[error("Invalid key log chain / hash link")]
    InvalidKeyLogChain,

    #[error("Sealed group key required")]
    SealedGkRequired,

    #[error("I/O error: {0}")]
    IoError(String),
}

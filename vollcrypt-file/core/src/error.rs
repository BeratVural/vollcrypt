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
}

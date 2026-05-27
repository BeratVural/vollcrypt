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
}

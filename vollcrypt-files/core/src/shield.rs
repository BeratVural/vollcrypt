use crate::error::FileFormatError;
use crate::header::{Header, SignedMetadata, Mode};
use crate::merkle::HashAlgorithm;
use crate::signature::{verify_header_signature_plain_policy, VerificationPolicy};
use crate::pipelined_io::read_header_from_stream;
use std::io::{Read, Seek, SeekFrom};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReleaseMode {
    #[default]
    Verified,
    Streaming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignaturePolicy {
    #[default]
    Required,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnTamper {
    #[default]
    Abort,
    AbortWithReport,
    AttemptRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShieldPolicy {
    pub release_mode: ReleaseMode,
    pub signature: SignaturePolicy,
    pub rollback_pin: Option<u64>,
    pub founder_anchor: bool,
    pub on_tamper: OnTamper,
    pub verify_sealed_marker: bool,
}

impl Default for ShieldPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

impl ShieldPolicy {
    pub fn strict() -> Self {
        Self {
            release_mode: ReleaseMode::Verified,
            signature: SignaturePolicy::Required,
            rollback_pin: None,
            founder_anchor: true,
            on_tamper: OnTamper::Abort,
            verify_sealed_marker: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldReport {
    Success,
    Magic,
    Version(u8),
    HeaderField(String),
    WrapTable,
    Signature,
    ChunkIndexMismatch { expected: u32, got: u32 },
    ChunkTag { index: u32 },
    MerkleRoot,
    MerkleProof { index: u32 },
    ContainerSealed,
    Unrecoverable,
    KdfError,
    Rollback { expected: u64, got: u64 },
    UntrustedGenesis,
}

pub fn verify_container<R: Read + Seek>(
    mut reader: R,
    policy: &ShieldPolicy,
) -> ShieldReport {
    // 1. Read header
    let (header, header_len) = match read_header_from_stream(&mut reader) {
        Ok(res) => res,
        Err(e) => return map_format_error_to_report(e),
    };

    // 2. Signature verification policy
    let sig_policy = match policy.signature {
        SignaturePolicy::Required => VerificationPolicy::RequireSigned,
        SignaturePolicy::Optional => VerificationPolicy::AllowLegacy,
    };

    if header.version == 2 || header.version == 3 {
        if let Err(_) = verify_header_signature_plain_policy(&header, sig_policy) {
            return ShieldReport::Signature;
        }
    } else if sig_policy == VerificationPolicy::RequireSigned {
        return ShieldReport::Signature;
    }

    // 3. Sealed marker integrity & Re-wrapping rejection
    let wraps_empty = header.wraps.is_empty();
    let has_sealed_marker = matches!(header.signed_metadata, Some(SignedMetadata::SovereignSealed { .. }));
    if has_sealed_marker {
        if !wraps_empty {
            // Re-adding a wrap to a sealed container is rejected
            return ShieldReport::WrapTable;
        }
    }

    if crate::sovereign::is_sealed(&header) {
        return ShieldReport::ContainerSealed;
    }

    // 4. Verify chunk index and tags
    let chunk_size = header.chunk_size as usize;
    let plaintext_size = header.plaintext_size;
    let hash_algo = header.hash_algorithm;

    let current_pos = reader.stream_position().unwrap_or(0);
    let total_len = reader.seek(std::io::SeekFrom::End(0)).unwrap_or(0);
    let _ = reader.seek(std::io::SeekFrom::Start(current_pos));
    let max_possible_chunks = if total_len > current_pos {
        (total_len - current_pos) / 32
    } else {
        0
    };

    let total_chunks_u64 = if plaintext_size == 0 {
        0
    } else {
        plaintext_size.div_ceil(chunk_size as u64)
    };
    if total_chunks_u64 > 10_000_000 || total_chunks_u64 > max_possible_chunks {
        return ShieldReport::HeaderField("too_many_chunks".to_string());
    }
    let total_chunks = total_chunks_u64 as u32;

    let mut leaf_hashes = Vec::new();
    let payload_start_pos = match reader.stream_position() {
        Ok(pos) => pos,
        Err(_) => return ShieldReport::HeaderField("stream_position_failed".to_string()),
    };

    let mut ciphertext_buf = vec![0u8; chunk_size];

    for idx in 0..total_chunks {
        let is_last = idx == total_chunks - 1;
        let chunk_plaintext_len = if is_last {
            let rem = plaintext_size % chunk_size as u64;
            if rem == 0 {
                chunk_size
            } else {
                rem as usize
            }
        } else {
            chunk_size
        };

        // Read index and IV
        let mut prefix = [0u8; 16];
        if let Err(_) = reader.read_exact(&mut prefix) {
            return ShieldReport::ChunkTag { index: idx };
        }
        let read_idx = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        if read_idx != idx {
            return ShieldReport::ChunkIndexMismatch { expected: idx, got: read_idx };
        }
        let iv: [u8; 12] = prefix[4..16].try_into().unwrap();

        // Read ciphertext instead of seeking forward
        ciphertext_buf.resize(chunk_plaintext_len, 0);
        if let Err(_) = reader.read_exact(&mut ciphertext_buf) {
            return ShieldReport::ChunkTag { index: idx };
        }

        // Read tag
        let mut tag = [0u8; 16];
        if let Err(_) = reader.read_exact(&mut tag) {
            return ShieldReport::ChunkTag { index: idx };
        }

        // Compute leaf hash
        let leaf = crate::merkle::chunk_leaf_hash_raw_with_algo(idx, &iv, &ciphertext_buf, &tag, hash_algo);
        leaf_hashes.push(leaf);
    }

    // Verify there are no trailing bytes
    let end_pos = match reader.stream_position() {
        Ok(pos) => pos,
        Err(_) => return ShieldReport::HeaderField("stream_position_failed".to_string()),
    };
    let final_pos = match reader.seek(SeekFrom::End(0)) {
        Ok(pos) => pos,
        Err(_) => return ShieldReport::HeaderField("seek_end_failed".to_string()),
    };
    if final_pos != end_pos {
        return ShieldReport::HeaderField("trailing_bytes".to_string());
    }

    // Verify Merkle root
    let recomputed_root = if leaf_hashes.is_empty() {
        [0u8; 32]
    } else {
        let tree = crate::merkle::MerkleTree::from_leaves_with_algo(leaf_hashes, hash_algo);
        tree.root()
    };

    if recomputed_root.ct_eq(&header.merkle_root).unwrap_u8() != 1 {
        return ShieldReport::MerkleRoot;
    }

    ShieldReport::Success
}

fn map_format_error_to_report(err: FileFormatError) -> ShieldReport {
    match err {
        FileFormatError::InvalidMagic => ShieldReport::Magic,
        FileFormatError::UnsupportedVersion(v) => ShieldReport::Version(v),
        FileFormatError::InvalidMode(m) => ShieldReport::HeaderField(format!("mode_{}", m)),
        FileFormatError::InvalidCipherId(c) => ShieldReport::HeaderField(format!("cipher_id_{}", c)),
        FileFormatError::UnsupportedHashAlgorithm(a) => ShieldReport::HeaderField(format!("hash_algorithm_{}", a)),
        FileFormatError::TruncatedHeader { .. } => ShieldReport::HeaderField("truncated_header".to_string()),
        FileFormatError::TruncatedChunk { .. } => ShieldReport::HeaderField("truncated_chunk".to_string()),
        FileFormatError::ChunkIndexOutOfOrder { expected, got } => ShieldReport::ChunkIndexMismatch { expected, got },
        FileFormatError::AesGcmDecryptFailed => ShieldReport::MerkleRoot,
        FileFormatError::ContainerSealed => ShieldReport::ContainerSealed,
        FileFormatError::RollbackError { expected, got } => ShieldReport::Rollback { expected, got },
        FileFormatError::UntrustedGenesis => ShieldReport::UntrustedGenesis,
        _ => ShieldReport::HeaderField(err.to_string()),
    }
}

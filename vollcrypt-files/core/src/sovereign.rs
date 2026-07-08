use crate::error::FileFormatError;
use crate::header::{Header, SignedMetadata, Mode};
use crate::merkle::HashAlgorithm;
use crate::pipelined_io::{read_header_from_stream, PipelinedSignInfo};
use std::io::{Read, Write, Seek, SeekFrom};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealMode {
    Seal,
    Purge,
}

#[derive(Clone)]
pub struct SealOptions {
    pub mode: SealMode,
    pub reason: Option<String>,
    pub sign_info: Option<PipelinedSignInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedInspection {
    pub version: u8,
    pub file_id: [u8; 16],
    pub chunk_size: u32,
    pub plaintext_size: u64,
    pub merkle_root: [u8; 32],
    pub hash_algorithm: HashAlgorithm,
    pub sealed_mode: Option<u8>,
    pub reason: Option<String>,
    pub timestamp: Option<u64>,
    pub ciphertext_present: bool,
}

pub fn is_sealed(header: &Header) -> bool {
    header.wraps.is_empty()
}

pub fn inspect_sealed<R: Read + Seek>(mut reader: R) -> Result<SealedInspection, FileFormatError> {
    let (header, header_len) = read_header_from_stream(&mut reader)?;
    if !header.wraps.is_empty() {
        return Err(FileFormatError::IntegrityError("Container is not sealed".to_string()));
    }

    let current_pos = reader.stream_position().map_err(|e| FileFormatError::IoError(e.to_string()))?;
    let end_pos = reader.seek(SeekFrom::End(0)).map_err(|e| FileFormatError::IoError(e.to_string()))?;
    let ciphertext_present = end_pos > header_len as u64;

    let (sealed_mode, reason, timestamp) = match &header.signed_metadata {
        Some(SignedMetadata::SovereignSealed { mode, reason, timestamp, .. }) => {
            (Some(mode), Some(reason.clone()), Some(timestamp))
        }
        _ => (None, None, None),
    };

    Ok(SealedInspection {
        version: header.version,
        file_id: header.file_id,
        chunk_size: header.chunk_size,
        plaintext_size: header.plaintext_size,
        merkle_root: header.merkle_root,
        hash_algorithm: header.hash_algorithm,
        sealed_mode: sealed_mode.copied(),
        reason,
        timestamp: timestamp.copied(),
        ciphertext_present,
    })
}

pub fn seal_container<R: Read + Seek, W: Write + Seek>(
    mut source: R,
    mut dest: W,
    mut options: SealOptions,
) -> Result<(), FileFormatError> {
    // 1. Read header
    let (mut header, header_len) = read_header_from_stream(&mut source)?;

    // 2. Idempotency: if already sealed, return Ok(()) (no-op)
    if header.wraps.is_empty() {
        source.seek(SeekFrom::Start(0)).map_err(|e| FileFormatError::IoError(e.to_string()))?;
        dest.seek(SeekFrom::Start(0)).map_err(|e| FileFormatError::IoError(e.to_string()))?;
        std::io::copy(&mut source, &mut dest).map_err(|e| FileFormatError::IoError(e.to_string()))?;
        return Ok(());
    }

    // 3. Clear wraps
    header.wraps.clear();

    // 4. Handle signing (required for all versions, upgrades version 1 to 3)
    let sign_info = options.sign_info.as_ref().ok_or_else(|| {
        FileFormatError::IntegrityError("Signature keys required to seal container".to_string())
    })?;

    if header.version == 1 {
        header.version = 3;
    }

    let (signer_pk, signer_sk, timestamp) = match sign_info {
        PipelinedSignInfo::Plain { signer_pk, signer_sk, timestamp, .. } => (signer_pk, signer_sk, *timestamp),
        PipelinedSignInfo::Sealed { signer_pk, signer_sk, timestamp, .. } => (signer_pk, signer_sk, *timestamp),
    };

    let reason = options.reason.clone().unwrap_or_default();
    let mode_u8 = match options.mode {
        SealMode::Seal => 1,
        SealMode::Purge => 2,
    };

    crate::signature::sign_header_sovereign_sealed(
        &mut header,
        signer_pk,
        signer_sk,
        mode_u8,
        reason,
        timestamp,
    )?;

    // 5. Write rewritten header
    let serialized_header = header.write();
    dest.write_all(&serialized_header).map_err(|e| FileFormatError::IoError(e.to_string()))?;

    // 6. Handle chunks based on mode
    match options.mode {
        SealMode::Seal => {
            source.seek(SeekFrom::Start(header_len as u64)).map_err(|e| FileFormatError::IoError(e.to_string()))?;
            std::io::copy(&mut source, &mut dest).map_err(|e| FileFormatError::IoError(e.to_string()))?;
        }
        SealMode::Purge => {
            // Ciphertext purged. Do not copy anything to dest.
        }
    }

    // Explicitly zeroize options secrets in memory after the operation
    if let Some(ref mut sign_info) = options.sign_info {
        match sign_info {
            PipelinedSignInfo::Plain { signer_sk, .. } => signer_sk.zeroize(),
            PipelinedSignInfo::Sealed { signer_sk, sealed_gk, .. } => {
                signer_sk.zeroize();
                sealed_gk.zeroize();
            }
        }
    }

    Ok(())
}

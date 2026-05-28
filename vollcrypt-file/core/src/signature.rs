use crate::aead::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::error::FileFormatError;
use crate::header::{Header, SignedMetadata};
use crate::signing::{ed25519_sign, ed25519_verify};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn sign_header_plain(
    header: &mut Header,
    signer_ed25519_pk: &[u8; 32],
    signer_ed25519_sk: &[u8; 32],
    key_log_id: [u8; 32],
    timestamp: u64,
) -> Result<(), FileFormatError> {
    header.signed_metadata = Some(SignedMetadata::Plain {
        signer_pubkey: *signer_ed25519_pk,
        timestamp,
        key_log_id,
    });
    header.signature = None;
    let bytes_to_sign = header.signed_bytes();
    let sig = ed25519_sign(signer_ed25519_sk, &bytes_to_sign);
    header.signature = Some(sig);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn sign_header_sealed(
    header: &mut Header,
    signer_ed25519_pk: &[u8; 32],
    signer_ed25519_sk: &[u8; 32],
    key_log_id: [u8; 32],
    timestamp: u64,
    sealed_group_id: [u8; 16],
    sealed_gk_version: u32,
    sealed_gk: &[u8; 32],
) -> Result<(), FileFormatError> {
    let mut sealed_plaintext = [0u8; 64];
    sealed_plaintext[0..32].copy_from_slice(signer_ed25519_pk);
    sealed_plaintext[32..64].copy_from_slice(&key_log_id);

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(&header.file_id);
    aad.extend_from_slice(&timestamp.to_be_bytes());

    let (sealed_payload, sealed_tag) = aes256_gcm_encrypt(sealed_gk, &iv, &aad, &sealed_plaintext)?;

    header.signed_metadata = Some(SignedMetadata::Sealed {
        sealed_group_id,
        sealed_gk_version,
        iv,
        sealed_payload,
        sealed_tag,
        timestamp,
    });
    header.signature = None;
    let bytes_to_sign = header.signed_bytes();
    let sig = ed25519_sign(signer_ed25519_sk, &bytes_to_sign);
    header.signature = Some(sig);
    Ok(())
}

pub fn verify_header_signature_plain(header: &Header) -> Result<[u8; 32], FileFormatError> {
    let signed_metadata = header
        .signed_metadata
        .as_ref()
        .ok_or(FileFormatError::HeaderNotSigned)?;

    let signer_pubkey = match signed_metadata {
        SignedMetadata::Plain { signer_pubkey, .. } => signer_pubkey,
        SignedMetadata::Sealed { .. } => return Err(FileFormatError::HeaderSealed),
    };

    let signature = header.signature.ok_or(FileFormatError::HeaderNotSigned)?;
    let bytes_to_verify = header.signed_bytes();
    ed25519_verify(signer_pubkey, &bytes_to_verify, &signature)?;

    Ok(*signer_pubkey)
}

pub fn verify_header_signature_sealed(
    header: &Header,
    sealed_gk: &[u8; 32],
) -> Result<[u8; 32], FileFormatError> {
    let signed_metadata = header
        .signed_metadata
        .as_ref()
        .ok_or(FileFormatError::HeaderNotSigned)?;

    let (sealed_payload, sealed_tag, iv, timestamp) = match signed_metadata {
        SignedMetadata::Plain { .. } => return Err(FileFormatError::HeaderNotSealed),
        SignedMetadata::Sealed {
            sealed_payload,
            sealed_tag,
            iv,
            timestamp,
            ..
        } => (sealed_payload, sealed_tag, iv, timestamp),
    };

    let signature = header.signature.ok_or(FileFormatError::HeaderNotSigned)?;

    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(&header.file_id);
    aad.extend_from_slice(&timestamp.to_be_bytes());

    let sealed_plaintext = aes256_gcm_decrypt(sealed_gk, iv, &aad, sealed_payload, sealed_tag)
        .map_err(|_| FileFormatError::WrongGroupKey)?;

    if sealed_plaintext.len() != 64 {
        return Err(FileFormatError::InvalidSealedPayload);
    }

    let mut signer_pubkey = [0u8; 32];
    signer_pubkey.copy_from_slice(&sealed_plaintext[0..32]);

    let bytes_to_verify = header.signed_bytes();
    ed25519_verify(&signer_pubkey, &bytes_to_verify, &signature)?;

    Ok(signer_pubkey)
}

pub fn extract_key_log_id_plain(header: &Header) -> Result<[u8; 32], FileFormatError> {
    let signed_metadata = header
        .signed_metadata
        .as_ref()
        .ok_or(FileFormatError::HeaderNotSigned)?;
    match signed_metadata {
        SignedMetadata::Plain { key_log_id, .. } => Ok(*key_log_id),
        SignedMetadata::Sealed { .. } => Err(FileFormatError::HeaderSealed),
    }
}

pub fn extract_key_log_id_sealed(
    header: &Header,
    sealed_gk: &[u8; 32],
) -> Result<[u8; 32], FileFormatError> {
    let signed_metadata = header
        .signed_metadata
        .as_ref()
        .ok_or(FileFormatError::HeaderNotSigned)?;
    let (sealed_payload, sealed_tag, iv, timestamp) = match signed_metadata {
        SignedMetadata::Plain { .. } => return Err(FileFormatError::HeaderNotSealed),
        SignedMetadata::Sealed {
            sealed_payload,
            sealed_tag,
            iv,
            timestamp,
            ..
        } => (sealed_payload, sealed_tag, iv, timestamp),
    };

    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(&header.file_id);
    aad.extend_from_slice(&timestamp.to_be_bytes());

    let sealed_plaintext = aes256_gcm_decrypt(sealed_gk, iv, &aad, sealed_payload, sealed_tag)
        .map_err(|_| FileFormatError::WrongGroupKey)?;

    if sealed_plaintext.len() != 64 {
        return Err(FileFormatError::InvalidSealedPayload);
    }

    let mut key_log_id = [0u8; 32];
    key_log_id.copy_from_slice(&sealed_plaintext[32..64]);
    Ok(key_log_id)
}

use crate::aead::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::error::FileFormatError;
use crate::header::{Header, SignedMetadata};
use crate::hybrid_sig::{hybrid_sign, hybrid_verify, HybridPublicKey, HybridSecretKey, HybridSignature};
use crate::keylog::{KeyLog, KeyLogEntryType};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

pub fn sign_header_plain(
    header: &mut Header,
    signer_pk: &HybridPublicKey,
    signer_sk: &HybridSecretKey,
    key_log_id: [u8; 32],
    timestamp: u64,
) -> Result<(), FileFormatError> {
    header.version = 3;
    header.signed_metadata = Some(SignedMetadata::Plain {
        signer_pubkey: signer_pk.clone(),
        timestamp,
        key_log_id,
    });
    header.signature = None;
    let bytes_to_sign = header.signed_bytes();
    let sig = hybrid_sign(signer_sk, signer_pk, "vollf-hdr-plain", &[], &bytes_to_sign);
    header.signature = Some(sig);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn sign_header_sealed(
    header: &mut Header,
    signer_pk: &HybridPublicKey,
    signer_sk: &HybridSecretKey,
    key_log_id: [u8; 32],
    timestamp: u64,
    sealed_group_id: [u8; 16],
    sealed_gk_version: u32,
    sealed_gk: &[u8; 32],
) -> Result<(), FileFormatError> {
    header.version = 3;

    // Under v3, we ONLY seal key_log_id (32 bytes).
    let mut sealed_plaintext = [0u8; 32];
    sealed_plaintext.copy_from_slice(&key_log_id);

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
    let sig = hybrid_sign(signer_sk, signer_pk, "vollf-hdr-sealed", &[], &bytes_to_sign);
    header.signature = Some(sig);
    Ok(())
}

pub fn verify_header_signature_plain(header: &Header) -> Result<HybridPublicKey, FileFormatError> {
    verify_header_signature_plain_policy(header, false)
}

pub fn verify_header_signature_plain_policy(
    header: &Header,
    require_pq_signature: bool,
) -> Result<HybridPublicKey, FileFormatError> {
    if header.version == 1 || header.signed_metadata.is_none() || header.signature.is_none() {
        if require_pq_signature {
            return Err(FileFormatError::IntegrityError(
                "Unsigned header rejected under require_pq_signature policy".to_string(),
            ));
        } else {
            return Err(FileFormatError::HeaderNotSigned);
        }
    }

    if require_pq_signature && header.version < 3 {
        return Err(FileFormatError::IntegrityError(
            "Legacy signature version rejected under require_pq_signature policy".to_string(),
        ));
    }

    let signed_metadata = header.signed_metadata.as_ref().unwrap();

    let signer_pubkey = match signed_metadata {
        SignedMetadata::Plain { signer_pubkey, .. } => signer_pubkey,
        SignedMetadata::Sealed { .. } => return Err(FileFormatError::HeaderSealed),
    };

    let signature = header.signature.as_ref().unwrap();
    let bytes_to_verify = header.signed_bytes();

    if header.version == 3 {
        if !hybrid_verify(signer_pubkey, "vollf-hdr-plain", &[], &bytes_to_verify, signature) {
            return Err(FileFormatError::SignatureInvalid);
        }
    } else {
        crate::signing::ed25519_verify(&signer_pubkey.ed25519, &bytes_to_verify, &signature.ed25519)?;
    }

    Ok(signer_pubkey.clone())
}

pub fn verify_header_signature_sealed(
    header: &Header,
    sealed_gk: &[u8; 32],
    key_log: &KeyLog,
) -> Result<HybridPublicKey, FileFormatError> {
    verify_header_signature_sealed_policy(header, sealed_gk, key_log, false)
}

pub fn verify_header_signature_sealed_policy(
    header: &Header,
    sealed_gk: &[u8; 32],
    key_log: &KeyLog,
    require_pq_signature: bool,
) -> Result<HybridPublicKey, FileFormatError> {
    if header.version == 1 || header.signed_metadata.is_none() || header.signature.is_none() {
        if require_pq_signature {
            return Err(FileFormatError::IntegrityError(
                "Unsigned header rejected under require_pq_signature policy".to_string(),
            ));
        } else {
            return Err(FileFormatError::HeaderNotSigned);
        }
    }

    if require_pq_signature && header.version < 3 {
        return Err(FileFormatError::IntegrityError(
            "Legacy signature version rejected under require_pq_signature policy".to_string(),
        ));
    }

    let signed_metadata = header.signed_metadata.as_ref().unwrap();

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

    let signature = header.signature.as_ref().unwrap();

    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(&header.file_id);
    aad.extend_from_slice(&timestamp.to_be_bytes());

    let decrypt_res = aes256_gcm_decrypt(sealed_gk, iv, &aad, sealed_payload, sealed_tag);
    let decrypt_ok = decrypt_res.is_ok();

    if header.version == 3 {
        let mut decrypted = decrypt_res.unwrap_or_else(|_| vec![0u8; 32]);
        let len_ok = decrypted.len() == 32;

        let mut safe_plaintext = [0u8; 32];
        let copy_len = std::cmp::min(decrypted.len(), 32);
        safe_plaintext[..copy_len].copy_from_slice(&decrypted[..copy_len]);

        let key_log_id = safe_plaintext;

        decrypted.zeroize();
        safe_plaintext.zeroize();

        let mut key_found = false;
        let mut signer_pubkey = HybridPublicKey {
            ed25519: [0u8; 32],
            mldsa: [0u8; 1952],
        };

        if let Some(entry) = key_log.lookup_by_entry_hash(&key_log_id) {
            if let KeyLogEntryType::DeviceRegister { device_pubkey, .. } = &entry.entry {
                signer_pubkey = device_pubkey.clone();
                key_found = true;
            }
        }

        let bytes_to_verify = header.signed_bytes();
        let sig_ok = hybrid_verify(&signer_pubkey, "vollf-hdr-sealed", &[], &bytes_to_verify, signature);

        if decrypt_ok && len_ok && key_found && sig_ok {
            Ok(signer_pubkey)
        } else {
            Err(FileFormatError::WrongGroupKey)
        }
    } else {
        let mut decrypted = decrypt_res.unwrap_or_else(|_| vec![0u8; 64]);
        let len_ok = decrypted.len() == 64;

        let mut safe_plaintext = [0u8; 64];
        let copy_len = std::cmp::min(decrypted.len(), 64);
        safe_plaintext[..copy_len].copy_from_slice(&decrypted[..copy_len]);

        let mut signer_ed_pubkey = [0u8; 32];
        signer_ed_pubkey.copy_from_slice(&safe_plaintext[0..32]);

        decrypted.zeroize();
        safe_plaintext.zeroize();

        let bytes_to_verify = header.signed_bytes();
        let sig_ok = crate::signing::ed25519_verify(&signer_ed_pubkey, &bytes_to_verify, &signature.ed25519).is_ok();

        if decrypt_ok && len_ok && sig_ok {
            let signer_pubkey = HybridPublicKey {
                ed25519: signer_ed_pubkey,
                mldsa: [0u8; 1952],
            };
            Ok(signer_pubkey)
        } else {
            Err(FileFormatError::WrongGroupKey)
        }
    }
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

    let decrypt_res = aes256_gcm_decrypt(sealed_gk, iv, &aad, sealed_payload, sealed_tag);
    let decrypt_ok = decrypt_res.is_ok();

    if header.version == 3 {
        let mut decrypted = decrypt_res.unwrap_or_else(|_| vec![0u8; 32]);
        let len_ok = decrypted.len() == 32;

        let mut safe_plaintext = [0u8; 32];
        let copy_len = std::cmp::min(decrypted.len(), 32);
        safe_plaintext[..copy_len].copy_from_slice(&decrypted[..copy_len]);

        let key_log_id = safe_plaintext;
        decrypted.zeroize();
        safe_plaintext.zeroize();

        if decrypt_ok && len_ok {
            Ok(key_log_id)
        } else {
            Err(FileFormatError::WrongGroupKey)
        }
    } else {
        let mut decrypted = decrypt_res.unwrap_or_else(|_| vec![0u8; 64]);
        let len_ok = decrypted.len() == 64;

        let mut safe_plaintext = [0u8; 64];
        let copy_len = std::cmp::min(decrypted.len(), 64);
        safe_plaintext[..copy_len].copy_from_slice(&decrypted[..copy_len]);

        let mut key_log_id = [0u8; 32];
        key_log_id.copy_from_slice(&safe_plaintext[32..64]);

        decrypted.zeroize();
        safe_plaintext.zeroize();

        if decrypt_ok && len_ok {
            Ok(key_log_id)
        } else {
            Err(FileFormatError::WrongGroupKey)
        }
    }
}

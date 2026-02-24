use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;
use crate::padding::{pad_message_with_len, unpad_message_with_len};

/// Encrypts data using AES-256-GCM.
/// Automatically generates a secure 12-byte random IV (nonce) and prepends it to the cipher text.
/// Returns Ok(iv + ciphertext) or Err
pub fn encrypt_aes256gcm(
    key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    if key.len() != 32 {
        log::error!("encrypt_aes256gcm: Invalid AES key length (expected 32, got {})", key.len());
        return Err("Invalid AES key length, must be 32 bytes");
    }

    log::debug!("encrypt_aes256gcm: Encrypting plaintext of length {}", plaintext.len());
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
        log::error!("encrypt_aes256gcm: Failed to create AES cipher");
        "Failed to create AES cipher"
    })?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data.unwrap_or(b""),
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| {
            log::error!("encrypt_aes256gcm: Encryption failed");
            "Encryption failed"
        })?;

    // Prepend the nonce to the ciphertext
    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    nonce_bytes.zeroize();

    Ok(result)
}

/// Decrypts data using AES-256-GCM.
/// Expects the 12-byte IV (nonce) to be prepended to the cipher text.
pub fn decrypt_aes256gcm(
    key: &[u8],
    encrypted_data: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    if key.len() != 32 {
        log::error!("decrypt_aes256gcm: Invalid AES key length");
        return Err("Invalid AES key length, must be 32 bytes");
    }
    if encrypted_data.len() < 12 {
        log::error!("decrypt_aes256gcm: Encrypted data too short (missing nonce)");
        return Err("Encrypted data too short, missing nonce");
    }

    log::debug!("decrypt_aes256gcm: Decrypting ciphertext of length {}", encrypted_data.len());
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
        log::error!("decrypt_aes256gcm: Failed to create AES cipher");
        "Failed to create AES cipher"
    })?;

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data.unwrap_or(b""),
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| {
            log::error!("decrypt_aes256gcm: Decryption failed or MAC mismatch");
            "Decryption failed or MAC mismatch"
        })?;

    Ok(plaintext)
}

pub fn encrypt_aes256gcm_padded(
    key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    let padded = pad_message_with_len(plaintext)?;
    let encrypted = encrypt_aes256gcm(key, &padded, associated_data)?;
    Ok(encrypted)
}

pub fn decrypt_aes256gcm_padded(
    key: &[u8],
    encrypted_data: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    let mut padded = decrypt_aes256gcm(key, encrypted_data, associated_data)?;
    let unpadded = unpad_message_with_len(&padded)?;
    padded.zeroize();
    Ok(unpadded)
}

fn build_chunk_aad(base_aad: Option<&[u8]>, chunk_index: u32) -> Vec<u8> {
    let base_len = base_aad.map(|v| v.len()).unwrap_or(0);
    let mut aad = Vec::with_capacity(base_len + 4);
    if let Some(base) = base_aad {
        aad.extend_from_slice(base);
    }
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad
}

pub fn encrypt_aes256gcm_chunked(
    key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
    chunk_size: usize,
) -> Result<Vec<u8>, &'static str> {
    if chunk_size == 0 {
        log::error!("encrypt_aes256gcm_chunked: Invalid chunk size");
        return Err("Invalid chunk size, must be greater than 0");
    }
    if key.len() != 32 {
        log::error!("encrypt_aes256gcm_chunked: Invalid AES key length (expected 32, got {})", key.len());
        return Err("Invalid AES key length, must be 32 bytes");
    }

    let total_len = plaintext.len();
    let chunk_count = if total_len == 0 {
        1usize
    } else {
        (total_len + chunk_size - 1) / chunk_size
    };

    if chunk_count > u32::MAX as usize {
        log::error!("encrypt_aes256gcm_chunked: Chunk count overflow");
        return Err("Chunk count exceeds supported maximum");
    }

    let mut result = Vec::new();
    result.extend_from_slice(&(chunk_count as u32).to_be_bytes());

    for i in 0..chunk_count {
        let start = i * chunk_size;
        let end = if total_len == 0 { 0 } else { (start + chunk_size).min(total_len) };
        let chunk = &plaintext[start..end];
        let mut aad = build_chunk_aad(associated_data, i as u32);
        let encrypted = encrypt_aes256gcm(key, chunk, Some(&aad))?;
        let enc_len = encrypted.len();
        if enc_len > u32::MAX as usize {
            aad.zeroize();
            log::error!("encrypt_aes256gcm_chunked: Chunk ciphertext too large");
            return Err("Chunk ciphertext too large");
        }
        result.extend_from_slice(&(i as u32).to_be_bytes());
        result.extend_from_slice(&(enc_len as u32).to_be_bytes());
        result.extend_from_slice(&encrypted);
        aad.zeroize();
    }

    Ok(result)
}

pub fn decrypt_aes256gcm_chunked(
    key: &[u8],
    encrypted_data: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    if key.len() != 32 {
        log::error!("decrypt_aes256gcm_chunked: Invalid AES key length");
        return Err("Invalid AES key length, must be 32 bytes");
    }
    if encrypted_data.len() < 4 {
        log::error!("decrypt_aes256gcm_chunked: Encrypted data too short");
        return Err("Encrypted data too short");
    }

    let chunk_count = u32::from_be_bytes([encrypted_data[0], encrypted_data[1], encrypted_data[2], encrypted_data[3]]) as usize;
    if chunk_count == 0 {
        log::error!("decrypt_aes256gcm_chunked: Invalid chunk count");
        return Err("Invalid chunk count");
    }

    let mut offset = 4usize;
    let mut plaintext = Vec::new();

    for expected_index in 0..chunk_count {
        if offset + 8 > encrypted_data.len() {
            log::error!("decrypt_aes256gcm_chunked: Truncated chunk header");
            return Err("Encrypted data truncated");
        }
        let chunk_index = u32::from_be_bytes([
            encrypted_data[offset],
            encrypted_data[offset + 1],
            encrypted_data[offset + 2],
            encrypted_data[offset + 3],
        ]);
        let chunk_len = u32::from_be_bytes([
            encrypted_data[offset + 4],
            encrypted_data[offset + 5],
            encrypted_data[offset + 6],
            encrypted_data[offset + 7],
        ]) as usize;
        offset += 8;

        if chunk_index as usize != expected_index {
            log::error!("decrypt_aes256gcm_chunked: Chunk index mismatch");
            return Err("Chunk index mismatch");
        }
        if chunk_len == 0 || offset + chunk_len > encrypted_data.len() {
            log::error!("decrypt_aes256gcm_chunked: Invalid chunk length");
            return Err("Invalid chunk length");
        }

        let chunk = &encrypted_data[offset..offset + chunk_len];
        let mut aad = build_chunk_aad(associated_data, chunk_index);
        let decrypted = decrypt_aes256gcm(key, chunk, Some(&aad))?;
        aad.zeroize();
        plaintext.extend_from_slice(&decrypted);
        offset += chunk_len;
    }

    if offset != encrypted_data.len() {
        log::error!("decrypt_aes256gcm_chunked: Trailing data after chunks");
        return Err("Trailing data after chunks");
    }

    Ok(plaintext)
}

pub fn encrypt_aes256gcm_chunked_padded(
    key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
    chunk_size: usize,
) -> Result<Vec<u8>, &'static str> {
    let padded = pad_message_with_len(plaintext)?;
    let encrypted = encrypt_aes256gcm_chunked(key, &padded, associated_data, chunk_size)?;
    Ok(encrypted)
}

pub fn decrypt_aes256gcm_chunked_padded(
    key: &[u8],
    encrypted_data: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    let mut padded = decrypt_aes256gcm_chunked(key, encrypted_data, associated_data)?;
    let unpadded = unpad_message_with_len(&padded)?;
    padded.zeroize();
    Ok(unpadded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = b"an_example_very_secret_key_32_ba"; // 32 bytes
        let message = b"Confidential Lawyer Documents";
        let aad = b"metadata";

        let encrypted = encrypt_aes256gcm(key, message, Some(aad)).unwrap();

        let decrypted = decrypt_aes256gcm(key, &encrypted, Some(aad)).unwrap();
        assert_eq!(decrypted, message);

        // Fails with bad key
        let mut bad_key = *key;
        bad_key[0] = b'b';
        assert!(decrypt_aes256gcm(&bad_key, &encrypted, Some(aad)).is_err());

        // Fails with bad AAD
        assert!(decrypt_aes256gcm(key, &encrypted, Some(b"wrong_meta")).is_err());
    }

    #[test]
    fn test_aes_chunked_roundtrip() {
        let key = [7u8; 32];
        let aad = b"chunked-aad";
        let plaintext = vec![0x42u8; 10_000];
        let encrypted = encrypt_aes256gcm_chunked(&key, &plaintext, Some(aad), 1024).unwrap();
        let decrypted = decrypt_aes256gcm_chunked(&key, &encrypted, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_chunked_index_tamper_fails() {
        let key = [9u8; 32];
        let plaintext = vec![0x33u8; 2048];
        let mut encrypted = encrypt_aes256gcm_chunked(&key, &plaintext, None, 1024).unwrap();
        encrypted[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert!(decrypt_aes256gcm_chunked(&key, &encrypted, None).is_err());
    }

    #[test]
    fn test_aes_padded_roundtrip() {
        let key = [3u8; 32];
        let plaintext = b"padded-message";
        let encrypted = encrypt_aes256gcm_padded(&key, plaintext, None).unwrap();
        let decrypted = decrypt_aes256gcm_padded(&key, &encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_chunked_padded_roundtrip() {
        let key = [4u8; 32];
        let plaintext = vec![0x22u8; 10_000];
        let encrypted = encrypt_aes256gcm_chunked_padded(&key, &plaintext, None, 1024).unwrap();
        let decrypted = decrypt_aes256gcm_chunked_padded(&key, &encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }


    #[test]
    fn test_aes_chunked_empty_roundtrip() {
        let key = [1u8; 32];
        let plaintext = Vec::new();
        let encrypted = encrypt_aes256gcm_chunked(&key, &plaintext, None, 1024).unwrap();
        let decrypted = decrypt_aes256gcm_chunked(&key, &encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

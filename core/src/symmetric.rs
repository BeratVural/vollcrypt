use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;

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
}

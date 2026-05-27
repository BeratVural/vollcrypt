use crate::error::FileFormatError;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};

/// Encrypts plaintext using AES-256-GCM.
///
/// Returns a tuple containing the ciphertext (`Vec<u8>`) and the auth tag (`[u8; 16]`).
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), FileFormatError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

    let nonce = Nonce::from_slice(iv);
    let mut buffer = plaintext.to_vec();

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut buffer)
        .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(&tag);
    Ok((buffer, tag_arr))
}

/// Decrypts ciphertext using AES-256-GCM.
///
/// Returns the decrypted plaintext (`Vec<u8>`). If decryption or authentication fails,
/// returns `FileFormatError::AesGcmDecryptFailed`.
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, FileFormatError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

    let nonce = Nonce::from_slice(iv);
    let tag_obj = Tag::from_slice(tag);
    let mut buffer = ciphertext.to_vec();

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut buffer, tag_obj)
        .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

    Ok(buffer)
}

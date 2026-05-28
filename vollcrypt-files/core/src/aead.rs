use crate::error::FileFormatError;
use crate::provider::get_crypto_provider;
use crate::buffer_pool::PooledBuffer;

/// Encrypts plaintext using AES-256-GCM.
///
/// Returns a tuple containing the ciphertext (`Vec<u8>`) and the auth tag (`[u8; 16]`).
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), FileFormatError> {
    get_crypto_provider().encrypt(key, iv, aad, plaintext)
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
    get_crypto_provider().decrypt(key, iv, aad, ciphertext, tag)
}

/// Encrypts plaintext using AES-256-GCM asynchronously.
pub async fn aes256_gcm_encrypt_async(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: Vec<u8>,
) -> Result<(Vec<u8>, [u8; 16]), FileFormatError> {
    get_crypto_provider().encrypt_async(key, iv, aad, plaintext).await
}

/// Decrypts ciphertext using AES-256-GCM asynchronously.
pub async fn aes256_gcm_decrypt_async(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
) -> Result<Vec<u8>, FileFormatError> {
    get_crypto_provider().decrypt_async(key, iv, aad, ciphertext, tag).await
}

/// Encrypts a buffer in place using AES-256-GCM.
pub fn aes256_gcm_encrypt_in_place(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; 16], FileFormatError> {
    get_crypto_provider().encrypt_in_place(key, iv, aad, buffer)
}

/// Decrypts a buffer in place using AES-256-GCM.
pub fn aes256_gcm_decrypt_in_place(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), FileFormatError> {
    get_crypto_provider().decrypt_in_place(key, iv, aad, buffer, tag)
}

/// Encrypts a PooledBuffer in place asynchronously using AES-256-GCM.
pub async fn aes256_gcm_encrypt_in_place_async(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    buffer: PooledBuffer,
    len: usize,
) -> Result<(PooledBuffer, [u8; 16]), FileFormatError> {
    get_crypto_provider().encrypt_in_place_async(key, iv, aad, buffer, len).await
}

/// Decrypts a PooledBuffer in place asynchronously using AES-256-GCM.
pub async fn aes256_gcm_decrypt_in_place_async(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    buffer: PooledBuffer,
    len: usize,
    tag: [u8; 16],
) -> Result<PooledBuffer, FileFormatError> {
    get_crypto_provider().decrypt_in_place_async(key, iv, aad, buffer, len, tag).await
}



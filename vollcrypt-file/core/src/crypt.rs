use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::aead::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::chunk::ChunkEnvelope;
use crate::error::FileFormatError;
use crate::kdf::derive_chunk_subkey;

/// Encrypts a single plaintext chunk and returns a `ChunkEnvelope`.
///
/// * `dek`: The Data Encryption Key (32 bytes).
/// * `file_id`: The unique file identifier (16 bytes).
/// * `chunk_index`: The index of the chunk.
/// * `plaintext`: The plaintext data for this chunk.
pub fn encrypt_chunk(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    plaintext: &[u8],
) -> Result<ChunkEnvelope, FileFormatError> {
    // Derive subkey and wrap it in Zeroizing to guarantee zeroization on scope exit.
    let subkey = Zeroizing::new(derive_chunk_subkey(dek, file_id, chunk_index));

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let mut aad = [0u8; 20];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());

    let (ciphertext, tag) = aes256_gcm_encrypt(&subkey, &iv, &aad, plaintext)?;

    Ok(ChunkEnvelope {
        chunk_index,
        iv,
        ciphertext,
        tag,
    })
}

/// Decrypts a single chunk from a `ChunkEnvelope`.
///
/// * `dek`: The Data Encryption Key (32 bytes).
/// * `file_id`: The unique file identifier (16 bytes).
/// * `chunk_index`: The expected index of the chunk.
/// * `envelope`: The `ChunkEnvelope` containing encrypted chunk data.
pub fn decrypt_chunk(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    envelope: &ChunkEnvelope,
) -> Result<Vec<u8>, FileFormatError> {
    if envelope.chunk_index != chunk_index {
        return Err(FileFormatError::ChunkIndexOutOfOrder {
            expected: chunk_index,
            got: envelope.chunk_index,
        });
    }

    // Derive subkey and wrap it in Zeroizing to guarantee zeroization on scope exit.
    let subkey = Zeroizing::new(derive_chunk_subkey(dek, file_id, chunk_index));

    let mut aad = [0u8; 20];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());

    let plaintext = aes256_gcm_decrypt(
        &subkey,
        &envelope.iv,
        &aad,
        &envelope.ciphertext,
        &envelope.tag,
    )?;

    Ok(plaintext)
}

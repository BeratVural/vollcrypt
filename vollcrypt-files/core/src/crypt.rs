use zeroize::Zeroizing;

use crate::aead::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::chunk::ChunkEnvelope;
use crate::error::FileFormatError;
use crate::kdf::derive_chunk_keys;

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
    // GCM'de tehlikeli olan aynı (key, nonce) çiftinin tekrar kullanılmasıdır.
    // Her chunk'ın subkey'i zaten chunk_index'e bağlı türetildiği için her chunk'ın
    // ANAHTARI benzersizdir. Nonce tekrarı yalnızca aynı anahtar altında tehlikelidir;
    // anahtar her chunk'ta farklı olduğundan (subkey, IV) çifti benzersiz kalır.
    // Dolayısıyla deterministik IV nonce reuse yaratmaz. Bu, age / AWS Encryption SDK /
    // STREAM construction'da kullanılan standart desendir.
    // İNVARIANT: Aynı DEK aynı file_id ile farklı içerik için ASLA tekrar kullanılmamalı.
    // generate_dek() ve generate_file_id() her dosyada taze random ürettiği için bu sağlanır.
    let (subkey_raw, iv) = derive_chunk_keys(dek, file_id, chunk_index);
    let subkey = Zeroizing::new(subkey_raw);

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

    // Derive subkey using derive_chunk_keys (the subkey is the first 32 bytes of the output).
    // Zeroizing guarantees zeroization on scope exit.
    let subkey = Zeroizing::new(derive_chunk_keys(dek, file_id, chunk_index).0);

    let mut aad = [0u8; 20];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());

    // We decrypt using the IV stored in the envelope, not assuming it matches the deterministic IV
    let plaintext = aes256_gcm_decrypt(
        &subkey,
        &envelope.iv,
        &aad,
        &envelope.ciphertext,
        &envelope.tag,
    )?;

    Ok(plaintext)
}

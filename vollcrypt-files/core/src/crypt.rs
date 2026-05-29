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
    header_hash: Option<&[u8; 32]>,
) -> Result<ChunkEnvelope, FileFormatError> {
    let (subkey_raw, iv) = derive_chunk_keys(dek, file_id, chunk_index);
    let subkey = Zeroizing::new(subkey_raw);

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    let (ciphertext, tag) = aes256_gcm_encrypt(&subkey, &iv, aad_slice, plaintext)?;

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
    header_hash: Option<&[u8; 32]>,
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

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    // We decrypt using the IV stored in the envelope, not assuming it matches the deterministic IV
    let plaintext = aes256_gcm_decrypt(
        &subkey,
        &envelope.iv,
        aad_slice,
        &envelope.ciphertext,
        &envelope.tag,
    )?;

    Ok(plaintext)
}

/// Encrypts a single plaintext chunk asynchronously.
pub async fn encrypt_chunk_async(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    plaintext: Vec<u8>,
    header_hash: Option<&[u8; 32]>,
) -> Result<ChunkEnvelope, FileFormatError> {
    let (subkey_raw, iv) = derive_chunk_keys(dek, file_id, chunk_index);
    let subkey = zeroize::Zeroizing::new(subkey_raw);

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    let (ciphertext, tag) =
        crate::aead::aes256_gcm_encrypt_async(&subkey, &iv, aad_slice, plaintext).await?;

    Ok(ChunkEnvelope {
        chunk_index,
        iv,
        ciphertext,
        tag,
    })
}

/// Decrypts a single chunk from a `ChunkEnvelope` asynchronously.
pub async fn decrypt_chunk_async(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    envelope: ChunkEnvelope,
    header_hash: Option<&[u8; 32]>,
) -> Result<Vec<u8>, FileFormatError> {
    if envelope.chunk_index != chunk_index {
        return Err(FileFormatError::ChunkIndexOutOfOrder {
            expected: chunk_index,
            got: envelope.chunk_index,
        });
    }

    let subkey = zeroize::Zeroizing::new(derive_chunk_keys(dek, file_id, chunk_index).0);

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    let plaintext = crate::aead::aes256_gcm_decrypt_async(
        &subkey,
        &envelope.iv,
        aad_slice,
        envelope.ciphertext,
        envelope.tag,
    )
    .await?;

    Ok(plaintext)
}

/// Encrypts a chunk in place inside a PooledBuffer.
pub fn encrypt_chunk_in_place(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    buffer: &mut crate::buffer_pool::PooledBuffer,
    plaintext_len: usize,
    header_hash: Option<&[u8; 32]>,
) -> Result<(), FileFormatError> {
    let (subkey_raw, iv) = derive_chunk_keys(dek, file_id, chunk_index);
    let subkey = Zeroizing::new(subkey_raw);

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    buffer.set_index(chunk_index);
    buffer.set_iv(&iv);

    let tag = crate::aead::aes256_gcm_encrypt_in_place(
        &subkey,
        &iv,
        aad_slice,
        buffer.as_plaintext_mut(plaintext_len),
    )?;

    *buffer.as_tag_mut(plaintext_len) = tag;

    Ok(())
}

/// Decrypts a chunk in place inside a PooledBuffer.
pub fn decrypt_chunk_in_place(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    buffer: &mut crate::buffer_pool::PooledBuffer,
    ciphertext_len: usize,
    header_hash: Option<&[u8; 32]>,
) -> Result<(), FileFormatError> {
    let got_index = buffer.get_index();
    if got_index != chunk_index {
        return Err(FileFormatError::ChunkIndexOutOfOrder {
            expected: chunk_index,
            got: got_index,
        });
    }

    let subkey = Zeroizing::new(derive_chunk_keys(dek, file_id, chunk_index).0);

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    let iv = *buffer.get_iv();
    let tag = *buffer.as_tag_slice(ciphertext_len);

    crate::aead::aes256_gcm_decrypt_in_place(
        &subkey,
        &iv,
        aad_slice,
        buffer.as_ciphertext_mut(ciphertext_len),
        &tag,
    )?;

    Ok(())
}

/// Encrypts a chunk in place asynchronously inside a PooledBuffer.
pub async fn encrypt_chunk_in_place_async(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    buffer: crate::buffer_pool::PooledBuffer,
    plaintext_len: usize,
    header_hash: Option<&[u8; 32]>,
) -> Result<(crate::buffer_pool::PooledBuffer, [u8; 16]), FileFormatError> {
    let (subkey_raw, iv) = derive_chunk_keys(dek, file_id, chunk_index);
    let subkey = Zeroizing::new(subkey_raw);

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    let mut buffer = buffer;
    buffer.set_index(chunk_index);
    buffer.set_iv(&iv);

    let (mut buffer, tag) = crate::aead::aes256_gcm_encrypt_in_place_async(
        &subkey,
        &iv,
        aad_slice,
        buffer,
        plaintext_len,
    )
    .await?;

    *buffer.as_tag_mut(plaintext_len) = tag;

    Ok((buffer, tag))
}

/// Decrypts a chunk in place asynchronously inside a PooledBuffer.
pub async fn decrypt_chunk_in_place_async(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    buffer: crate::buffer_pool::PooledBuffer,
    ciphertext_len: usize,
    tag: [u8; 16],
    header_hash: Option<&[u8; 32]>,
) -> Result<crate::buffer_pool::PooledBuffer, FileFormatError> {
    let got_index = buffer.get_index();
    if got_index != chunk_index {
        return Err(FileFormatError::ChunkIndexOutOfOrder {
            expected: chunk_index,
            got: got_index,
        });
    }

    let subkey = Zeroizing::new(derive_chunk_keys(dek, file_id, chunk_index).0);

    let mut aad = [0u8; 52];
    aad[0..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    let aad_slice = if let Some(hash) = header_hash {
        aad[20..52].copy_from_slice(hash);
        &aad[0..52]
    } else {
        &aad[0..20]
    };

    let iv = *buffer.get_iv();

    let buffer = crate::aead::aes256_gcm_decrypt_in_place_async(
        &subkey,
        &iv,
        aad_slice,
        buffer,
        ciphertext_len,
        tag,
    )
    .await?;

    Ok(buffer)
}

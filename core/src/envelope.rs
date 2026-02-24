//! Message Envelope structures and formatting.
//! The envelope binary format used in VollChat is:
//! [window_index:4B][IV:12B][AAD_hash:32B][ciphertext][auth_tag:16B]

/// Packs the encryption output into the standard VollChat binary envelope.
/// `encrypted_blob` comes from `encrypt_aes256gcm` and has the form `[IV:12B][ciphertext][auth_tag:16B]`.
pub fn pack_envelope(
    window_index: u32,
    aad_hash: &[u8; 32],
    encrypted_blob: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if encrypted_blob.len() < 12 + 16 {
        return Err("Encrypted blob too small, must contain at least IV and auth tag");
    }
    let mut out = Vec::with_capacity(4 + 12 + 32 + encrypted_blob.len() - 12);
    out.extend_from_slice(&window_index.to_be_bytes());
    out.extend_from_slice(&encrypted_blob[0..12]);
    out.extend_from_slice(aad_hash);
    out.extend_from_slice(&encrypted_blob[12..]);
    Ok(out)
}

/// Unpacks a standard VollChat binary envelope.
/// Returns (window_index, aad_hash, encrypted_blob).
/// `encrypted_blob` can be passed directly to `decrypt_aes256gcm`.
pub fn unpack_envelope(envelope: &[u8]) -> Result<(u32, [u8; 32], Vec<u8>), &'static str> {
    if envelope.len() < 4 + 12 + 32 + 16 {
        return Err("Envelope too small");
    }
    
    let mut window_index_bytes = [0u8; 4];
    window_index_bytes.copy_from_slice(&envelope[0..4]);
    let window_index = u32::from_be_bytes(window_index_bytes);

    let iv = &envelope[4..16];
    
    let mut aad_hash = [0u8; 32];
    aad_hash.copy_from_slice(&envelope[16..48]);

    let ciphertext_with_tag = &envelope[48..];

    // Reconstruct encrypted blob for decrypt_aes256gcm: [IV][Ciphertext][Tag]
    let mut encrypted_blob = Vec::with_capacity(12 + ciphertext_with_tag.len());
    encrypted_blob.extend_from_slice(iv);
    encrypted_blob.extend_from_slice(ciphertext_with_tag);

    Ok((window_index, aad_hash, encrypted_blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_packing() {
        let window_index = 100u32;
        let aad_hash = [0x55u8; 32];
        let mut mock_encrypted_blob = vec![0x00u8; 12]; // IV
        mock_encrypted_blob.extend_from_slice(b"ciphertext_body!"); // Cipher + Tag (16)
        
        let envelope = pack_envelope(window_index, &aad_hash, &mock_encrypted_blob).unwrap();
        assert_eq!(envelope.len(), 4 + 12 + 32 + 16);

        let (unpacked_window, unpacked_aad, unpacked_blob) = unpack_envelope(&envelope).unwrap();
        assert_eq!(unpacked_window, window_index);
        assert_eq!(unpacked_aad, aad_hash);
        assert_eq!(unpacked_blob, mock_encrypted_blob);
    }
}

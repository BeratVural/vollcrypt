use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a chunk-specific subkey using HKDF-SHA256.
///
/// * `dek`: The Data Encryption Key (IKM).
/// * `file_id`: The unique file identifier (Salt).
/// * `chunk_index`: The index of the chunk.
///
/// Returns a derived 32-byte subkey. The caller is responsible for zeroizing the output subkey when done.
pub fn derive_chunk_subkey(dek: &[u8; 32], file_id: &[u8; 16], chunk_index: u32) -> [u8; 32] {
    let mut info = [0u8; 27];
    info[0..23].copy_from_slice(b"vollcrypt-file-chunk-v1");
    info[23..27].copy_from_slice(&chunk_index.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(file_id), dek);
    let mut subkey = [0u8; 32];

    // hk.expand will only fail if the requested length is too large (i.e. > 255 * 32).
    // Here we request 32 bytes, which is well within limits. We handle the error gracefully without unwrapping/panicking.
    if hk.expand(&info, &mut subkey).is_err() {
        // Fallback to zeros if it ever fails
        subkey = [0u8; 32];
    }

    subkey
}

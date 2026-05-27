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

/// Derives a Key Encrypting Key (KEK) using PBKDF2-HMAC-SHA256.
///
/// * `password`: The input password.
/// * `salt`: The 16-byte KDF salt.
/// * `iterations`: The number of PBKDF2 iterations.
///
/// If iterations is 0, it debug_asserts in debug mode and is forced to 1 in production mode.
pub fn derive_kek_pbkdf2(password: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    debug_assert!(iterations > 0, "iterations must be greater than 0");
    let iter = if iterations == 0 { 1 } else { iterations };

    let mut kek = [0u8; 32];
    use pbkdf2::hmac::Hmac;
    // pbkdf2 is infallible under normal parameters and does not return a result.
    let _ = pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iter, &mut kek);

    kek
}

/// Derives a Key Encrypting Key (KEK) using Argon2id.
///
/// * `password`: The input password.
/// * `salt`: The 16-byte KDF salt.
/// * `m_cost`: Memory cost.
/// * `t_cost`: Time cost.
/// * `p_cost`: Parallelism cost.
pub fn derive_kek_argon2id(
    password: &[u8],
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], crate::error::FileFormatError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| crate::error::FileFormatError::KdfParameterOutOfRange(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut kek)
        .map_err(|e| crate::error::FileFormatError::KdfParameterOutOfRange(e.to_string()))?;

    Ok(kek)
}

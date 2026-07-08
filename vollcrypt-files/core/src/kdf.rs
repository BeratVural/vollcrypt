use hkdf::Hkdf;
use sha2::Sha256;
use crate::error::FileFormatError;

#[cfg(test)]
thread_local! {
    pub static INJECT_KDF_ERROR: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

/// Derives a chunk-specific subkey using HKDF-SHA256.
///
/// * `dek`: The Data Encryption Key (IKM).
/// * `file_id`: The unique file identifier (Salt).
/// * `chunk_index`: The index of the chunk.
///
/// Returns a derived 32-byte subkey. The caller is responsible for zeroizing the output subkey when done.
pub fn derive_chunk_subkey(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
) -> Result<[u8; 32], FileFormatError> {
    #[cfg(test)]
    if INJECT_KDF_ERROR.with(|h| h.get()) {
        return Err(FileFormatError::IntegrityError("HKDF expansion failed for subkey (injected)".to_string()));
    }

    let mut info = [0u8; 27];
    info[0..23].copy_from_slice(b"vollcrypt-file-chunk-v1");
    info[23..27].copy_from_slice(&chunk_index.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(file_id), dek);
    let mut subkey = [0u8; 32];

    hk.expand(&info, &mut subkey)
        .map_err(|_| FileFormatError::IntegrityError("HKDF expansion failed for subkey".to_string()))?;

    Ok(subkey)
}

/// Derives a Key Encrypting Key (KEK) using PBKDF2-HMAC-SHA256.
///
/// * `password`: The input password.
/// * `salt`: The 16-byte KDF salt.
/// * `iterations`: The number of PBKDF2 iterations.
///
/// If iterations is 0, it debug_asserts in debug mode and is forced to 1 in production mode.
pub fn derive_kek_pbkdf2(password: &[u8], salt: &[u8; 16], iterations: u32) -> Result<[u8; 32], FileFormatError> {
    if iterations < 1_000 || iterations > 5_000_000 {
        return Err(FileFormatError::KdfParameterOutOfRange(format!(
            "PBKDF2 iterations out of safety bounds: {}",
            iterations
        )));
    }

    let mut kek = [0u8; 32];
    use pbkdf2::hmac::Hmac;
    let _ = pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut kek);

    Ok(kek)
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

    if m_cost < 8 || m_cost > 262144 || t_cost < 1 || t_cost > 5 || p_cost < 1 || p_cost > 8 {
        return Err(crate::error::FileFormatError::KdfParameterOutOfRange(
            format!(
                "Argon2 parameters exceed safety limits: m_cost={}, t_cost={}, p_cost={}",
                m_cost, t_cost, p_cost
            ),
        ));
    }

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| crate::error::FileFormatError::KdfParameterOutOfRange(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut kek)
        .map_err(|e| crate::error::FileFormatError::KdfParameterOutOfRange(e.to_string()))?;

    Ok(kek)
}

/// Derives both a chunk subkey and a chunk IV deterministically from the DEK using HKDF-SHA256.
///
/// * `dek`: The Data Encryption Key (IKM).
/// * `file_id`: The unique file identifier (Salt).
/// * `chunk_index`: The index of the chunk.
///
/// Returns a tuple containing the 32-byte derived subkey and 12-byte derived IV.
/// The subkey contains sensitive key material and should be zeroized after use.
pub fn derive_chunk_keys(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
) -> Result<([u8; 32], [u8; 12]), FileFormatError> {
    #[cfg(test)]
    if INJECT_KDF_ERROR.with(|h| h.get()) {
        return Err(FileFormatError::IntegrityError("HKDF expansion failed for chunk keys (injected)".to_string()));
    }

    let mut info = [0u8; 27];
    info[0..23].copy_from_slice(b"vollcrypt-file-chunk-v1");
    info[23..27].copy_from_slice(&chunk_index.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(file_id), dek);
    let mut okm = [0u8; 44];

    hk.expand(&info, &mut okm)
        .map_err(|_| FileFormatError::IntegrityError("HKDF expansion failed for chunk keys".to_string()))?;

    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&okm[0..32]);

    let mut iv = [0u8; 12];
    iv.copy_from_slice(&okm[32..44]);

    Ok((subkey, iv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_error_injection() {
        INJECT_KDF_ERROR.with(|h| h.set(true));
        let dek = [1u8; 32];
        let file_id = [2u8; 16];
        let res_subkey = derive_chunk_subkey(&dek, &file_id, 0);
        let res_keys = derive_chunk_keys(&dek, &file_id, 0);
        INJECT_KDF_ERROR.with(|h| h.set(false));

        assert!(res_subkey.is_err());
        assert!(res_keys.is_err());
    }
}

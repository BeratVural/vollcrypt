use crate::error::FileFormatError;
use aes_kw::KekAes256;

/// Wraps a 32-byte Data Encryption Key (DEK) with a 32-byte Key Encrypting Key (KEK) using AES-256-KW.
///
/// Output is exactly 40 bytes (8-byte IV + 32-byte wrapped key).
pub fn aes256_kw_wrap(kek: &[u8; 32], dek: &[u8; 32]) -> Result<[u8; 40], FileFormatError> {
    let kek_obj = KekAes256::from(*kek);
    let mut out = [0u8; 40];
    let wrapped = kek_obj
        .wrap_vec(dek)
        .map_err(|_| FileFormatError::KeyWrapFailed)?;
    if wrapped.len() != out.len() {
        return Err(FileFormatError::KeyWrapFailed);
    }
    out.copy_from_slice(&wrapped);
    Ok(out)
}

/// Unwraps a 40-byte wrapped DEK using a 32-byte Key Encrypting Key (KEK).
///
/// Returns the unwrapped 32-byte DEK. If unwrap fails (e.g. invalid KEK/integrity check),
/// returns `FileFormatError::WrongPassword`.
pub fn aes256_kw_unwrap(kek: &[u8; 32], wrapped: &[u8; 40]) -> Result<[u8; 32], FileFormatError> {
    let kek_obj = KekAes256::from(*kek);

    let unwrapped_vec = kek_obj
        .unwrap_vec(wrapped)
        .map_err(|_| FileFormatError::WrongPassword)?;

    let mut dek = [0u8; 32];
    if unwrapped_vec.len() != 32 {
        return Err(FileFormatError::WrongPassword);
    }
    dek.copy_from_slice(&unwrapped_vec);

    Ok(dek)
}

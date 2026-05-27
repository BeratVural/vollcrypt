use crate::error::FileFormatError;
use crate::wrap::WrapEntry;
use rand::rngs::OsRng;
use rand::RngCore;

/// Generates a cryptographically secure random 32-byte Group Key (GK).
pub fn generate_gk() -> [u8; 32] {
    let mut gk = [0u8; 32];
    OsRng.fill_bytes(&mut gk);
    gk
}

/// Wraps a DEK using the Group Key (GK) as the key-wrapping key (KEK).
///
/// Returns a `WrapEntry::GroupWrap` containing the group metadata and wrapped key.
pub fn wrap_dek_for_group(
    dek: &[u8; 32],
    group_id: [u8; 16],
    gk_version: u32,
    gk: &[u8; 32],
) -> WrapEntry {
    let wrapped_dek = crate::keywrap::aes256_kw_wrap(gk, dek);

    WrapEntry::GroupWrap {
        group_id,
        gk_version,
        wrapped_dek,
    }
}

/// Unwraps the DEK from a `WrapEntry::GroupWrap` using the Group Key (GK).
pub fn unwrap_dek_with_group_key(
    wrap: &WrapEntry,
    gk: &[u8; 32],
) -> Result<[u8; 32], FileFormatError> {
    match wrap {
        WrapEntry::GroupWrap {
            group_id: _,
            gk_version: _,
            wrapped_dek,
        } => crate::keywrap::aes256_kw_unwrap(gk, wrapped_dek).map_err(|e| {
            if matches!(e, FileFormatError::WrongPassword) {
                FileFormatError::WrongGroupKey
            } else {
                e
            }
        }),
        _ => Err(FileFormatError::WrongWrapType),
    }
}

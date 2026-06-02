use crate::error::FileFormatError;
use crate::kdf::{derive_kek_argon2id, derive_kek_pbkdf2};
use crate::keywrap::{aes256_kw_unwrap, aes256_kw_wrap};
use crate::random::generate_salt;
use crate::wrap::WrapEntry;
use zeroize::Zeroize;

/// The KDF choice and parameters to use for password-based KEK derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfChoice {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
}

impl KdfChoice {
    /// PBKDF2 default parameter set (600,000 iterations).
    pub fn pbkdf2_default() -> Self {
        Self::Pbkdf2 {
            iterations: 600_000,
        }
    }

    /// Argon2id default parameter set (65,536 KB memory, 3 iterations, 4 parallelism).
    pub fn argon2id_default() -> Self {
        Self::Argon2id {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }

    /// Argon2id interactive parameter set (19,456 KB memory, 2 iterations, 1 parallelism).
    pub fn argon2id_interactive() -> Self {
        Self::Argon2id {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// Derives a KEK from a password and wraps the DEK using AES-256-KW.
///
/// Returns a `WrapEntry` configuration containing the parameters, salt, and wrapped DEK.
pub fn wrap_dek_with_password(
    dek: &[u8; 32],
    password: &[u8],
    kdf: KdfChoice,
) -> Result<WrapEntry, FileFormatError> {
    let salt = generate_salt();

    let entry = match kdf {
        KdfChoice::Pbkdf2 { iterations } => {
            let mut kek = derive_kek_pbkdf2(password, &salt, iterations);
            let wrapped_dek = aes256_kw_wrap(&kek, dek);
            kek.zeroize();

            WrapEntry::PasswordPbkdf2 {
                iterations,
                salt,
                wrapped_dek,
            }
        }
        KdfChoice::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        } => {
            let mut kek = derive_kek_argon2id(password, &salt, m_cost, t_cost, p_cost)?;
            let wrapped_dek = aes256_kw_wrap(&kek, dek);
            kek.zeroize();

            WrapEntry::PasswordArgon2id {
                m_cost,
                t_cost,
                p_cost,
                salt,
                wrapped_dek,
            }
        }
    };

    Ok(entry)
}

/// Unwraps the DEK from a password-based `WrapEntry`.
///
/// Returns the unwrapped 32-byte DEK.
pub fn unwrap_dek_with_password(
    wrap: &WrapEntry,
    password: &[u8],
) -> Result<[u8; 32], FileFormatError> {
    match wrap {
        WrapEntry::PasswordPbkdf2 {
            iterations,
            salt,
            wrapped_dek,
        } => {
            let mut kek = derive_kek_pbkdf2(password, salt, *iterations);
            let dek_res = aes256_kw_unwrap(&kek, wrapped_dek);
            kek.zeroize();
            dek_res
        }
        WrapEntry::PasswordArgon2id {
            m_cost,
            t_cost,
            p_cost,
            salt,
            wrapped_dek,
        } => {
            let mut kek = derive_kek_argon2id(password, salt, *m_cost, *t_cost, *p_cost)?;
            let dek_res = aes256_kw_unwrap(&kek, wrapped_dek);
            kek.zeroize();
            dek_res
        }
        WrapEntry::HybridKem { .. } | WrapEntry::GroupWrap { .. } | WrapEntry::Threshold { .. } => {
            Err(FileFormatError::WrongWrapType)
        }
    }
}

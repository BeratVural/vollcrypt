pub mod bip39;
pub mod kdf;
pub mod keys;
pub mod symmetric;

// Re-export common functions directly
pub use crate::bip39::{generate_mnemonic, mnemonic_to_seed};
pub use kdf::{derive_hkdf, derive_pbkdf2, derive_srk, derive_window_key};
pub use keys::{
    ecdh_shared_secret, generate_ed25519_keypair, generate_x25519_keypair, sign_message,
    verify_signature,
};
pub use symmetric::{decrypt_aes256gcm, encrypt_aes256gcm};

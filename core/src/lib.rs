pub mod bip39;
pub mod kdf;
pub mod keys;
pub mod symmetric;
pub mod wrap;
pub mod padding;
pub mod envelope;

// Re-export common functions directly
pub use bip39::{generate_mnemonic, mnemonic_to_seed};
pub use kdf::{derive_hkdf, derive_pbkdf2, derive_srk, derive_window_key};
pub use keys::{
    ecdh_shared_secret, generate_ed25519_keypair, generate_x25519_keypair, sign_message,
    verify_signature,
};
pub use symmetric::{decrypt_aes256gcm, encrypt_aes256gcm};
pub use wrap::{wrap_key, unwrap_key};
pub use padding::pad_message;
pub use envelope::{pack_envelope, unpack_envelope};

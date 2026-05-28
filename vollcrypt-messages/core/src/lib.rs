pub mod bip39;
pub mod device;
pub mod envelope;
pub mod kdf;
pub mod key_log;
pub mod keys;
pub mod padding;
pub mod pqc;
pub mod ratchet;
pub mod sealed_sender;
pub mod symmetric;
pub mod transcript;
pub mod verification;
pub mod wrap;

// Re-export common functions directly
pub use bip39::{generate_mnemonic, mnemonic_to_seed};
pub use device::{DefaultDeviceRegistry, Device};
pub use envelope::{pack_envelope, unpack_envelope};
pub use kdf::{derive_hkdf, derive_pbkdf2, derive_srk, derive_window_key};
pub use keys::{
    ecdh_shared_secret, generate_ed25519_keypair, generate_x25519_keypair, sign_message,
    verify_signature,
};
pub use padding::pad_message;
pub use pqc::{
    hybrid_kem_decapsulate, hybrid_kem_encapsulate, ml_kem_decapsulate, ml_kem_encapsulate,
    ml_kem_keygen,
};
pub use ratchet::{
    CryptoError, RatchetConfig, RatchetKeyPair, RatchetOutput, generate_ratchet_keypair,
    ratchet_srk_receiver, ratchet_srk_sender, should_ratchet,
};
pub use symmetric::{
    decrypt_aes256gcm, decrypt_aes256gcm_chunked, decrypt_aes256gcm_chunked_padded,
    decrypt_aes256gcm_padded, encrypt_aes256gcm, encrypt_aes256gcm_chunked,
    encrypt_aes256gcm_chunked_padded, encrypt_aes256gcm_padded,
};
pub use transcript::TranscriptState;
pub use wrap::{unwrap_key, wrap_key};

#[cfg(test)]
mod tests {
    mod adversarial;
}

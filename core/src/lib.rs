pub mod bip39;
pub mod kdf;
pub mod keys;
pub mod symmetric;
pub mod wrap;
pub mod padding;
pub mod envelope;
pub mod pqc;
pub mod device;
pub mod ratchet;
pub mod transcript;
pub mod sealed_sender;

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
pub use pqc::{
    ml_kem_keygen, ml_kem_encapsulate, ml_kem_decapsulate,
    hybrid_kem_encapsulate, hybrid_kem_decapsulate,
};
pub use device::{Device, DefaultDeviceRegistry};
pub use ratchet::{
    generate_ratchet_keypair, ratchet_srk_sender, ratchet_srk_receiver, should_ratchet,
    RatchetKeyPair, RatchetOutput, RatchetConfig, CryptoError,
};
pub use transcript::TranscriptState;

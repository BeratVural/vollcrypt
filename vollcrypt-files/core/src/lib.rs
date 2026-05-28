pub mod aead;
pub mod chunk;
pub mod constants;
pub mod crypt;
pub mod error;
pub mod group;
pub mod header;
pub mod kdf;
pub mod keylog;
pub mod keywrap;
pub mod manifest;
pub mod merkle;
pub mod password;
pub mod pqc;
pub mod random;
pub mod recipient;
pub mod resolver;
pub mod signature;
pub mod signing;
pub mod wrap;
pub mod pipelined_io;

pub use aead::{aes256_gcm_decrypt, aes256_gcm_encrypt};
pub use chunk::ChunkEnvelope;
pub use constants::{DEFAULT_CHUNK_SIZE, FIXED_HEADER_LEN, MAGIC, VERSION};
pub use crypt::{decrypt_chunk, encrypt_chunk};
pub use error::FileFormatError;
pub use group::{
    crypto_shred_header, generate_gk, rewrap_dek_in_header, unwrap_dek_with_group_key,
    wrap_dek_for_group,
};
pub use header::{CipherId, Header, Mode, SignedMetadata};
pub use kdf::{derive_chunk_keys, derive_chunk_subkey, derive_kek_argon2id, derive_kek_pbkdf2};
pub use keylog::{KeyLog, KeyLogEntry, KeyLogEntryType};
pub use keywrap::{aes256_kw_unwrap, aes256_kw_wrap};
pub use manifest::{GroupManifest, Operation, SignedOperation};
pub use merkle::{
    check_proof_length, chunk_leaf_hash, chunk_leaf_hash_with_algo, expected_proof_len,
    verify_merkle_proof, verify_merkle_proof_with_algo, HashAlgorithm, MerkleTree,
};
pub use password::{unwrap_dek_with_password, wrap_dek_with_password, KdfChoice};
pub use random::{generate_dek, generate_file_id, generate_salt};
pub use recipient::{
    generate_recipient_keypair, unwrap_key_with_recipient_key, wrap_key_to_recipient,
    RecipientPublicKey, RecipientSecretKey,
};
pub use resolver::{resolve_sender, SenderInfo};
pub use signature::{
    sign_header_plain, sign_header_sealed, verify_header_signature_plain,
    verify_header_signature_sealed,
};
pub use signing::{ed25519_keypair_generate, ed25519_sign, ed25519_verify};
pub use wrap::WrapEntry;
pub use pipelined_io::{encrypt_file_pipelined, decrypt_file_pipelined, PipelinedSignInfo};

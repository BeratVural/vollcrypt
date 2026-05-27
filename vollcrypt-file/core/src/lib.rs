pub mod aead;
pub mod chunk;
pub mod constants;
pub mod crypt;
pub mod error;
pub mod header;
pub mod kdf;
pub mod merkle;
pub mod wrap;

pub use aead::{aes256_gcm_decrypt, aes256_gcm_encrypt};
pub use chunk::ChunkEnvelope;
pub use constants::{DEFAULT_CHUNK_SIZE, FIXED_HEADER_LEN, MAGIC, VERSION};
pub use crypt::{decrypt_chunk, encrypt_chunk};
pub use error::FileFormatError;
pub use header::{CipherId, Header, Mode};
pub use kdf::derive_chunk_subkey;
pub use merkle::{
    check_proof_length, chunk_leaf_hash, expected_proof_len, verify_merkle_proof, MerkleTree,
};
pub use wrap::WrapEntry;

pub mod aead;
pub mod chunk;
pub mod constants;
pub mod crypt;
pub mod error;
pub mod header;
pub mod kdf;
pub mod keywrap;
pub mod merkle;
pub mod password;
pub mod random;
pub mod wrap;

pub use aead::{aes256_gcm_decrypt, aes256_gcm_encrypt};
pub use chunk::ChunkEnvelope;
pub use constants::{DEFAULT_CHUNK_SIZE, FIXED_HEADER_LEN, MAGIC, VERSION};
pub use crypt::{decrypt_chunk, encrypt_chunk};
pub use error::FileFormatError;
pub use header::{CipherId, Header, Mode};
pub use kdf::{derive_chunk_subkey, derive_kek_argon2id, derive_kek_pbkdf2};
pub use keywrap::{aes256_kw_unwrap, aes256_kw_wrap};
pub use merkle::{
    check_proof_length, chunk_leaf_hash, expected_proof_len, verify_merkle_proof, MerkleTree,
};
pub use password::{unwrap_dek_with_password, wrap_dek_with_password, KdfChoice};
pub use random::{generate_dek, generate_file_id, generate_salt};
pub use wrap::WrapEntry;

pub mod aead;
pub mod buffer_pool;
pub mod chunk;
pub mod constants;
pub mod crypt;
pub mod error;
pub mod group;
pub mod header;
pub mod hybrid_sig;
pub mod kdf;
pub mod keylog;
pub mod keywrap;
pub mod manifest;
pub mod merkle;
pub mod mldsa;
pub mod password;
pub mod pipelined_io;
pub mod pqc;
pub mod provider;
pub mod random;
pub mod recipient;
pub mod resolver;
pub mod signature;
pub mod signing;
#[cfg(target_arch = "wasm32")]
pub mod web_crypto;
pub mod wrap;
pub mod writer;

pub use aead::{
    aes256_gcm_decrypt, aes256_gcm_decrypt_async, aes256_gcm_decrypt_in_place,
    aes256_gcm_decrypt_in_place_async, aes256_gcm_encrypt, aes256_gcm_encrypt_async,
    aes256_gcm_encrypt_in_place, aes256_gcm_encrypt_in_place_async,
};
pub use buffer_pool::{BufferPool, PooledBuffer};
pub use chunk::ChunkEnvelope;
pub use constants::{DEFAULT_CHUNK_SIZE, FIXED_HEADER_LEN, MAGIC, VERSION};
pub use crypt::{
    decrypt_chunk, decrypt_chunk_async, decrypt_chunk_in_place, decrypt_chunk_in_place_async,
    encrypt_chunk, encrypt_chunk_async, encrypt_chunk_in_place, encrypt_chunk_in_place_async,
};
pub use provider::{
    get_crypto_provider, set_crypto_provider, CryptoProvider, NativeCryptoProvider,
};
#[cfg(target_arch = "wasm32")]
pub use web_crypto::WasmWebCryptoProvider;
pub use writer::{
    write_raw_at, BatchedChunkWriter, ChunkWriter, DirectOffsetChunkWriter, IoWriteMode,
    SequentialChunkWriter,
};

pub use error::FileFormatError;
pub use group::{
    crypto_shred_header, generate_gk, rewrap_dek_in_header, unwrap_dek_with_group_key,
    wrap_dek_for_group,
};
pub use header::{CipherId, Header, Mode, SignedMetadata};
pub use kdf::{derive_chunk_keys, derive_chunk_subkey, derive_kek_argon2id, derive_kek_pbkdf2};
pub use keylog::{KeyLog, KeyLogEntry, KeyLogEntryType};
pub use keywrap::{aes256_kw_unwrap, aes256_kw_wrap};
pub use manifest::{
    detect_equivocation, manifest_head, verify_manifest_with_pin, verify_manifest_with_pin_policy,
    verify_manifest, EquivocationResult, GroupManifest, Operation, SignedOperation,
    RollbackCheck, FounderAnchor,
};
pub use merkle::{
    bind_root_with_length, check_proof_length, chunk_leaf_hash, chunk_leaf_hash_raw,
    chunk_leaf_hash_raw_with_algo, chunk_leaf_hash_with_algo, default_hash_algorithm,
    detect_sha_ni_support, expected_proof_len, verify_merkle_proof, verify_merkle_proof_with_algo,
    HashAlgorithm, MerkleTree, StreamingMerkle,
};
pub use password::{unwrap_dek_with_password, wrap_dek_with_password, KdfChoice};
pub use pipelined_io::{
    decrypt_file_pipelined, decrypt_verified, decrypt_streaming_online,
    encrypt_file_pipelined, PipelinedSignInfo,
};
pub use random::{generate_dek, generate_file_id, generate_salt};
pub use recipient::{
    generate_recipient_keypair, unwrap_key_with_recipient_key, wrap_key_to_recipient,
    RecipientPublicKey, RecipientSecretKey,
};
pub use resolver::{resolve_sender, SenderInfo};
pub use signature::{
    sign_header_plain, sign_header_sealed, verify_header_signature_plain,
    verify_header_signature_plain_policy, verify_header_signature_sealed,
    verify_header_signature_sealed_policy, VerificationPolicy,
};
pub use signing::{ed25519_keypair_generate, ed25519_sign, ed25519_verify};
pub use hybrid_sig::{
    hybrid_keypair_generate, hybrid_sign, hybrid_verify, HybridPublicKey, HybridSecretKey,
    HybridSignature,
};
pub use wrap::WrapEntry;


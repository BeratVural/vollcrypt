pub const MAGIC: [u8; 8] = *b"VOLLVALT";
pub const VERSION: u8 = 1;
pub const DEFAULT_CHUNK_SIZE: u32 = 4_194_304;
pub const FIXED_HEADER_LEN: usize = 80;

pub const CHUNK_ENVELOPE_OVERHEAD: usize = 32;

pub const ML_KEM_768_ENCAPSULATION_KEY_SIZE: usize = 1_184;
pub const ML_KEM_768_DECAPSULATION_KEY_SIZE: usize = 2_400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1_088;

pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1_952;
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4_032;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3_309;

pub const HYBRID_PUBLIC_KEY_SIZE: usize = 32 + ML_DSA_65_PUBLIC_KEY_SIZE;
pub const HYBRID_SECRET_KEY_SIZE: usize = 32 + ML_DSA_65_SECRET_KEY_SIZE;

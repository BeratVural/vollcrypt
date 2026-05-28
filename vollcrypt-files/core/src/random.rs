use rand::rngs::OsRng;
use rand::RngCore;

/// Generates a cryptographically secure random 32-byte Data Encryption Key (DEK).
pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut dek);
    dek
}

/// Generates a cryptographically secure random 16-byte file identifier.
pub fn generate_file_id() -> [u8; 16] {
    let mut file_id = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut file_id);
    file_id
}

/// Generates a cryptographically secure random 16-byte salt for KDF.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    salt
}

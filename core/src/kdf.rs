use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;

/// Derives a key using PBKDF2-HMAC-SHA256.
/// Useful for legacy compatibility or when a password is the source.
/// Default VollChat config: Iterations = 100,000, Key Length = 32 bytes (for AES-256)
pub fn derive_pbkdf2(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut derived_key = vec![0u8; key_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut derived_key);

    // We expect the caller to securely zeroize the output key when they are done,
    // but the intermediate pbkdf2 implementation handles its own memory safely.
    derived_key
}

/// Derives a key using HKDF-SHA256.
/// Useful for deriving symmetric keys from high-entropy sources like an ECDH Shared Secret.
/// Info is optional application-specific context (e.g., "vollchat-e2ee-v1").
pub fn derive_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    key_len: usize,
) -> Result<Vec<u8>, &'static str> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; key_len];

    hk.expand(info.unwrap_or(b""), &mut okm)
        .map_err(|_| "HKDF expansion failed (length too long)")?;

    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2() {
        let pw = b"my_secure_password";
        let salt = b"some_random_salt";

        let key1 = derive_pbkdf2(pw, salt, 10_000, 32);
        let key2 = derive_pbkdf2(pw, salt, 10_000, 32);

        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2);

        let key_different_salt = derive_pbkdf2(pw, b"other_salt", 10_000, 32);
        assert_ne!(key1, key_different_salt);
    }

    #[test]
    fn test_hkdf() {
        let ecdh_secret = b"a_very_random_shared_secret_1234";
        let salt = b"handshake_salt";

        let key1 = derive_hkdf(ecdh_secret, Some(salt), Some(b"vollchat-enc"), 32).unwrap();
        let key2 = derive_hkdf(ecdh_secret, Some(salt), Some(b"vollchat-enc"), 32).unwrap();
        let key_mac = derive_hkdf(ecdh_secret, Some(salt), Some(b"vollchat-mac"), 32).unwrap();

        assert_eq!(key1, key2);
        assert_ne!(key1, key_mac); // Different info context generates unique keys
    }
}

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;

/// Derives a key using PBKDF2-HMAC-SHA256.
/// Useful for legacy compatibility or when a password is the source.
/// Default VollChat config: Iterations = 100,000, Key Length = 32 bytes (for AES-256)
///
/// # Security
/// The returned key material is sensitive. Caller must call `.zeroize()` 
/// on the returned `Vec<u8>` after use to prevent key material from 
/// remaining in memory.
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
///
/// # Security
/// The returned key material is sensitive. Caller must call `.zeroize()` 
/// on the returned `Vec<u8>` after use to prevent key material from 
/// remaining in memory.
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

/// Derives a Session Root Key (SRK) from a DEK and a conversation identifier.
/// 
/// The SRK is unique per conversation and never leaves the client.
/// It is used as input material for window key derivation.
///
/// # Arguments
/// * `dek` - Data Encryption Key (32 bytes)
/// * `chat_id` - Unique conversation identifier (arbitrary bytes)
///
/// # Security
/// Caller must zeroize the returned Vec<u8> after use.
pub fn derive_srk(dek: &[u8], chat_id: &[u8]) -> Result<Vec<u8>, &'static str> {
    derive_hkdf(
        dek,
        Some(chat_id),
        Some(b"vollchat-srk-v1"),
        32,
    )
}

/// Derives a time-windowed encryption key from a Session Root Key.
///
/// The window_index is computed as: floor(unix_timestamp_seconds / window_size_seconds)
/// All messages within the same time window use the same WindowKey.
/// Different windows produce cryptographically independent keys.
///
/// # Arguments
/// * `srk` - Session Root Key (32 bytes, from derive_srk)
/// * `window_index` - Time window index (u64)
///
/// # Security  
/// Caller must zeroize the returned Vec<u8> after use.
pub fn derive_window_key(srk: &[u8], window_index: u64) -> Result<Vec<u8>, &'static str> {
    let window_salt = window_index.to_be_bytes(); // 8 byte big-endian
    derive_hkdf(
        srk,
        Some(&window_salt),
        Some(b"vollchat-window-key-v1"),
        32,
    )
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

    #[test]
    fn test_derive_srk_determinism() {
        let dek = [0xABu8; 32];
        let chat_id = b"test-conversation-id";
        
        let srk1 = derive_srk(&dek, chat_id).unwrap();
        let srk2 = derive_srk(&dek, chat_id).unwrap();
        
        assert_eq!(srk1, srk2, "SRK türetimi deterministik olmalı");
    }

    #[test]
    fn test_derive_srk_different_chats_produce_different_keys() {
        let dek = [0xABu8; 32];
        
        let srk_chat_a = derive_srk(&dek, b"chat-a").unwrap();
        let srk_chat_b = derive_srk(&dek, b"chat-b").unwrap();
        
        assert_ne!(srk_chat_a, srk_chat_b, "Farklı chat_id farklı SRK üretmeli");
    }

    #[test]
    fn test_derive_window_key_determinism() {
        let srk = [0xCDu8; 32];
        
        let wk1 = derive_window_key(&srk, 1000).unwrap();
        let wk2 = derive_window_key(&srk, 1000).unwrap();
        
        assert_eq!(wk1, wk2, "WindowKey türetimi deterministik olmalı");
    }

    #[test]
    fn test_derive_window_key_different_windows_produce_different_keys() {
        let srk = [0xCDu8; 32];
        
        let wk_window_1 = derive_window_key(&srk, 1000).unwrap();
        let wk_window_2 = derive_window_key(&srk, 1001).unwrap();
        
        assert_ne!(wk_window_1, wk_window_2, "Farklı window_index farklı WindowKey üretmeli");
    }

    #[test]
    fn test_srk_isolation() {
        // Farklı DEK ile aynı chat_id -> farklı SRK
        let dek_a = [0xAAu8; 32];
        let dek_b = [0xBBu8; 32];
        let chat_id = b"same-chat";
        
        let srk_a = derive_srk(&dek_a, chat_id).unwrap();
        let srk_b = derive_srk(&dek_b, chat_id).unwrap();
        
        assert_ne!(srk_a, srk_b, "Farklı DEK ile aynı chat_id farklı SRK üretmeli");
    }
}

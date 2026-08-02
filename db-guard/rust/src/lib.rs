use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Instant;
use zeroize::Zeroize;

pub const DB_GUARD_ERROR_PREFIX: &str = "Vollcrypt DbGuard:";
pub type DbGuardResult<T> = Result<T, String>;

fn db_guard_error(message: &str) -> String {
    let detail = message
        .strip_prefix(DB_GUARD_ERROR_PREFIX)
        .unwrap_or(message)
        .trim_start();
    format!("{DB_GUARD_ERROR_PREFIX} {detail}")
}
#[derive(Clone, Debug)]
pub struct UserContext {
    pub role: Option<String>,
    pub user_id: Option<String>,
}

thread_local! {
    pub static CURRENT_CONTEXT: std::cell::RefCell<Option<UserContext>> = const { std::cell::RefCell::new(None) };
}

pub fn set_context(context: UserContext) {
    CURRENT_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = Some(context);
    });
}

pub fn clear_context() {
    CURRENT_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = None;
    });
}

static DECRYPT_COUNT: AtomicUsize = AtomicUsize::new(0);
static WINDOW_START: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));
static IS_FAIL_CLOSED: AtomicBool = AtomicBool::new(false);
static MAX_DECRYPT_RATE: AtomicUsize = AtomicUsize::new(500);

pub fn set_max_decrypt_rate(rate: usize) {
    MAX_DECRYPT_RATE.store(rate, Ordering::SeqCst);
}

pub fn check_rust_rate_limit() -> DbGuardResult<()> {
    if IS_FAIL_CLOSED.load(Ordering::SeqCst) {
        return Err(db_guard_error(
            "Vollcrypt DbGuard: Fail-Closed mode is active. Decryption blocked.",
        ));
    }

    let limit = MAX_DECRYPT_RATE.load(Ordering::SeqCst);
    let mut start = match WINDOW_START.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let elapsed = start.elapsed().as_millis();

    if elapsed > 1000 {
        DECRYPT_COUNT.store(0, Ordering::SeqCst);
        *start = Instant::now();
    }

    let current = DECRYPT_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    if current > limit {
        IS_FAIL_CLOSED.store(true, Ordering::SeqCst);
        // Zeroize all registered keys
        let mut reg = match REGISTRY.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (_, mut key) in reg.keys.drain() {
            key.zeroize();
        }
        reg.active_version = None;
        return Err(db_guard_error("Vollcrypt DbGuard: Decryption rate limit exceeded. Fail-Closed mode triggered. Keys zeroized."));
    }

    Ok(())
}

pub fn reset_rust_fail_closed_for_testing() {
    IS_FAIL_CLOSED.store(false, Ordering::SeqCst);
    DECRYPT_COUNT.store(0, Ordering::SeqCst);
    let mut start = match WINDOW_START.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *start = Instant::now();
}

pub mod contract;
mod secure_string;

pub mod diesel_impl;

#[cfg(feature = "sea-orm")]
pub mod seaorm_impl;

#[cfg(feature = "pkcs11")]
pub mod pkcs11_impl;

pub struct KeyRegistry {
    keys: HashMap<String, Vec<u8>>,
    active_version: Option<String>,
}

impl KeyRegistry {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            active_version: None,
        }
    }
}

static REGISTRY: Lazy<RwLock<KeyRegistry>> = Lazy::new(|| RwLock::new(KeyRegistry::new()));

/// Sets an encryption/decryption key for a given version.
pub fn set_key(version: &str, key: &[u8]) {
    let mut reg = match REGISTRY.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    reg.keys.insert(version.to_string(), key.to_vec());
    if reg.active_version.is_none() {
        reg.active_version = Some(version.to_string());
    }
}

/// Sets the active key version to be used for new encryptions.
pub fn set_active_version(version: &str) -> DbGuardResult<()> {
    let mut reg = match REGISTRY.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if reg.keys.contains_key(version) {
        reg.active_version = Some(version.to_string());
        Ok(())
    } else {
        Err(db_guard_error("Key version not found in registry"))
    }
}

/// Retrieves the key for a specific version.
pub fn get_key(version: &str) -> Option<Vec<u8>> {
    let reg = match REGISTRY.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    reg.keys.get(version).cloned()
}

/// Retrieves the active key and its version.
pub fn get_active_key() -> Option<(String, Vec<u8>)> {
    let reg = match REGISTRY.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let version = reg.active_version.as_ref()?;
    let key = reg.keys.get(version)?;
    Some((version.clone(), key.clone()))
}

/// Clears all keys from the registry.
pub fn clear_registry() {
    let mut reg = match REGISTRY.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    for (_, mut key) in reg.keys.drain() {
        key.zeroize();
    }
    reg.active_version = None;
}

/// Helper to encrypt data with the active key.
/// Prefixes ciphertext with "VOLLVALT:v{version}:base64_ciphertext"
pub fn encrypt_field(plaintext: &[u8]) -> DbGuardResult<String> {
    let (version, key) =
        get_active_key().ok_or_else(|| db_guard_error("Active key not set in registry"))?;
    let key = zeroize::Zeroizing::new(key);
    let padded = pad_message_with_len(plaintext);
    let ciphertext = encrypt_aes256gcm(&key, &padded)?;

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
    Ok(format!("VOLLVALT:v{}:{}", version, b64))
}

/// Helper to decrypt data.
/// Parses the "VOLLVALT:v{version}:base64_ciphertext" format and decrypts.
/// If the "VOLLVALT:" prefix is missing, it falls back to raw string bytes (dual-read).
pub fn decrypt_field(stored_val: &str) -> DbGuardResult<Vec<u8>> {
    if !stored_val.starts_with("VOLLVALT:") {
        // Dual-Read Fallback: Value is not encrypted. Return the raw bytes as is.
        return Ok(stored_val.as_bytes().to_vec());
    }

    check_rust_rate_limit()?;

    let payload = &stored_val["VOLLVALT:".len()..];
    if !payload.starts_with('v') {
        return Err(db_guard_error(
            "Invalid stored ciphertext format: missing version prefix after magic bytes",
        ));
    }
    let colon_pos = payload
        .find(':')
        .ok_or_else(|| db_guard_error("Invalid stored ciphertext format: missing colon divider"))?;
    let version = &payload[1..colon_pos];
    let b64_ciphertext = &payload[colon_pos + 1..];

    let key = get_key(version)
        .ok_or_else(|| db_guard_error("Decryption key version not found in registry"))?;
    let key = zeroize::Zeroizing::new(key);

    use base64::Engine;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(b64_ciphertext)
        .map_err(|_| db_guard_error("Failed to decode base64 ciphertext"))?;

    let plaintext = decrypt_aes256gcm(&key, &ciphertext)?;
    unpad_message_with_len(&plaintext)
}

/// Computes a hardened, frequency-resistant blind index for a database field.
///
/// Uses HKDF-SHA256 to derive a unique column key from the root salt,
/// preventing cross-column frequency analysis. Zeroizes intermediate keys immediately.
pub fn compute_blind_index(
    value: &str,
    root_salt: &[u8],
    column_name: &str,
) -> DbGuardResult<String> {
    // 1. Derive column-specific key using HKDF-SHA256
    let mut derived_column_key = derive_hkdf(root_salt, None, Some(column_name.as_bytes()), 32)?;

    // 2. Compute the final blind index using the derived column key
    let blind_index = derive_hkdf(&derived_column_key, None, Some(value.as_bytes()), 32)?;

    // 3. RAM Security: Zeroize the derived key immediately (Anti-Core Dump)
    derived_column_key.zeroize();

    // 4. Encode as lowercase hex string
    let hex_str = blind_index
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(hex_str)
}

// Local cryptographic helper functions using standard crates

fn calculate_padding(content_len: usize) -> Vec<u8> {
    use rand::{rngs::OsRng, RngCore};

    let sizes = [64usize, 128, 256, 512, 1024, 2048];
    let min_padding = 2usize;
    let target = sizes
        .iter()
        .copied()
        .find(|size| *size >= content_len + min_padding)
        .unwrap_or_else(|| {
            let remainder = (content_len + min_padding) % 1024;
            if remainder == 0 {
                content_len + min_padding
            } else {
                content_len + min_padding + (1024 - remainder)
            }
        });

    let mut padding = vec![0u8; target - content_len];
    OsRng.fill_bytes(&mut padding);
    padding
}

fn pad_message_with_len(content: &[u8]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(4 + content.len() + 64);
    padded.extend_from_slice(&(content.len() as u32).to_be_bytes());
    padded.extend_from_slice(content);
    let padding = calculate_padding(padded.len());
    padded.extend_from_slice(&padding);
    padded
}

fn unpad_message_with_len(padded: &[u8]) -> DbGuardResult<Vec<u8>> {
    if padded.len() < 4 {
        return Err(db_guard_error("Padded message too short"));
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len > padded.len() - 4 {
        return Err(db_guard_error("Invalid padded message length"));
    }
    Ok(padded[4..4 + len].to_vec())
}

fn encrypt_aes256gcm(key: &[u8], plaintext: &[u8]) -> DbGuardResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(db_guard_error("Invalid AES key length, must be 32 bytes"));
    }
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use rand::{rngs::OsRng, RngCore};

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| db_guard_error("Failed to create AES cipher"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad: &[],
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| db_guard_error("Encryption failed"))?;

    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_aes256gcm(key: &[u8], encrypted_data: &[u8]) -> DbGuardResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(db_guard_error("Invalid AES key length, must be 32 bytes"));
    }
    if encrypted_data.len() < 12 {
        return Err(db_guard_error("Encrypted data too short, missing nonce"));
    }
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| db_guard_error("Failed to create AES cipher"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let payload = Payload {
        msg: ciphertext,
        aad: &[],
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| db_guard_error("Decryption failed or MAC mismatch"))?;
    Ok(plaintext)
}

fn derive_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    key_len: usize,
) -> DbGuardResult<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; key_len];
    hk.expand(info.unwrap_or(b""), &mut okm)
        .map_err(|_| db_guard_error("HKDF expansion failed"))?;
    Ok(okm)
}

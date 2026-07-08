use std::path::Path;
use cryptoki::context::{Pkcs11, CInitializeArgs};
use cryptoki::session::UserType;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::mechanism::Mechanism;
use secrecy::SecretString;

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() {
        return Err("Hex string contains non-ASCII characters".to_string());
    }
    if s.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }
    let bytes = s.as_bytes();
    (0..bytes.len())
        .step_by(2)
        .map(|i| {
            let chunk = std::str::from_utf8(&bytes[i..i + 2])
                .map_err(|e| format!("Invalid UTF-8: {}", e))?;
            u8::from_str_radix(chunk, 16)
                .map_err(|e| format!("Invalid hex digit: {}", e))
        })
        .collect()
}

pub fn decrypt_with_hsm(
    library_path: &str,
    pin: &str,
    slot_id: Option<usize>,
    key_id_hex: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let pkcs11 = Pkcs11::new(Path::new(library_path))
        .map_err(|e| format!("Failed to load PKCS#11 library: {}", e))?;

    if !pkcs11.is_initialized() {
        if let Err(e) = pkcs11.initialize(CInitializeArgs::OsThreads) {
            if !matches!(e, cryptoki::error::Error::AlreadyInitialized) {
                return Err(format!("Failed to initialize PKCS#11 context: {}", e));
            }
        }
    }

    let slots = pkcs11.get_slots_with_token()
        .map_err(|e| format!("Failed to get slots: {}", e))?;

    let slot_idx = slot_id.unwrap_or(0);
    if slots.len() <= slot_idx {
        return Err(format!("PKCS#11 slot index {} not found.", slot_idx));
    }
    let slot = slots[slot_idx];

    let session = pkcs11.open_ro_session(slot)
        .map_err(|e| format!("Failed to open session: {}", e))?;

    let auth_pin = SecretString::new(pin.to_string());
    session.login(UserType::User, Some(&auth_pin))
        .map_err(|e| format!("Login failed: {}", e))?;

    let result = (|| {
        let key_id_bytes = decode_hex(key_id_hex)?;
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Id(key_id_bytes),
        ];

        let keys = session.find_objects(&template)
            .map_err(|e| format!("Key search failed: {}", e))?;

        if keys.is_empty() {
            return Err(format!("Secret key with ID {} not found in HSM.", key_id_hex));
        }
        let key_handle = keys[0];

        let mut iv = [0u8; 16];
        let actual_ciphertext = if ciphertext.len() > 16 {
            iv.copy_from_slice(&ciphertext[0..16]);
            &ciphertext[16..]
        } else {
            ciphertext
        };

        let mechanism = Mechanism::AesCbcPad(iv);
        let decrypted = session.decrypt(&mechanism, key_handle, actual_ciphertext)
            .map_err(|e| format!("PKCS#11 decryption failed: {}", e))?;

        Ok(decrypted)
    })();

    let _ = session.logout();

    result
}

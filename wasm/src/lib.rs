use wasm_bindgen::prelude::*;
use vollcrypt_core::{
    generate_mnemonic as core_generate_mnemonic,
    mnemonic_to_seed as core_mnemonic_to_seed,
    generate_ed25519_keypair as core_generate_ed25519_keypair,
    generate_x25519_keypair as core_generate_x25519_keypair,
    encrypt_aes256gcm as core_encrypt_aes256gcm,
    decrypt_aes256gcm as core_decrypt_aes256gcm,
    derive_pbkdf2 as core_derive_pbkdf2,
    derive_hkdf as core_derive_hkdf,
    sign_message as core_sign_message,
    verify_signature as core_verify_signature,
    ecdh_shared_secret as core_ecdh_shared_secret,
    derive_srk as core_derive_srk,
    derive_window_key as core_derive_window_key,
    wrap_key as core_wrap_key,
    unwrap_key as core_unwrap_key,
    pad_message as core_pad_message,
    pack_envelope as core_pack_envelope,
    unpack_envelope as core_unpack_envelope,
    ml_kem_keygen as core_ml_kem_keygen,
    ml_kem_encapsulate as core_ml_kem_encapsulate,
    ml_kem_decapsulate as core_ml_kem_decapsulate,
    hybrid_kem_encapsulate as core_hybrid_kem_encapsulate,
    hybrid_kem_decapsulate as core_hybrid_kem_decapsulate,
};

#[wasm_bindgen]
pub fn generate_mnemonic() -> String {
    core_generate_mnemonic()
}

#[wasm_bindgen]
pub fn mnemonic_to_seed(phrase: &str, password: Option<String>) -> Result<Vec<u8>, JsValue> {
    core_mnemonic_to_seed(phrase, password.as_deref())
        .map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub struct Ed25519KeyPairObj {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl Ed25519KeyPairObj {
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        core_sign_message(&self.secret_key, message)
            .map_err(|e| JsValue::from_str(e))
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

#[wasm_bindgen]
pub fn generate_ed25519_keypair() -> Ed25519KeyPairObj {
    let (sk, pk) = core_generate_ed25519_keypair();
    Ed25519KeyPairObj {
        secret_key: sk,
        public_key: pk,
    }
}

#[wasm_bindgen]
pub struct X25519KeyPairObj {
    secret: Vec<u8>,
    public: Vec<u8>,
}

#[wasm_bindgen]
impl X25519KeyPairObj {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

#[wasm_bindgen]
pub fn generate_x25519_keypair() -> X25519KeyPairObj {
    let (secret, public) = core_generate_x25519_keypair();
    X25519KeyPairObj {
        secret,
        public,
    }
}

#[wasm_bindgen]
pub fn ecdh_shared_secret(our_secret: &[u8], their_public: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_ecdh_shared_secret(our_secret, their_public)
        .map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn sign_message(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_sign_message(secret_key, message)
        .map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    core_verify_signature(public_key, message, signature)
}

#[wasm_bindgen]
pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8], aad: Option<Vec<u8>>) -> Result<Vec<u8>, JsValue> {
    core_encrypt_aes256gcm(key, plaintext, aad.as_deref())
        .map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn decrypt_aes_gcm(key: &[u8], ciphertext: &[u8], aad: Option<Vec<u8>>) -> Result<Vec<u8>, JsValue> {
    core_decrypt_aes256gcm(key, ciphertext, aad.as_deref())
        .map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn derive_pbkdf2(password: &[u8], salt: &[u8], iterations: u32, key_len: u32) -> Vec<u8> {
    core_derive_pbkdf2(password, salt, iterations, key_len as usize)
}

#[wasm_bindgen]
pub fn derive_hkdf(ikm: &[u8], salt: Option<Vec<u8>>, info: Option<Vec<u8>>, key_len: u32) -> Result<Vec<u8>, JsValue> {
    core_derive_hkdf(ikm, salt.as_deref(), info.as_deref(), key_len as usize)
        .map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn derive_srk(dek: &[u8], chat_id: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_derive_srk(dek, chat_id).map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn derive_window_key(srk: &[u8], window_index: u32) -> Result<Vec<u8>, JsValue> {
    core_derive_window_key(srk, window_index as u64).map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn wrap_key(kek: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_wrap_key(kek, key_to_wrap).map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn unwrap_key(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_unwrap_key(kek, wrapped_key).map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn pad_message(content: &[u8]) -> Vec<u8> {
    core_pad_message(content)
}

#[wasm_bindgen]
pub fn pack_envelope(window_index: u32, aad_hash: &[u8], encrypted_blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut aad = [0u8; 32];
    if aad_hash.len() != 32 {
        return Err(JsValue::from_str("AAD Hash must be exactly 32 bytes"));
    }
    aad.copy_from_slice(aad_hash);
    core_pack_envelope(window_index, &aad, encrypted_blob).map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub struct UnpackedEnvelope {
    pub window_index: u32,
    aad_hash: Vec<u8>,
    encrypted_blob: Vec<u8>,
}

#[wasm_bindgen]
impl UnpackedEnvelope {
    #[wasm_bindgen(getter)]
    pub fn aad_hash(&self) -> Vec<u8> {
        self.aad_hash.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn encrypted_blob(&self) -> Vec<u8> {
        self.encrypted_blob.clone()
    }
}

#[wasm_bindgen]
pub fn unpack_envelope(envelope: &[u8]) -> Result<UnpackedEnvelope, JsValue> {
    match core_unpack_envelope(envelope) {
        Ok((window_index, aad_hash, encrypted_blob)) => Ok(UnpackedEnvelope {
            window_index,
            aad_hash: aad_hash.to_vec(),
            encrypted_blob,
        }),
        Err(e) => Err(JsValue::from_str(e)),
    }
}

// ==================== Post-Quantum Cryptography (Phase 6) ====================

#[wasm_bindgen]
pub struct MlKemKeyPairObj {
    decapsulation_key: Vec<u8>,
    encapsulation_key: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemKeyPairObj {
    #[wasm_bindgen(getter)]
    pub fn decapsulation_key(&self) -> Vec<u8> {
        self.decapsulation_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn encapsulation_key(&self) -> Vec<u8> {
        self.encapsulation_key.clone()
    }
}

#[wasm_bindgen]
pub fn ml_kem_keygen() -> MlKemKeyPairObj {
    let (dk, ek) = core_ml_kem_keygen();
    MlKemKeyPairObj {
        decapsulation_key: dk,
        encapsulation_key: ek,
    }
}

#[wasm_bindgen]
pub struct MlKemEncapsulationResult {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemEncapsulationResult {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

#[wasm_bindgen]
pub fn ml_kem_encapsulate(encapsulation_key: &[u8]) -> Result<MlKemEncapsulationResult, JsValue> {
    let (ct, ss) = core_ml_kem_encapsulate(encapsulation_key)
        .map_err(|e| JsValue::from_str(e))?;
    Ok(MlKemEncapsulationResult {
        ciphertext: ct,
        shared_secret: ss,
    })
}

#[wasm_bindgen]
pub fn ml_kem_decapsulate(decapsulation_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_ml_kem_decapsulate(decapsulation_key, ciphertext)
        .map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub struct HybridKemResult {
    shared_key: Vec<u8>,
    ml_kem_ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl HybridKemResult {
    #[wasm_bindgen(getter)]
    pub fn shared_key(&self) -> Vec<u8> {
        self.shared_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ml_kem_ciphertext(&self) -> Vec<u8> {
        self.ml_kem_ciphertext.clone()
    }
}

#[wasm_bindgen]
pub fn hybrid_kem_encapsulate(
    x25519_our_secret: &[u8],
    x25519_their_public: &[u8],
    ml_kem_ek: &[u8],
) -> Result<HybridKemResult, JsValue> {
    let (key, ct) = core_hybrid_kem_encapsulate(x25519_our_secret, x25519_their_public, ml_kem_ek)
        .map_err(|e| JsValue::from_str(e))?;
    Ok(HybridKemResult {
        shared_key: key,
        ml_kem_ciphertext: ct,
    })
}

#[wasm_bindgen]
pub fn hybrid_kem_decapsulate(
    x25519_our_secret: &[u8],
    x25519_their_public: &[u8],
    ml_kem_dk: &[u8],
    ml_kem_ct: &[u8],
) -> Result<Vec<u8>, JsValue> {
    core_hybrid_kem_decapsulate(x25519_our_secret, x25519_their_public, ml_kem_dk, ml_kem_ct)
        .map_err(|e| JsValue::from_str(e))
}

// ==================== Device Authorization Registry ====================

#[wasm_bindgen]
pub fn registry_empty() -> String {
    let registry = vollcrypt_core::DefaultDeviceRegistry::new();
    registry.to_json().unwrap_or_else(|_| "{\"devices\":[]}".to_string())
}

#[wasm_bindgen]
pub fn registry_add_device(
    registry_json: &str,
    device_id: &str,
    name: &str,
    added_at: u32,
    public_key: &str,
) -> Result<String, JsValue> {
    let mut registry = vollcrypt_core::DefaultDeviceRegistry::from_json(registry_json)
        .map_err(|e| JsValue::from_str(e))?;
        
    let device = vollcrypt_core::Device {
        device_id: device_id.to_string(),
        name: name.to_string(),
        added_at: added_at as u64,
        public_key: public_key.to_string(),
        is_revoked: false,
    };
    
    registry.add_device(device).map_err(|e| JsValue::from_str(e))?;
    
    registry.to_json().map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn registry_revoke_device(registry_json: &str, device_id: &str) -> Result<String, JsValue> {
    let mut registry = vollcrypt_core::DefaultDeviceRegistry::from_json(registry_json)
        .map_err(|e| JsValue::from_str(e))?;
        
    registry.revoke_device(device_id).map_err(|e| JsValue::from_str(e))?;
    
    registry.to_json().map_err(|e| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn registry_get_active_devices(registry_json: &str) -> Result<String, JsValue> {
    let registry = vollcrypt_core::DefaultDeviceRegistry::from_json(registry_json)
        .map_err(|e| JsValue::from_str(e))?;
        
    registry.get_active_devices_json().map_err(|e| JsValue::from_str(e))
}

// ==================== Logging Initialization ====================

#[wasm_bindgen]
pub fn init_logger() {
    console_error_panic_hook::set_once();
    
    let _ = console_log::init_with_level(log::Level::Debug);
}

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

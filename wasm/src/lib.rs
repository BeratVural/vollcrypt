use wasm_bindgen::prelude::*;
use vollcrypt_core::{
    generate_mnemonic as core_generate_mnemonic,
    mnemonic_to_seed as core_mnemonic_to_seed,
    generate_ed25519_keypair as core_generate_ed25519_keypair,
    generate_x25519_keypair as core_generate_x25519_keypair,
    encrypt_aes256gcm as core_encrypt_aes256gcm,
    decrypt_aes256gcm as core_decrypt_aes256gcm,
    encrypt_aes256gcm_chunked as core_encrypt_aes256gcm_chunked,
    decrypt_aes256gcm_chunked as core_decrypt_aes256gcm_chunked,
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
        .map_err(JsValue::from_str)
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
            .map_err(JsValue::from_str)
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

/// Verification code result (for WASM)
#[wasm_bindgen]
pub struct VerificationCodeResult {
    fingerprint:      Vec<u8>,  // 32 bytes
    numeric_digits:   String,   // 60 digits
    numeric_formatted: String,  // "12345 67890 ..."
    emoji_formatted:  String,   // "🔥💧... 🌊⚡..."
}

#[wasm_bindgen]
impl VerificationCodeResult {
    #[wasm_bindgen(getter)] pub fn fingerprint(&self)       -> Vec<u8> { self.fingerprint.clone() }
    #[wasm_bindgen(getter)] pub fn numeric_digits(&self)    -> String  { self.numeric_digits.clone() }
    #[wasm_bindgen(getter)] pub fn numeric_formatted(&self) -> String  { self.numeric_formatted.clone() }
    #[wasm_bindgen(getter)] pub fn emoji_formatted(&self)   -> String  { self.emoji_formatted.clone() }
}

#[wasm_bindgen]
pub fn generate_verification_code(
    key_a: &[u8],
    key_b: &[u8],
    conversation_id: &[u8],
) -> Result<VerificationCodeResult, JsValue> {
    let ka: [u8; 32] = key_a.try_into().map_err(|_| JsValue::from_str("key_a must be 32 bytes"))?;
    let kb: [u8; 32] = key_b.try_into().map_err(|_| JsValue::from_str("key_b must be 32 bytes"))?;
    
    let code = vollcrypt_core::verification::generate_verification_code(&ka, &kb, conversation_id);
    
    Ok(VerificationCodeResult {
        fingerprint: code.fingerprint.to_vec(),
        numeric_digits: code.numeric.digits,
        numeric_formatted: code.numeric.formatted,
        emoji_formatted: code.emoji.formatted,
    })
}

#[wasm_bindgen]
pub fn compute_fingerprint(
    key_a: &[u8],
    key_b: &[u8],
    conversation_id: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let ka: [u8; 32] = key_a.try_into().map_err(|_| JsValue::from_str("key_a must be 32 bytes"))?;
    let kb: [u8; 32] = key_b.try_into().map_err(|_| JsValue::from_str("key_b must be 32 bytes"))?;
    
    let fp = vollcrypt_core::verification::compute_fingerprint(&ka, &kb, conversation_id);
    Ok(fp.to_vec())
}

#[wasm_bindgen]
pub fn verify_fingerprints_match(
    fingerprint_a: &[u8],
    fingerprint_b: &[u8],
) -> Result<bool, JsValue> {
    let fa: [u8; 32] = fingerprint_a.try_into().map_err(|_| JsValue::from_str("fingerprint_a must be 32 bytes"))?;
    let fb: [u8; 32] = fingerprint_b.try_into().map_err(|_| JsValue::from_str("fingerprint_b must be 32 bytes"))?;
    
    Ok(vollcrypt_core::verification::verify_fingerprints_match(&fa, &fb))
}

#[wasm_bindgen]
pub fn ecdh_shared_secret(our_secret: &[u8], their_public: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_ecdh_shared_secret(our_secret, their_public)
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn sign_message(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_sign_message(secret_key, message)
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    core_verify_signature(public_key, message, signature)
}

#[wasm_bindgen]
pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8], aad: Option<Vec<u8>>) -> Result<Vec<u8>, JsValue> {
    core_encrypt_aes256gcm(key, plaintext, aad.as_deref())
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn decrypt_aes_gcm(key: &[u8], ciphertext: &[u8], aad: Option<Vec<u8>>) -> Result<Vec<u8>, JsValue> {
    core_decrypt_aes256gcm(key, ciphertext, aad.as_deref())
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn encrypt_aes_gcm_chunked(
    key: &[u8],
    plaintext: &[u8],
    aad: Option<Vec<u8>>,
    chunk_size: u32,
) -> Result<Vec<u8>, JsValue> {
    core_encrypt_aes256gcm_chunked(key, plaintext, aad.as_deref(), chunk_size as usize)
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn decrypt_aes_gcm_chunked(
    key: &[u8],
    ciphertext: &[u8],
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    core_decrypt_aes256gcm_chunked(key, ciphertext, aad.as_deref())
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn derive_pbkdf2(password: &[u8], salt: &[u8], iterations: u32, key_len: u32) -> Vec<u8> {
    core_derive_pbkdf2(password, salt, iterations, key_len as usize)
}

#[wasm_bindgen]
pub fn derive_hkdf(ikm: &[u8], salt: Option<Vec<u8>>, info: Option<Vec<u8>>, key_len: u32) -> Result<Vec<u8>, JsValue> {
    core_derive_hkdf(ikm, salt.as_deref(), info.as_deref(), key_len as usize)
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn derive_srk(dek: &[u8], chat_id: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_derive_srk(dek, chat_id).map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn derive_window_key(srk: &[u8], window_index: u32) -> Result<Vec<u8>, JsValue> {
    core_derive_window_key(srk, window_index as u64).map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn wrap_key(kek: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_wrap_key(kek, key_to_wrap).map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn unwrap_key(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_unwrap_key(kek, wrapped_key).map_err(JsValue::from_str)
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
    core_pack_envelope(window_index, &aad, encrypted_blob).map_err(JsValue::from_str)
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

// ==================== Transcript Hashing ====================

#[wasm_bindgen]
pub fn transcript_new(session_id: &[u8]) -> Vec<u8> {
    let ts = vollcrypt_core::transcript::TranscriptState::new(session_id);
    ts.to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn transcript_update(
    chain_state: &[u8],
    message_hash: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if chain_state.len() != 32 || message_hash.len() != 32 {
        return Err(JsValue::from_str("chain_state and message_hash must be 32 bytes"));
    }
    
    let mut state_bytes = [0u8; 32];
    state_bytes.copy_from_slice(chain_state);
    let mut msg_hash_bytes = [0u8; 32];
    msg_hash_bytes.copy_from_slice(message_hash);

    let mut ts = vollcrypt_core::transcript::TranscriptState::from_bytes(state_bytes);
    ts.update(&msg_hash_bytes);
    Ok(ts.to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn transcript_compute_message_hash(
    message_id: &[u8],
    sender_id: &[u8],
    timestamp: u32,
    ciphertext: &[u8],
) -> Vec<u8> {
    vollcrypt_core::transcript::TranscriptState::compute_message_hash(
        message_id,
        sender_id,
        timestamp as u64,
        ciphertext,
    ).to_vec()
}

#[wasm_bindgen]
pub fn transcript_verify_sync(hash_a: &[u8], hash_b: &[u8]) -> bool {
    if hash_a.len() != 32 || hash_b.len() != 32 {
        return false;
    }
    
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(hash_a);
    let mut b_bytes = [0u8; 32];
    b_bytes.copy_from_slice(hash_b);

    vollcrypt_core::transcript::TranscriptState::verify_sync(&a_bytes, &b_bytes)
}

// ==================== Sealed Sender ====================

#[wasm_bindgen]
pub struct UnsealResult {
    sender_id: Vec<u8>,
    content: Vec<u8>,
}

#[wasm_bindgen]
impl UnsealResult {
    #[wasm_bindgen(getter)]
    pub fn sender_id(&self) -> Vec<u8> {
        self.sender_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn content(&self) -> Vec<u8> {
        self.content.clone()
    }

    pub fn free(self) {}
}

#[wasm_bindgen]
pub fn seal_message(
    recipient_x25519_pub: &[u8],
    sender_id: &[u8],
    content: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if recipient_x25519_pub.len() != 32 {
        return Err(JsValue::from_str("recipient_x25519_pub must be 32 bytes"));
    }
    
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(recipient_x25519_pub);

    vollcrypt_core::sealed_sender::seal(&pub_bytes, sender_id, content)
        .map_err(|e| JsValue::from_str(&format!("Sealing failed: {:?}", e)))
}

#[wasm_bindgen]
pub fn unseal_message(
    sealed_packet: &[u8],
    our_x25519_sk: &[u8],
) -> Result<UnsealResult, JsValue> {
    if our_x25519_sk.len() != 32 {
        return Err(JsValue::from_str("our_x25519_sk must be 32 bytes"));
    }
    
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(our_x25519_sk);

    vollcrypt_core::sealed_sender::unseal(sealed_packet, &sk_bytes)
        .map(|(sender_id, content)| UnsealResult { sender_id, content })
        .map_err(|e| JsValue::from_str(&format!("Unsealing failed: {:?}", e)))
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
        .map_err(JsValue::from_str)?;
    Ok(MlKemEncapsulationResult {
        ciphertext: ct,
        shared_secret: ss,
    })
}

#[wasm_bindgen]
pub fn ml_kem_decapsulate(decapsulation_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    core_ml_kem_decapsulate(decapsulation_key, ciphertext)
        .map_err(JsValue::from_str)
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
        .map_err(JsValue::from_str)?;
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
        .map_err(JsValue::from_str)
}

// ==================== Authenticated Hybrid KEM ====================

#[wasm_bindgen]
pub struct AuthenticatedKemResult {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl AuthenticatedKemResult {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// WARNING: shared_secret should only be used in SRK derivation,
    /// and should not be used as an encryption key directly.
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }

    pub fn free(self) {} // wasm-bindgen drop
}

#[wasm_bindgen]
pub fn authenticated_kem_encapsulate(
    our_x25519_sk: &[u8],
    recipient_x25519_pub: &[u8],
    recipient_mlkem_pub: &[u8],
    sender_identity_sk: &[u8],
) -> Result<AuthenticatedKemResult, JsValue> {
    let (ct, ss) = vollcrypt_core::pqc::authenticated_kem_encapsulate(
        our_x25519_sk,
        recipient_x25519_pub,
        recipient_mlkem_pub,
        sender_identity_sk,
    ).map_err(JsValue::from_str)?;

    Ok(AuthenticatedKemResult {
        ciphertext: ct,
        shared_secret: ss,
    })
}

#[wasm_bindgen]
pub fn authenticated_kem_decapsulate(
    our_x25519_sk: &[u8],
    sender_x25519_pub: &[u8],
    our_mlkem_dk: &[u8],
    authenticated_ciphertext: &[u8],
    sender_identity_pk: &[u8],
) -> Result<Vec<u8>, JsValue> {
    vollcrypt_core::pqc::authenticated_kem_decapsulate(
        our_x25519_sk,
        sender_x25519_pub,
        our_mlkem_dk,
        authenticated_ciphertext,
        sender_identity_pk,
    ).map_err(JsValue::from_str)
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
        .map_err(JsValue::from_str)?;
        
    let device = vollcrypt_core::Device {
        device_id: device_id.to_string(),
        name: name.to_string(),
        added_at: added_at as u64,
        public_key: public_key.to_string(),
        is_revoked: false,
    };
    
    registry.add_device(device).map_err(JsValue::from_str)?;
    
    registry.to_json().map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn registry_revoke_device(registry_json: &str, device_id: &str) -> Result<String, JsValue> {
    let mut registry = vollcrypt_core::DefaultDeviceRegistry::from_json(registry_json)
        .map_err(JsValue::from_str)?;
        
    registry.revoke_device(device_id).map_err(JsValue::from_str)?;
    
    registry.to_json().map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn registry_get_active_devices(registry_json: &str) -> Result<String, JsValue> {
    let registry = vollcrypt_core::DefaultDeviceRegistry::from_json(registry_json)
        .map_err(JsValue::from_str)?;
        
    registry.get_active_devices_json().map_err(JsValue::from_str)
}

// ==================== Logging Initialization ====================

#[wasm_bindgen]
pub fn init_logger() {
    console_error_panic_hook::set_once();
    
    let _ = console_log::init_with_level(log::Level::Debug);
}

// ==================== Post-Compromise Security (PCS) ====================

#[wasm_bindgen]
pub struct RatchetKeyPairObj {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl RatchetKeyPairObj {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Computes SRK ratchet using this key pair.
    /// secret_key never crosses the WASM boundary.
    #[wasm_bindgen]
    pub fn compute_ratchet(
        &self,
        current_srk: &[u8],
        their_ratchet_pub: &[u8],
        chat_id: &[u8],
        ratchet_step: u32,
    ) -> Result<Vec<u8>, JsValue> {
        if current_srk.len() != 32 || their_ratchet_pub.len() != 32 {
            return Err(JsValue::from_str("Keys must be 32 bytes"));
        }

        let mut current_srk_arr = [0u8; 32];
        current_srk_arr.copy_from_slice(current_srk);
        let mut their_pub_arr = [0u8; 32];
        their_pub_arr.copy_from_slice(their_ratchet_pub);
        let mut our_secret_arr = [0u8; 32];
        our_secret_arr.copy_from_slice(&self.secret_key);

        // Compute ratchet
        let new_srk = vollcrypt_core::ratchet_srk_sender(
            &current_srk_arr,
            &our_secret_arr,
            &their_pub_arr,
            chat_id,
            ratchet_step as u64,
        ).map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(new_srk.to_vec())
    }
}

#[wasm_bindgen]
pub fn generate_ratchet_keypair() -> Result<RatchetKeyPairObj, JsValue> {
    let kp = vollcrypt_core::generate_ratchet_keypair()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
    Ok(RatchetKeyPairObj {
        secret_key: kp.secret_key().to_vec(),
        public_key: kp.public_key.to_vec(),
    })
}

#[wasm_bindgen]
pub fn should_ratchet(
    message_count: u32,
    window_changed: bool,
    messages_per_ratchet: u32,
    ratchet_on_new_window: bool,
) -> bool {
    let config = vollcrypt_core::RatchetConfig {
        messages_per_ratchet,
        ratchet_on_new_window,
    };
    vollcrypt_core::should_ratchet(message_count, window_changed, &config)
}

// ==================== Key Transparency (Key Log) ====================

#[wasm_bindgen]
pub fn key_log_create_entry(
    user_id: &[u8],
    public_key: &[u8],
    timestamp: u32,
    prev_entry_hash: &[u8],
    action: u8,
    signing_key: &[u8],
) -> Result<String, JsValue> {
    if public_key.len() != 32 || prev_entry_hash.len() != 32 || signing_key.len() != 32 {
        return Err(JsValue::from_str("Key lengths must be exactly 32 bytes"));
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_key);
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(prev_entry_hash);
    let mut sign_key = [0u8; 32];
    sign_key.copy_from_slice(signing_key);

    let act = match action {
        1 => vollcrypt_core::key_log::KeyAction::Add,
        2 => vollcrypt_core::key_log::KeyAction::Update,
        3 => vollcrypt_core::key_log::KeyAction::Revoke,
        _ => return Err(JsValue::from_str("Invalid action type")),
    };

    match vollcrypt_core::key_log::create_entry(user_id, &pk, timestamp as u64, &prev_hash, act, &sign_key) {
        Ok(entry) => {
            serde_json::to_string(&entry).map_err(|e| JsValue::from_str(&e.to_string()))
        },
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn key_log_verify_chain(entries_json: &str) -> Result<bool, JsValue> {
    let entries: Vec<vollcrypt_core::key_log::KeyLogEntry> = serde_json::from_str(entries_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON array: {}", e)))?;
    
    let log = vollcrypt_core::key_log::KeyLog { entries };
    match log.verify_chain() {
        Ok(_) => Ok(true),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn key_log_current_key(
    entries_json: &str,
    user_id: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let entries: Vec<vollcrypt_core::key_log::KeyLogEntry> = serde_json::from_str(entries_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON array: {}", e)))?;
    
    let log = vollcrypt_core::key_log::KeyLog { entries };
    match log.current_key_for(user_id) {
        Some(k) => Ok(k.to_vec()),
        None => Ok(Vec::new()),
    }
}

#[wasm_bindgen]
pub fn key_log_key_at_timestamp(
    entries_json: &str,
    user_id: &[u8],
    timestamp: u32,
) -> Result<Vec<u8>, JsValue> {
    let entries: Vec<vollcrypt_core::key_log::KeyLogEntry> = serde_json::from_str(entries_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON array: {}", e)))?;
    
    let log = vollcrypt_core::key_log::KeyLog { entries };
    match log.key_at_timestamp(user_id, timestamp as u64) {
        Some(k) => Ok(k.to_vec()),
        None => Ok(Vec::new()),
    }
}

#[wasm_bindgen]
pub fn key_log_compute_entry_hash(entry_json: &str) -> Result<Vec<u8>, JsValue> {
    let entry: vollcrypt_core::key_log::KeyLogEntry = serde_json::from_str(entry_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON object: {}", e)))?;
    
    let hash = entry.compute_hash();
    Ok(hash.to_vec())
}

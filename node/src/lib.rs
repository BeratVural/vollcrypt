use napi::{Error, Result, bindgen_prelude::{Buffer, Uint8Array}};
use napi_derive::napi;

#[napi]
pub fn generate_mnemonic() -> String {
    vollcrypt_core::generate_mnemonic()
}

#[napi]
pub fn mnemonic_to_seed(phrase: String, password: Option<String>) -> Result<Buffer> {
    match vollcrypt_core::mnemonic_to_seed(&phrase, password.as_deref()) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// Secret Key, Public Key
#[napi]
pub fn generate_ed25519_keypair() -> Vec<Buffer> {
    let (sk, pk) = vollcrypt_core::generate_ed25519_keypair();
    vec![Buffer::from(sk), Buffer::from(pk)]
}

// Secret, Public
#[napi]
pub fn generate_x25519_keypair() -> Vec<Buffer> {
    let (secret, public) = vollcrypt_core::generate_x25519_keypair();
    vec![Buffer::from(secret), Buffer::from(public)]
}

#[napi]
pub fn ecdh_shared_secret(our_secret: Uint8Array, their_public: Uint8Array) -> Result<Buffer> {
    match vollcrypt_core::ecdh_shared_secret(our_secret.as_ref(), their_public.as_ref()) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn sign_message(secret_key: Uint8Array, message: Uint8Array) -> Result<Buffer> {
    match vollcrypt_core::sign_message(secret_key.as_ref(), message.as_ref()) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn verify_signature(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array) -> bool {
    vollcrypt_core::verify_signature(public_key.as_ref(), message.as_ref(), signature.as_ref())
}

#[napi]
pub fn encrypt_aes_gcm(key: Uint8Array, plaintext: Uint8Array, aad: Option<Uint8Array>) -> Result<Buffer> {
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    match vollcrypt_core::encrypt_aes256gcm(key.as_ref(), plaintext.as_ref(), aad_ref) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn decrypt_aes_gcm(key: Uint8Array, ciphertext: Uint8Array, aad: Option<Uint8Array>) -> Result<Buffer> {
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    match vollcrypt_core::decrypt_aes256gcm(key.as_ref(), ciphertext.as_ref(), aad_ref) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn derive_pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: u32, key_len: u32) -> Buffer {
    let key = vollcrypt_core::derive_pbkdf2(password.as_ref(), salt.as_ref(), iterations, key_len as usize);
    Buffer::from(key)
}

#[napi]
pub fn derive_hkdf(ikm: Uint8Array, salt: Option<Uint8Array>, info: Option<Uint8Array>, key_len: u32) -> Result<Buffer> {
    let salt_ref = salt.as_ref().map(|x| x.as_ref());
    let info_ref = info.as_ref().map(|x| x.as_ref());
    match vollcrypt_core::derive_hkdf(ikm.as_ref(), salt_ref, info_ref, key_len as usize) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn derive_srk(dek: Uint8Array, chat_id: Uint8Array) -> Result<Buffer> {
    match vollcrypt_core::derive_srk(dek.as_ref(), chat_id.as_ref()) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn derive_window_key(srk: Uint8Array, window_index: u32) -> Result<Buffer> {
    match vollcrypt_core::derive_window_key(srk.as_ref(), window_index as u64) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn wrap_key(kek: Uint8Array, key_to_wrap: Uint8Array) -> Result<Buffer> {
    match vollcrypt_core::wrap_key(kek.as_ref(), key_to_wrap.as_ref()) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn unwrap_key(kek: Uint8Array, wrapped_key: Uint8Array) -> Result<Buffer> {
    match vollcrypt_core::unwrap_key(kek.as_ref(), wrapped_key.as_ref()) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn pad_message(content: Uint8Array) -> Buffer {
    let padded = vollcrypt_core::pad_message(content.as_ref());
    Buffer::from(padded)
}

#[napi]
pub fn pack_envelope(window_index: u32, aad_hash: Uint8Array, encrypted_blob: Uint8Array) -> Result<Buffer> {
    if aad_hash.as_ref().len() != 32 {
        return Err(Error::from_reason("AAD hash must be exactly 32 bytes"));
    }
    let mut aad = [0u8; 32];
    aad.copy_from_slice(aad_hash.as_ref());
    match vollcrypt_core::pack_envelope(window_index, &aad, encrypted_blob.as_ref()) {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi(object)]
pub struct UnpackedEnvelope {
    pub window_index: u32,
    pub aad_hash: Buffer,
    pub encrypted_blob: Buffer,
}

#[napi]
pub fn unpack_envelope(envelope: Uint8Array) -> Result<UnpackedEnvelope> {
    match vollcrypt_core::unpack_envelope(envelope.as_ref()) {
        Ok((window_index, aad_hash, encrypted_blob)) => Ok(UnpackedEnvelope {
            window_index,
            aad_hash: Buffer::from(aad_hash.to_vec()),
            encrypted_blob: Buffer::from(encrypted_blob),
        }),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// ==================== Post-Quantum Cryptography (Phase 6) ====================

#[napi]
pub fn ml_kem_keygen() -> Vec<Buffer> {
    let (dk, ek) = vollcrypt_core::ml_kem_keygen();
    vec![Buffer::from(dk), Buffer::from(ek)]
}

#[napi(object)]
pub struct MlKemEncapsulationResult {
    pub ciphertext: Buffer,
    pub shared_secret: Buffer,
}

#[napi]
pub fn ml_kem_encapsulate(encapsulation_key: Uint8Array) -> Result<MlKemEncapsulationResult> {
    match vollcrypt_core::ml_kem_encapsulate(encapsulation_key.as_ref()) {
        Ok((ct, ss)) => Ok(MlKemEncapsulationResult {
            ciphertext: Buffer::from(ct),
            shared_secret: Buffer::from(ss),
        }),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn ml_kem_decapsulate(decapsulation_key: Uint8Array, ciphertext: Uint8Array) -> Result<Buffer> {
    match vollcrypt_core::ml_kem_decapsulate(decapsulation_key.as_ref(), ciphertext.as_ref()) {
        Ok(ss) => Ok(Buffer::from(ss)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi(object)]
pub struct HybridKemResult {
    pub shared_key: Buffer,
    pub ml_kem_ciphertext: Buffer,
}

#[napi]
pub fn hybrid_kem_encapsulate(
    x25519_our_secret: Uint8Array,
    x25519_their_public: Uint8Array,
    ml_kem_ek: Uint8Array,
) -> Result<HybridKemResult> {
    match vollcrypt_core::hybrid_kem_encapsulate(
        x25519_our_secret.as_ref(),
        x25519_their_public.as_ref(),
        ml_kem_ek.as_ref(),
    ) {
        Ok((key, ct)) => Ok(HybridKemResult {
            shared_key: Buffer::from(key),
            ml_kem_ciphertext: Buffer::from(ct),
        }),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn hybrid_kem_decapsulate(
    x25519_our_secret: Uint8Array,
    x25519_their_public: Uint8Array,
    ml_kem_dk: Uint8Array,
    ml_kem_ct: Uint8Array,
) -> Result<Buffer> {
    match vollcrypt_core::hybrid_kem_decapsulate(
        x25519_our_secret.as_ref(),
        x25519_their_public.as_ref(),
        ml_kem_dk.as_ref(),
        ml_kem_ct.as_ref(),
    ) {
        Ok(key) => Ok(Buffer::from(key)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn authenticated_kem_encapsulate(
    our_x25519_sk: Uint8Array,
    recipient_x25519_pub: Uint8Array,
    recipient_mlkem_ek: Uint8Array,
    sender_identity_sk: Uint8Array,
) -> Result<Vec<Buffer>> {
    match vollcrypt_core::pqc::authenticated_kem_encapsulate(
        our_x25519_sk.as_ref(),
        recipient_x25519_pub.as_ref(),
        recipient_mlkem_ek.as_ref(),
        sender_identity_sk.as_ref(),
    ) {
        Ok((ct, ss)) => Ok(vec![Buffer::from(ct), Buffer::from(ss)]),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn authenticated_kem_decapsulate(
    our_x25519_sk: Uint8Array,
    sender_x25519_pub: Uint8Array,
    our_mlkem_dk: Uint8Array,
    authenticated_ciphertext: Uint8Array,
    sender_identity_pk: Uint8Array,
) -> Result<Buffer> {
    match vollcrypt_core::pqc::authenticated_kem_decapsulate(
        our_x25519_sk.as_ref(),
        sender_x25519_pub.as_ref(),
        our_mlkem_dk.as_ref(),
        authenticated_ciphertext.as_ref(),
        sender_identity_pk.as_ref(),
    ) {
        Ok(ss) => Ok(Buffer::from(ss)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// ==================== Device Authorization Registry ====================

#[napi]
pub fn registry_empty() -> String {
    let registry = vollcrypt_core::DefaultDeviceRegistry::new();
    registry.to_json().unwrap_or_else(|_| "{\"devices\":[]}".to_string())
}

#[napi]
pub fn registry_add_device(
    registry_json: String,
    device_id: String,
    name: String,
    added_at: u32,
    public_key: String,
) -> Result<String> {
    let mut registry = vollcrypt_core::DefaultDeviceRegistry::from_json(&registry_json)
        .map_err(|e| Error::from_reason(e.to_string()))?;
        
    let device = vollcrypt_core::Device {
        device_id,
        name,
        added_at: added_at as u64,
        public_key,
        is_revoked: false,
    };
    
    registry.add_device(device).map_err(|e| Error::from_reason(e.to_string()))?;
    
    registry.to_json().map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn registry_revoke_device(registry_json: String, device_id: String) -> Result<String> {
    let mut registry = vollcrypt_core::DefaultDeviceRegistry::from_json(&registry_json)
        .map_err(|e| Error::from_reason(e.to_string()))?;
        
    registry.revoke_device(&device_id).map_err(|e| Error::from_reason(e.to_string()))?;
    
    registry.to_json().map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn registry_get_active_devices(registry_json: String) -> Result<String> {
    let registry = vollcrypt_core::DefaultDeviceRegistry::from_json(&registry_json)
        .map_err(|e| Error::from_reason(e.to_string()))?;
        
    registry.get_active_devices_json().map_err(|e| Error::from_reason(e.to_string()))
}

// ==================== Post-Compromise Security (PCS) ====================

#[napi]
pub fn generate_ratchet_keypair() -> Result<Vec<Buffer>> {
    match vollcrypt_core::generate_ratchet_keypair() {
        Ok(kp) => Ok(vec![Buffer::from(kp.secret_key().to_vec()), Buffer::from(kp.public_key.to_vec())]),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn ratchet_srk(
    current_srk: Uint8Array,
    our_ratchet_secret: Uint8Array,
    their_ratchet_pub: Uint8Array,
    chat_id: Uint8Array,
    ratchet_step: u32,
    is_sender: bool,
) -> Result<Buffer> {
    if current_srk.len() != 32 || our_ratchet_secret.len() != 32 || their_ratchet_pub.len() != 32 {
        return Err(Error::from_reason("Keys must be 32 bytes".to_string()));
    }

    let mut current_srk_arr = [0u8; 32];
    current_srk_arr.copy_from_slice(current_srk.as_ref());
    let mut our_secret_arr = [0u8; 32];
    our_secret_arr.copy_from_slice(our_ratchet_secret.as_ref());
    let mut their_pub_arr = [0u8; 32];
    their_pub_arr.copy_from_slice(their_ratchet_pub.as_ref());

    let result = if is_sender {
        vollcrypt_core::ratchet_srk_sender(
            &current_srk_arr,
            &our_secret_arr,
            &their_pub_arr,
            chat_id.as_ref(),
            ratchet_step as u64,
        )
    } else {
        vollcrypt_core::ratchet_srk_receiver(
            &current_srk_arr,
            &our_secret_arr,
            &their_pub_arr,
            chat_id.as_ref(),
            ratchet_step as u64,
        )
    };

    match result {
        Ok(new_srk) => Ok(Buffer::from(new_srk.to_vec())),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
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

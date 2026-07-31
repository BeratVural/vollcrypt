use napi::{
    bindgen_prelude::{BigInt, Buffer, Uint8Array},
    Error, Result,
};
use napi_derive::napi;
use zeroize::Zeroize;

fn bigint_to_u64(value: BigInt, field: &str) -> Result<u64> {
    let (negative, value, lossless) = value.get_u64();
    if negative || !lossless {
        return Err(Error::from_reason(format!(
            "{field} must be an unsigned 64-bit BigInt"
        )));
    }
    Ok(value)
}

#[napi]
pub fn generate_mnemonic() -> String {
    vollcrypt_core::generate_mnemonic()
}

#[napi]
pub fn mnemonic_to_seed(phrase: String, password: Option<String>) -> Result<Buffer> {
    let mut phrase = phrase;
    let mut password = password;
    let res = vollcrypt_core::mnemonic_to_seed(&phrase, password.as_deref());

    unsafe {
        phrase.as_mut_vec().zeroize();
        if let Some(ref mut pwd) = password {
            pwd.as_mut_vec().zeroize();
        }
    }

    match res {
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
    let mut secret_copy = our_secret.as_ref().to_vec();
    let res = vollcrypt_core::ecdh_shared_secret(&secret_copy, their_public.as_ref());
    secret_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn sign_message(secret_key: Uint8Array, message: Uint8Array) -> Result<Buffer> {
    let mut sk_copy = secret_key.as_ref().to_vec();
    let res = vollcrypt_core::sign_message(&sk_copy, message.as_ref());
    sk_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn sign_fresh_message(
    secret_key: Uint8Array,
    message_id: Uint8Array,
    timestamp_ms: BigInt,
    payload: Uint8Array,
) -> Result<Buffer> {
    let timestamp_ms = bigint_to_u64(timestamp_ms, "timestamp_ms")?;
    let mut sk_copy = secret_key.as_ref().to_vec();
    let result = vollcrypt_core::sign_fresh_message(
        &sk_copy,
        message_id.as_ref(),
        timestamp_ms,
        payload.as_ref(),
    );
    sk_copy.zeroize();

    result
        .map(Buffer::from)
        .map_err(|error| Error::from_reason(error.to_string()))
}

#[napi]
pub struct ReplayProtectionStore {
    inner: std::sync::Mutex<vollcrypt_core::ReplayProtectionStore>,
}

#[napi]
impl ReplayProtectionStore {
    #[napi(constructor)]
    pub fn new(validity_window_ms: Option<BigInt>, max_entries: Option<u32>) -> Result<Self> {
        let validity_window_ms = match validity_window_ms {
            Some(value) => bigint_to_u64(value, "validity_window_ms")?,
            None => 300_000,
        };
        let max_entries = max_entries.unwrap_or(100_000) as usize;
        let inner = vollcrypt_core::ReplayProtectionStore::new(validity_window_ms, max_entries)
            .map_err(|error| Error::from_reason(error.to_string()))?;

        Ok(Self {
            inner: std::sync::Mutex::new(inner),
        })
    }

    #[napi]
    pub fn verify_and_record(
        &self,
        public_key: Uint8Array,
        message_id: Uint8Array,
        timestamp_ms: BigInt,
        now_ms: BigInt,
        payload: Uint8Array,
        signature: Uint8Array,
    ) -> Result<bool> {
        let timestamp_ms = bigint_to_u64(timestamp_ms, "timestamp_ms")?;
        let now_ms = bigint_to_u64(now_ms, "now_ms")?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("replay protection store lock poisoned".to_string()))?;

        inner
            .verify_and_record(
                public_key.as_ref(),
                message_id.as_ref(),
                timestamp_ms,
                now_ms,
                payload.as_ref(),
                signature.as_ref(),
            )
            .map_err(|error| Error::from_reason(error.to_string()))?;
        Ok(true)
    }

    #[napi(getter)]
    pub fn size(&self) -> Result<u32> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("replay protection store lock poisoned".to_string()))?;
        u32::try_from(inner.len())
            .map_err(|_| Error::from_reason("replay protection store size overflow".to_string()))
    }

    #[napi]
    pub fn clear(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::from_reason("replay protection store lock poisoned".to_string()))?;
        inner.clear();
        Ok(())
    }
}

#[napi]
pub fn verify_signature(
    public_key: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    entries_json: Option<String>,
) -> bool {
    if let Some(ref json_str) = entries_json {
        if !json_str.is_empty() {
            match serde_json::from_str::<Vec<vollcrypt_core::key_log::KeyLogEntry>>(json_str) {
                Ok(entries) => {
                    let log = vollcrypt_core::key_log::KeyLog { entries };
                    if log.verify_chain().is_ok() {
                        if let Ok(pk_arr) = <&[u8; 32]>::try_from(public_key.as_ref()) {
                            let mut is_revoked = false;
                            for entry in &log.entries {
                                if &entry.public_key == pk_arr
                                    && entry.action == vollcrypt_core::key_log::KeyAction::Revoke
                                {
                                    is_revoked = true;
                                    break;
                                }
                            }
                            if is_revoked {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                Err(_) => {
                    return false;
                }
            }
        }
    }

    vollcrypt_core::verify_signature(public_key.as_ref(), message.as_ref(), signature.as_ref())
}

#[napi]
pub fn encrypt_aes_gcm(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Option<Uint8Array>,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::encrypt_aes256gcm(&key_copy, plaintext.as_ref(), aad_ref);
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn decrypt_aes_gcm(
    key: Uint8Array,
    ciphertext: Uint8Array,
    aad: Option<Uint8Array>,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::decrypt_aes256gcm(&key_copy, ciphertext.as_ref(), aad_ref);
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn encrypt_aes_gcm_padded(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Option<Uint8Array>,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::encrypt_aes256gcm_padded(&key_copy, plaintext.as_ref(), aad_ref);
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn decrypt_aes_gcm_padded(
    key: Uint8Array,
    ciphertext: Uint8Array,
    aad: Option<Uint8Array>,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::decrypt_aes256gcm_padded(&key_copy, ciphertext.as_ref(), aad_ref);
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn encrypt_aes_gcm_chunked(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Option<Uint8Array>,
    chunk_size: u32,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::encrypt_aes256gcm_chunked(
        &key_copy,
        plaintext.as_ref(),
        aad_ref,
        chunk_size as usize,
    );
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn decrypt_aes_gcm_chunked(
    key: Uint8Array,
    ciphertext: Uint8Array,
    aad: Option<Uint8Array>,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::decrypt_aes256gcm_chunked(&key_copy, ciphertext.as_ref(), aad_ref);
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn encrypt_aes_gcm_chunked_padded(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Option<Uint8Array>,
    chunk_size: u32,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::encrypt_aes256gcm_chunked_padded(
        &key_copy,
        plaintext.as_ref(),
        aad_ref,
        chunk_size as usize,
    );
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn decrypt_aes_gcm_chunked_padded(
    key: Uint8Array,
    ciphertext: Uint8Array,
    aad: Option<Uint8Array>,
) -> Result<Buffer> {
    let mut key_copy = key.as_ref().to_vec();
    let aad_ref = aad.as_ref().map(|x| x.as_ref());
    let res =
        vollcrypt_core::decrypt_aes256gcm_chunked_padded(&key_copy, ciphertext.as_ref(), aad_ref);
    key_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn derive_pbkdf2(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: u32,
    key_len: u32,
) -> napi::Result<Buffer> {
    let mut password_copy = password.as_ref().to_vec();
    let res =
        vollcrypt_core::derive_pbkdf2(&password_copy, salt.as_ref(), iterations, key_len as usize);
    password_copy.zeroize();
    let key = res.map_err(napi::Error::from_reason)?;
    Ok(Buffer::from(key))
}

#[napi]
pub fn derive_hkdf(
    ikm: Uint8Array,
    salt: Option<Uint8Array>,
    info: Option<Uint8Array>,
    key_len: u32,
) -> Result<Buffer> {
    let mut ikm_copy = ikm.as_ref().to_vec();
    let salt_ref = salt.as_ref().map(|x| x.as_ref());
    let info_ref = info.as_ref().map(|x| x.as_ref());
    let res = vollcrypt_core::derive_hkdf(ikm_copy.as_ref(), salt_ref, info_ref, key_len as usize);
    ikm_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn derive_srk(dek: Uint8Array, chat_id: Uint8Array) -> Result<Buffer> {
    let mut dek_copy = dek.as_ref().to_vec();
    let res = vollcrypt_core::derive_srk(dek_copy.as_ref(), chat_id.as_ref());
    dek_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn derive_window_key(srk: Uint8Array, window_index: BigInt) -> Result<Buffer> {
    let window_index = bigint_to_u64(window_index, "window_index")?;
    let mut srk_copy = srk.as_ref().to_vec();
    let res = vollcrypt_core::derive_window_key(srk_copy.as_ref(), window_index);
    srk_copy.zeroize();
    match res {
        Ok(v) => Ok(Buffer::from(v)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn generate_verification_code(
    key_a: Uint8Array,
    key_b: Uint8Array,
    conversation_id: Uint8Array,
) -> Result<String> {
    let key_a_slice = key_a.as_ref();
    let key_b_slice = key_b.as_ref();

    if key_a_slice.len() != 32 {
        return Err(Error::from_reason("key_a must be 32 bytes"));
    }
    if key_b_slice.len() != 32 {
        return Err(Error::from_reason("key_b must be 32 bytes"));
    }

    let mut ka = [0u8; 32];
    ka.copy_from_slice(key_a_slice);

    let mut kb = [0u8; 32];
    kb.copy_from_slice(key_b_slice);

    let code = vollcrypt_core::verification::generate_verification_code(
        &ka,
        &kb,
        conversation_id.as_ref(),
    );

    ka.zeroize();
    kb.zeroize();

    serde_json::to_string(&code)
        .map_err(|e| Error::from_reason(format!("Serialization failed: {}", e)))
}

#[napi]
pub fn compute_fingerprint(
    key_a: Uint8Array,
    key_b: Uint8Array,
    conversation_id: Uint8Array,
) -> Result<Buffer> {
    let key_a_slice = key_a.as_ref();
    let key_b_slice = key_b.as_ref();

    if key_a_slice.len() != 32 {
        return Err(Error::from_reason("key_a must be 32 bytes"));
    }
    if key_b_slice.len() != 32 {
        return Err(Error::from_reason("key_b must be 32 bytes"));
    }

    let mut ka = [0u8; 32];
    ka.copy_from_slice(key_a_slice);

    let mut kb = [0u8; 32];
    kb.copy_from_slice(key_b_slice);

    let fp = vollcrypt_core::verification::compute_fingerprint(&ka, &kb, conversation_id.as_ref());

    ka.zeroize();
    kb.zeroize();

    Ok(Buffer::from(fp.to_vec()))
}

#[napi]
pub fn verify_fingerprints_match(
    fingerprint_a: Uint8Array,
    fingerprint_b: Uint8Array,
) -> Result<bool> {
    let fa_slice = fingerprint_a.as_ref();
    let fb_slice = fingerprint_b.as_ref();

    if fa_slice.len() != 32 {
        return Err(Error::from_reason("fingerprint_a must be 32 bytes"));
    }
    if fb_slice.len() != 32 {
        return Err(Error::from_reason("fingerprint_b must be 32 bytes"));
    }

    let mut fa = [0u8; 32];
    fa.copy_from_slice(fa_slice);

    let mut fb = [0u8; 32];
    fb.copy_from_slice(fb_slice);

    Ok(vollcrypt_core::verification::verify_fingerprints_match(
        &fa, &fb,
    ))
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
pub fn pack_envelope(
    window_index: u32,
    aad_hash: Uint8Array,
    encrypted_blob: Uint8Array,
) -> Result<Buffer> {
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
    let mut dk_copy = decapsulation_key.as_ref().to_vec();
    let res = vollcrypt_core::ml_kem_decapsulate(&dk_copy, ciphertext.as_ref());
    dk_copy.zeroize();
    match res {
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
    let mut our_secret_copy = x25519_our_secret.as_ref().to_vec();
    let res = vollcrypt_core::hybrid_kem_encapsulate(
        &our_secret_copy,
        x25519_their_public.as_ref(),
        ml_kem_ek.as_ref(),
    );
    our_secret_copy.zeroize();
    match res {
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
    let mut our_secret_copy = x25519_our_secret.as_ref().to_vec();
    let mut ml_kem_dk_copy = ml_kem_dk.as_ref().to_vec();
    let res = vollcrypt_core::hybrid_kem_decapsulate(
        &our_secret_copy,
        x25519_their_public.as_ref(),
        &ml_kem_dk_copy,
        ml_kem_ct.as_ref(),
    );
    our_secret_copy.zeroize();
    ml_kem_dk_copy.zeroize();
    match res {
        Ok(key) => Ok(Buffer::from(key)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn authenticated_kem_encapsulate(
    our_x25519_sk: Uint8Array,
    recipient_x25519_pub: Uint8Array,
    recipient_mlkem_pub: Uint8Array,
    sender_identity_sk: Uint8Array,
) -> Result<Vec<Buffer>> {
    let mut our_x25519_sk_copy = our_x25519_sk.as_ref().to_vec();
    let mut sender_identity_sk_copy = sender_identity_sk.as_ref().to_vec();
    let res = vollcrypt_core::pqc::authenticated_kem_encapsulate(
        &our_x25519_sk_copy,
        recipient_x25519_pub.as_ref(),
        recipient_mlkem_pub.as_ref(),
        &sender_identity_sk_copy,
    );
    our_x25519_sk_copy.zeroize();
    sender_identity_sk_copy.zeroize();
    match res {
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
    let mut our_x25519_sk_copy = our_x25519_sk.as_ref().to_vec();
    let mut our_mlkem_dk_copy = our_mlkem_dk.as_ref().to_vec();
    let res = vollcrypt_core::pqc::authenticated_kem_decapsulate(
        &our_x25519_sk_copy,
        sender_x25519_pub.as_ref(),
        &our_mlkem_dk_copy,
        authenticated_ciphertext.as_ref(),
        sender_identity_pk.as_ref(),
    );
    our_x25519_sk_copy.zeroize();
    our_mlkem_dk_copy.zeroize();
    match res {
        Ok(ss) => Ok(Buffer::from(ss)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// ==================== Device Authorization Registry ====================

#[napi]
pub fn registry_empty() -> String {
    let registry = vollcrypt_core::DefaultDeviceRegistry::new();
    registry
        .to_json()
        .unwrap_or_else(|_| "{\"devices\":[]}".to_string())
}

#[napi]
pub fn registry_add_device(
    registry_json: String,
    device_id: String,
    name: String,
    added_at: BigInt,
    public_key: String,
) -> Result<String> {
    let added_at = bigint_to_u64(added_at, "added_at")?;
    let mut registry = vollcrypt_core::DefaultDeviceRegistry::from_json(&registry_json)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    let device = vollcrypt_core::Device {
        device_id,
        name,
        added_at,
        public_key,
        is_revoked: false,
    };

    registry
        .add_device(device)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    registry
        .to_json()
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn registry_revoke_device(registry_json: String, device_id: String) -> Result<String> {
    let mut registry = vollcrypt_core::DefaultDeviceRegistry::from_json(&registry_json)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    registry
        .revoke_device(&device_id)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    registry
        .to_json()
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn registry_get_active_devices(registry_json: String) -> Result<String> {
    let registry = vollcrypt_core::DefaultDeviceRegistry::from_json(&registry_json)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    registry
        .get_active_devices_json()
        .map_err(|e| Error::from_reason(e.to_string()))
}

// ==================== Post-Compromise Security (PCS) ====================

#[napi]
pub fn generate_ratchet_keypair() -> Result<Vec<Buffer>> {
    match vollcrypt_core::generate_ratchet_keypair() {
        Ok(kp) => Ok(vec![
            Buffer::from(kp.secret_key().to_vec()),
            Buffer::from(kp.public_key.to_vec()),
        ]),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn ratchet_srk(
    current_srk: Uint8Array,
    our_ratchet_secret: Uint8Array,
    their_ratchet_pub: Uint8Array,
    chat_id: Uint8Array,
    ratchet_step: BigInt,
    is_sender: bool,
) -> Result<Buffer> {
    let ratchet_step = bigint_to_u64(ratchet_step, "ratchet_step")?;
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
            ratchet_step,
        )
    } else {
        vollcrypt_core::ratchet_srk_receiver(
            &current_srk_arr,
            &our_secret_arr,
            &their_pub_arr,
            chat_id.as_ref(),
            ratchet_step,
        )
    };

    current_srk_arr.zeroize();
    our_secret_arr.zeroize();
    their_pub_arr.zeroize();

    match result {
        Ok(mut new_srk) => {
            let output = Buffer::from(new_srk.to_vec());
            new_srk.zeroize();
            Ok(output)
        }
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

// ==================== Transcript Hashing ====================

#[napi]
pub fn transcript_new(session_id: Uint8Array) -> Buffer {
    let ts = vollcrypt_core::transcript::TranscriptState::new(session_id.as_ref());
    Buffer::from(ts.to_bytes().to_vec())
}

#[napi]
pub fn transcript_update(chain_state: Uint8Array, message_hash: Uint8Array) -> Result<Buffer> {
    if chain_state.len() != 32 || message_hash.len() != 32 {
        return Err(Error::from_reason(
            "chain_state and message_hash must be 32 bytes".to_string(),
        ));
    }
    let mut state_bytes = [0u8; 32];
    state_bytes.copy_from_slice(chain_state.as_ref());
    let mut msg_hash_bytes = [0u8; 32];
    msg_hash_bytes.copy_from_slice(message_hash.as_ref());

    let mut ts = vollcrypt_core::transcript::TranscriptState::from_bytes(state_bytes);
    ts.update(&msg_hash_bytes);
    Ok(Buffer::from(ts.to_bytes().to_vec()))
}

#[napi]
pub fn transcript_compute_message_hash(
    message_id: Uint8Array,
    sender_id: Uint8Array,
    timestamp: BigInt,
    ciphertext: Uint8Array,
) -> Result<Buffer> {
    let timestamp = bigint_to_u64(timestamp, "timestamp")?;
    let hash = vollcrypt_core::transcript::TranscriptState::compute_message_hash(
        message_id.as_ref(),
        sender_id.as_ref(),
        timestamp,
        ciphertext.as_ref(),
    );
    Ok(Buffer::from(hash.to_vec()))
}

#[napi]
pub fn transcript_verify_sync(hash_a: Uint8Array, hash_b: Uint8Array) -> Result<bool> {
    if hash_a.len() != 32 || hash_b.len() != 32 {
        return Err(Error::from_reason("Hashes must be 32 bytes".to_string()));
    }
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(hash_a.as_ref());
    let mut b_bytes = [0u8; 32];
    b_bytes.copy_from_slice(hash_b.as_ref());

    Ok(vollcrypt_core::transcript::TranscriptState::verify_sync(
        &a_bytes, &b_bytes,
    ))
}

// ==================== Sealed Sender ====================

#[napi]
pub fn seal_message(
    recipient_x25519_pub: Uint8Array,
    sender_id: Uint8Array,
    content: Uint8Array,
    sender_signing_key: Uint8Array,
) -> Result<Buffer> {
    if recipient_x25519_pub.len() != 32 {
        return Err(Error::from_reason(
            "recipient_x25519_pub must be 32 bytes".to_string(),
        ));
    }
    if sender_signing_key.len() != 32 {
        return Err(Error::from_reason(
            "sender_signing_key must be 32 bytes".to_string(),
        ));
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(recipient_x25519_pub.as_ref());

    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(sender_signing_key.as_ref());

    let res = vollcrypt_core::sealed_sender::seal(
        &pub_bytes,
        sender_id.as_ref(),
        content.as_ref(),
        &sk_bytes,
    );
    sk_bytes.zeroize();

    match res {
        Ok(sealed) => Ok(Buffer::from(sealed)),
        Err(e) => Err(Error::from_reason(format!("Sealing failed: {:?}", e))),
    }
}

#[napi]
pub fn unseal_message(
    sealed_packet: Uint8Array,
    our_x25519_sk: Uint8Array,
    entries_json: Option<String>,
    trusted_sender_public_key: Uint8Array,
) -> Result<Vec<Buffer>> {
    if our_x25519_sk.len() != 32 {
        return Err(Error::from_reason(
            "our_x25519_sk must be 32 bytes".to_string(),
        ));
    }
    if trusted_sender_public_key.len() != 32 {
        return Err(Error::from_reason(
            "trusted_sender_public_key must be 32 bytes".to_string(),
        ));
    }

    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(our_x25519_sk.as_ref());
    let mut trusted_pk = [0u8; 32];
    trusted_pk.copy_from_slice(trusted_sender_public_key.as_ref());

    let res = vollcrypt_core::sealed_sender::unseal(
        sealed_packet.as_ref(),
        &sk_bytes,
        entries_json.as_deref(),
        Some(&trusted_pk),
    );
    sk_bytes.zeroize();
    match res {
        Ok((sender_id, content)) => Ok(vec![Buffer::from(sender_id), Buffer::from(content)]),
        Err(e) => Err(Error::from_reason(format!("Unsealing failed: {:?}", e))),
    }
}

// ==================== Key Transparency (Key Log) ====================

#[napi]
pub fn key_log_create_entry(
    user_id: Uint8Array,
    public_key: Uint8Array,
    timestamp: BigInt,
    prev_entry_hash: Uint8Array,
    action: u8,
    signing_key: Uint8Array,
) -> Result<String> {
    let timestamp = bigint_to_u64(timestamp, "timestamp")?;
    if public_key.len() != 32 || prev_entry_hash.len() != 32 || signing_key.len() != 32 {
        return Err(Error::from_reason(
            "Key lengths must be exactly 32 bytes".to_string(),
        ));
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_key.as_ref());
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(prev_entry_hash.as_ref());
    let mut sign_key = [0u8; 32];
    sign_key.copy_from_slice(signing_key.as_ref());

    let act = vollcrypt_core::key_log::KeyAction::try_from(action).map_err(|_| {
        sign_key.zeroize();
        Error::from_reason("Invalid action type".to_string())
    })?;

    let res = vollcrypt_core::key_log::create_entry(
        user_id.as_ref(),
        &pk,
        timestamp,
        &prev_hash,
        act,
        &sign_key,
    );

    sign_key.zeroize();

    match res {
        Ok(entry) => serde_json::to_string(&entry).map_err(|e| Error::from_reason(e.to_string())),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn key_log_verify_chain(entries_json: String) -> Result<bool> {
    let entries: Vec<vollcrypt_core::key_log::KeyLogEntry> = serde_json::from_str(&entries_json)
        .map_err(|e| Error::from_reason(format!("Invalid JSON array: {}", e)))?;

    let log = vollcrypt_core::key_log::KeyLog { entries };
    match log.verify_chain() {
        Ok(_) => Ok(true),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn key_log_current_key(entries_json: String, user_id: Uint8Array) -> Result<Option<Buffer>> {
    let entries: Vec<vollcrypt_core::key_log::KeyLogEntry> = serde_json::from_str(&entries_json)
        .map_err(|e| Error::from_reason(format!("Invalid JSON array: {}", e)))?;

    let log = vollcrypt_core::key_log::KeyLog { entries };
    log.verify_chain()
        .map_err(|e| Error::from_reason(e.to_string()))?;
    match log.current_key_for(user_id.as_ref()) {
        Some(k) => Ok(Some(Buffer::from(k.to_vec()))),
        None => Ok(None),
    }
}

#[napi]
pub fn key_log_key_at_timestamp(
    entries_json: String,
    user_id: Uint8Array,
    timestamp: BigInt,
) -> Result<Option<Buffer>> {
    let timestamp = bigint_to_u64(timestamp, "timestamp")?;
    let entries: Vec<vollcrypt_core::key_log::KeyLogEntry> = serde_json::from_str(&entries_json)
        .map_err(|e| Error::from_reason(format!("Invalid JSON array: {}", e)))?;

    let log = vollcrypt_core::key_log::KeyLog { entries };
    log.verify_chain()
        .map_err(|e| Error::from_reason(e.to_string()))?;
    match log.key_at_timestamp(user_id.as_ref(), timestamp) {
        Some(k) => Ok(Some(Buffer::from(k.to_vec()))),
        None => Ok(None),
    }
}

#[napi]
pub fn key_log_compute_entry_hash(entry_json: String) -> Result<Buffer> {
    let entry: vollcrypt_core::key_log::KeyLogEntry = serde_json::from_str(&entry_json)
        .map_err(|e| Error::from_reason(format!("Invalid JSON object: {}", e)))?;

    let hash = entry.compute_hash();
    Ok(Buffer::from(hash.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use napi::bindgen_prelude::Uint8Array;
    use vollcrypt_core::key_log::{create_entry, KeyAction, GENESIS_HASH};
    use vollcrypt_core::keys::{generate_ed25519_keypair, sign_message};

    #[test]
    fn test_verify_signature_revocation() {
        let (sk, pk) = generate_ed25519_keypair();
        let message = b"Hello revoked world!";
        let signature = sign_message(&sk, message).unwrap();

        let pk_ua = Uint8Array::from(pk.clone());
        let msg_ua = Uint8Array::from(message.to_vec());
        let sig_ua = Uint8Array::from(signature);

        // Case 1: No entries_json passed
        assert!(verify_signature(
            pk_ua.clone(),
            msg_ua.clone(),
            sig_ua.clone(),
            None
        ));

        // Case 2: Empty entries_json passed
        assert!(verify_signature(
            pk_ua.clone(),
            msg_ua.clone(),
            sig_ua.clone(),
            Some("".to_string())
        ));

        // Case 3: Key log without revocation
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk);

        let entry = create_entry(
            b"alice",
            &pk_arr,
            1000,
            &GENESIS_HASH,
            KeyAction::Add,
            &sk_arr,
        )
        .unwrap();
        let entries = vec![entry];
        let entries_json = serde_json::to_string(&entries).unwrap();

        assert!(verify_signature(
            pk_ua.clone(),
            msg_ua.clone(),
            sig_ua.clone(),
            Some(entries_json)
        ));

        // Case 4: Key log with active revocation
        let entry_add = create_entry(
            b"alice",
            &pk_arr,
            1000,
            &GENESIS_HASH,
            KeyAction::Add,
            &sk_arr,
        )
        .unwrap();
        let add_hash = entry_add.compute_hash();
        let entry_revoke = create_entry(
            b"alice",
            &pk_arr,
            2000,
            &add_hash,
            KeyAction::Revoke,
            &sk_arr,
        )
        .unwrap();
        let entries = vec![entry_add, entry_revoke];
        let entries_json_revoked = serde_json::to_string(&entries).unwrap();

        assert!(!verify_signature(
            pk_ua.clone(),
            msg_ua.clone(),
            sig_ua.clone(),
            Some(entries_json_revoked)
        ));
    }
}

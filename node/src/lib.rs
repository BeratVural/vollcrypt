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

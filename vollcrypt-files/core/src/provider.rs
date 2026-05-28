use crate::error::FileFormatError;
use crate::buffer_pool::PooledBuffer;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait CryptoProvider: Send + Sync {
    fn encrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), FileFormatError>;

    fn decrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, FileFormatError>;

    fn encrypt_in_place(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], FileFormatError>;

    fn decrypt_in_place(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), FileFormatError>;

    fn encrypt_async(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: Vec<u8>,
    ) -> BoxFuture<'static, Result<(Vec<u8>, [u8; 16]), FileFormatError>> {
        let key = *key;
        let iv = *iv;
        let aad = aad.to_vec();
        let res = self.encrypt(&key, &iv, &aad, &plaintext);
        Box::pin(async move { res })
    }

    fn decrypt_async(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext: Vec<u8>,
        tag: [u8; 16],
    ) -> BoxFuture<'static, Result<Vec<u8>, FileFormatError>> {
        let key = *key;
        let iv = *iv;
        let aad = aad.to_vec();
        let res = self.decrypt(&key, &iv, &aad, &ciphertext, &tag);
        Box::pin(async move { res })
    }

    fn encrypt_in_place_async(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        mut buffer: PooledBuffer,
        len: usize,
    ) -> BoxFuture<'static, Result<(PooledBuffer, [u8; 16]), FileFormatError>> {
        let key = *key;
        let iv = *iv;
        let aad = aad.to_vec();
        let res = self.encrypt_in_place(&key, &iv, &aad, buffer.as_plaintext_mut(len));
        Box::pin(async move {
            let tag = res?;
            Ok((buffer, tag))
        })
    }

    fn decrypt_in_place_async(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        mut buffer: PooledBuffer,
        len: usize,
        tag: [u8; 16],
    ) -> BoxFuture<'static, Result<PooledBuffer, FileFormatError>> {
        let key = *key;
        let iv = *iv;
        let aad = aad.to_vec();
        let res = self.decrypt_in_place(&key, &iv, &aad, buffer.as_ciphertext_mut(len), &tag);
        Box::pin(async move {
            res?;
            Ok(buffer)
        })
    }
}

pub struct NativeCryptoProvider;

impl CryptoProvider for NativeCryptoProvider {
    fn encrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), FileFormatError> {
        use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce};
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
        let nonce = Nonce::from_slice(iv);
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
            
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(&tag);
        Ok((buffer, tag_arr))
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, FileFormatError> {
        use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce, Tag};
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
        let nonce = Nonce::from_slice(iv);
        let tag_obj = Tag::from_slice(tag);
        let mut buffer = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, aad, &mut buffer, tag_obj)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
            
        Ok(buffer)
    }

    fn encrypt_in_place(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], FileFormatError> {
        use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce};
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
        let nonce = Nonce::from_slice(iv);
        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, buffer)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
            
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(&tag);
        Ok(tag_arr)
    }

    fn decrypt_in_place(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), FileFormatError> {
        use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce, Tag};
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
        let nonce = Nonce::from_slice(iv);
        let tag_obj = Tag::from_slice(tag);
        cipher
            .decrypt_in_place_detached(nonce, aad, buffer, tag_obj)
            .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;
            
        Ok(())
    }
}

static PROVIDER: OnceLock<Box<dyn CryptoProvider>> = OnceLock::new();

pub fn set_crypto_provider(provider: Box<dyn CryptoProvider>) -> Result<(), &'static str> {
    PROVIDER.set(provider).map_err(|_| "Crypto provider already set")
}

pub fn get_crypto_provider() -> &'static dyn CryptoProvider {
    PROVIDER.get_or_init(|| Box::new(NativeCryptoProvider)).as_ref()
}

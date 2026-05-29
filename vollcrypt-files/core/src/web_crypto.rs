#![cfg(target_arch = "wasm32")]

use crate::error::FileFormatError;
use crate::provider::{BoxFuture, CryptoProvider};
use js_sys::Object;
use wasm_bindgen::{JsCast, JsValue};

pub struct WasmWebCryptoProvider;

fn get_subtle_crypto() -> Result<web_sys::SubtleCrypto, FileFormatError> {
    let global = js_sys::global();
    let crypto_val = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|e| FileFormatError::IoError(format!("crypto not found: {:?}", e)))?;
    if crypto_val.is_undefined() || crypto_val.is_null() {
        return Err(FileFormatError::IoError(
            "crypto is undefined/null".to_string(),
        ));
    }
    let crypto: web_sys::Crypto = crypto_val.into();
    Ok(crypto.subtle())
}

static USE_ZERO_COPY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

async fn check_zero_copy_support() -> bool {
    // Attempt a 1-byte WebCrypto encryption using a direct WASM memory view.
    // If it succeeds, zero-copy is supported. If it throws a security error, fallback to copy.
    let subtle = match get_subtle_crypto() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let key_data = [0u8; 32];
    let iv_data = [0u8; 12];
    let plain_data = [0u8; 1];

    // Create direct view over plain_data stack buffer
    let memory = wasm_bindgen::memory();
    let memory: js_sys::WebAssembly::Memory = match wasm_bindgen::JsCast::dyn_into(memory) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let buffer = memory.buffer();
    let plain_js = js_sys::Uint8Array::new_with_byte_offset_and_length(
        &buffer,
        plain_data.as_ptr() as u32,
        plain_data.len() as u32,
    );

    let key_js = js_sys::Uint8Array::from(key_data.as_ref());
    let algorithm = Object::new();
    if js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str("AES-GCM"),
    )
    .is_err()
    {
        return false;
    }
    if js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("length"),
        &JsValue::from_f64(256.0),
    )
    .is_err()
    {
        return false;
    }

    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("encrypt"));

    let key_promise =
        match subtle.import_key_with_object("raw", &key_js, &algorithm, false, &usages) {
            Ok(p) => p,
            Err(_) => return false,
        };

    let key_val = match wasm_bindgen_futures::JsFuture::from(key_promise).await {
        Ok(v) => v,
        Err(_) => return false,
    };
    let crypto_key = web_sys::CryptoKey::from(key_val);

    let encrypt_params = Object::new();
    if js_sys::Reflect::set(
        &encrypt_params,
        &JsValue::from_str("name"),
        &JsValue::from_str("AES-GCM"),
    )
    .is_err()
    {
        return false;
    }
    let iv_js = js_sys::Uint8Array::from(iv_data.as_ref());
    if js_sys::Reflect::set(&encrypt_params, &JsValue::from_str("iv"), &iv_js).is_err() {
        return false;
    }
    if js_sys::Reflect::set(
        &encrypt_params,
        &JsValue::from_str("tagLength"),
        &JsValue::from_f64(128.0),
    )
    .is_err()
    {
        return false;
    }

    // Try to encrypt using plain_js (the direct WASM memory view) via reflection
    let encrypt_fn = match js_sys::Reflect::get(&subtle, &JsValue::from_str("encrypt")) {
        Ok(f) => match wasm_bindgen::JsCast::dyn_into::<js_sys::Function>(f) {
            Ok(f) => f,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    let enc_promise = match encrypt_fn.call3(&subtle, &encrypt_params, &crypto_key, &plain_js) {
        Ok(p) => match wasm_bindgen::JsCast::dyn_into::<js_sys::Promise>(p) {
            Ok(p) => p,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    match wasm_bindgen_futures::JsFuture::from(enc_promise).await {
        Ok(_) => true,
        Err(_) => false,
    }
}

impl CryptoProvider for WasmWebCryptoProvider {
    fn encrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), FileFormatError> {
        // Fallback to NativeCryptoProvider for sync execution
        crate::provider::NativeCryptoProvider.encrypt(key, iv, aad, plaintext)
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, FileFormatError> {
        // Fallback to NativeCryptoProvider for sync execution
        crate::provider::NativeCryptoProvider.decrypt(key, iv, aad, ciphertext, tag)
    }

    fn encrypt_in_place(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], FileFormatError> {
        crate::provider::NativeCryptoProvider.encrypt_in_place(key, iv, aad, buffer)
    }

    fn decrypt_in_place(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), FileFormatError> {
        crate::provider::NativeCryptoProvider.decrypt_in_place(key, iv, aad, buffer, tag)
    }

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

        Box::pin(async move {
            let subtle = get_subtle_crypto()?;

            // 1. Import Key
            let key_data = js_sys::Uint8Array::from(key.as_ref());
            let algorithm = Object::new();
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("length"),
                &JsValue::from_f64(256.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let usages = js_sys::Array::new();
            usages.push(&JsValue::from_str("encrypt"));

            let key_promise = subtle
                .import_key_with_object("raw", &key_data, &algorithm, false, &usages)
                .map_err(|e| FileFormatError::IoError(format!("importKey error: {:?}", e)))?;

            let key_val = wasm_bindgen_futures::JsFuture::from(key_promise)
                .await
                .map_err(|e| {
                    FileFormatError::IoError(format!("importKey promise error: {:?}", e))
                })?;
            let crypto_key = web_sys::CryptoKey::from(key_val);

            // 2. Encrypt
            let encrypt_params = Object::new();
            js_sys::Reflect::set(
                &encrypt_params,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let iv_js = js_sys::Uint8Array::from(iv.as_ref());
            js_sys::Reflect::set(&encrypt_params, &JsValue::from_str("iv"), &iv_js)
                .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let aad_js = js_sys::Uint8Array::from(aad.as_slice());
            js_sys::Reflect::set(
                &encrypt_params,
                &JsValue::from_str("additionalData"),
                &aad_js,
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            js_sys::Reflect::set(
                &encrypt_params,
                &JsValue::from_str("tagLength"),
                &JsValue::from_f64(128.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let enc_promise = subtle
                .encrypt_with_object_and_u8_array(&encrypt_params, &crypto_key, &plaintext)
                .map_err(|e| FileFormatError::IoError(format!("encrypt error: {:?}", e)))?;

            let enc_val = wasm_bindgen_futures::JsFuture::from(enc_promise)
                .await
                .map_err(|e| FileFormatError::IoError(format!("encrypt promise error: {:?}", e)))?;

            let array_buffer = js_sys::ArrayBuffer::from(enc_val);
            let uint8_array = js_sys::Uint8Array::new(&array_buffer);
            let output_vec = uint8_array.to_vec();

            if output_vec.len() < 16 {
                return Err(FileFormatError::AesGcmDecryptFailed);
            }
            let ciphertext = output_vec[0..output_vec.len() - 16].to_vec();
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&output_vec[output_vec.len() - 16..]);

            Ok((ciphertext, tag))
        })
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

        Box::pin(async move {
            let subtle = get_subtle_crypto()?;

            // 1. Import Key
            let key_data = js_sys::Uint8Array::from(key.as_ref());
            let algorithm = Object::new();
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("length"),
                &JsValue::from_f64(256.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let usages = js_sys::Array::new();
            usages.push(&JsValue::from_str("decrypt"));

            let key_promise = subtle
                .import_key_with_object("raw", &key_data, &algorithm, false, &usages)
                .map_err(|e| FileFormatError::IoError(format!("importKey error: {:?}", e)))?;

            let key_val = wasm_bindgen_futures::JsFuture::from(key_promise)
                .await
                .map_err(|e| {
                    FileFormatError::IoError(format!("importKey promise error: {:?}", e))
                })?;
            let crypto_key = web_sys::CryptoKey::from(key_val);

            // 2. Decrypt
            let decrypt_params = Object::new();
            js_sys::Reflect::set(
                &decrypt_params,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let iv_js = js_sys::Uint8Array::from(iv.as_ref());
            js_sys::Reflect::set(&decrypt_params, &JsValue::from_str("iv"), &iv_js)
                .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let aad_js = js_sys::Uint8Array::from(aad.as_slice());
            js_sys::Reflect::set(
                &decrypt_params,
                &JsValue::from_str("additionalData"),
                &aad_js,
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            js_sys::Reflect::set(
                &decrypt_params,
                &JsValue::from_str("tagLength"),
                &JsValue::from_f64(128.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let mut ct_and_tag = ciphertext;
            ct_and_tag.extend_from_slice(&tag);

            let dec_promise = subtle
                .decrypt_with_object_and_u8_array(&decrypt_params, &crypto_key, &ct_and_tag)
                .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

            let dec_val = wasm_bindgen_futures::JsFuture::from(dec_promise)
                .await
                .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

            let array_buffer = js_sys::ArrayBuffer::from(dec_val);
            let uint8_array = js_sys::Uint8Array::new(&array_buffer);
            let plaintext = uint8_array.to_vec();

            Ok(plaintext)
        })
    }

    fn encrypt_in_place_async(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: crate::buffer_pool::PooledBuffer,
        len: usize,
    ) -> BoxFuture<'static, Result<(crate::buffer_pool::PooledBuffer, [u8; 16]), FileFormatError>>
    {
        let key = *key;
        let iv = *iv;
        let aad = aad.to_vec();

        Box::pin(async move {
            // Determine if we should use zero-copy
            let use_zero_copy = match USE_ZERO_COPY.get() {
                Some(&val) => val,
                None => {
                    let val = check_zero_copy_support().await;
                    let _ = USE_ZERO_COPY.set(val);
                    val
                }
            };

            if !use_zero_copy {
                let provider = crate::provider::NativeCryptoProvider;
                let mut buffer = buffer;
                let tag =
                    provider.encrypt_in_place(&key, &iv, &aad, buffer.as_plaintext_mut(len))?;
                return Ok((buffer, tag));
            }

            let subtle = get_subtle_crypto()?;

            // 1. Import Key
            let key_data = js_sys::Uint8Array::from(key.as_ref());
            let algorithm = Object::new();
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("length"),
                &JsValue::from_f64(256.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let usages = js_sys::Array::new();
            usages.push(&JsValue::from_str("encrypt"));

            let key_promise = subtle
                .import_key_with_object("raw", &key_data, &algorithm, false, &usages)
                .map_err(|e| FileFormatError::IoError(format!("importKey error: {:?}", e)))?;

            let key_val = wasm_bindgen_futures::JsFuture::from(key_promise)
                .await
                .map_err(|e| {
                    FileFormatError::IoError(format!("importKey promise error: {:?}", e))
                })?;
            let crypto_key = web_sys::CryptoKey::from(key_val);

            // 2. Encrypt
            let encrypt_params = Object::new();
            js_sys::Reflect::set(
                &encrypt_params,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let iv_js = js_sys::Uint8Array::from(iv.as_ref());
            js_sys::Reflect::set(&encrypt_params, &JsValue::from_str("iv"), &iv_js)
                .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let aad_js = js_sys::Uint8Array::from(aad.as_slice());
            js_sys::Reflect::set(
                &encrypt_params,
                &JsValue::from_str("additionalData"),
                &aad_js,
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            js_sys::Reflect::set(
                &encrypt_params,
                &JsValue::from_str("tagLength"),
                &JsValue::from_f64(128.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            // Get direct WASM memory view
            let memory = wasm_bindgen::memory();
            let memory: js_sys::WebAssembly::Memory = wasm_bindgen::JsCast::dyn_into(memory)
                .map_err(|e| FileFormatError::IoError(format!("Memory cast error: {:?}", e)))?;
            let plain_js = js_sys::Uint8Array::new_with_byte_offset_and_length(
                &memory.buffer(),
                buffer.plaintext_ptr() as u32,
                len as u32,
            );

            let encrypt_fn = js_sys::Reflect::get(&subtle, &JsValue::from_str("encrypt"))
                .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?
                .dyn_into::<js_sys::Function>()
                .map_err(|e| {
                    FileFormatError::IoError(format!("Cast to function error: {:?}", e))
                })?;

            let enc_promise = encrypt_fn
                .call3(&subtle, &encrypt_params, &crypto_key, &plain_js)
                .map_err(|e| FileFormatError::IoError(format!("encrypt call error: {:?}", e)))?
                .dyn_into::<js_sys::Promise>()
                .map_err(|e| FileFormatError::IoError(format!("Cast to promise error: {:?}", e)))?;

            let enc_val = wasm_bindgen_futures::JsFuture::from(enc_promise)
                .await
                .map_err(|e| FileFormatError::IoError(format!("encrypt promise error: {:?}", e)))?;

            let array_buffer = js_sys::ArrayBuffer::from(enc_val);
            let uint8_array = js_sys::Uint8Array::new(&array_buffer);

            // WebCrypto output ciphertext has tag appended (len + 16)
            let output_len = uint8_array.length() as usize;
            if output_len < 16 {
                return Err(FileFormatError::AesGcmDecryptFailed);
            }
            let ciphertext_len = output_len - 16;
            if ciphertext_len != len {
                return Err(FileFormatError::AesGcmDecryptFailed);
            }

            // Write output array buffer directly to WASM memory view
            let memory = wasm_bindgen::memory();
            let memory: js_sys::WebAssembly::Memory = wasm_bindgen::JsCast::dyn_into(memory)
                .map_err(|e| FileFormatError::IoError(format!("Memory cast error: {:?}", e)))?;
            let dest_view = js_sys::Uint8Array::new_with_byte_offset_and_length(
                &memory.buffer(),
                buffer.ciphertext_ptr() as u32,
                ciphertext_len as u32,
            );

            // Copy ciphertext
            let ct_part = uint8_array.slice(0, ciphertext_len as u32);
            dest_view.set(&ct_part, 0);

            // Extract tag
            let tag_part = uint8_array.slice(ciphertext_len as u32, output_len as u32);
            let mut tag = [0u8; 16];
            tag_part.copy_to(&mut tag);

            Ok((buffer, tag))
        })
    }

    fn decrypt_in_place_async(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        buffer: crate::buffer_pool::PooledBuffer,
        len: usize,
        tag: [u8; 16],
    ) -> BoxFuture<'static, Result<crate::buffer_pool::PooledBuffer, FileFormatError>> {
        let key = *key;
        let iv = *iv;
        let aad = aad.to_vec();

        Box::pin(async move {
            // Determine if we should use zero-copy
            let use_zero_copy = match USE_ZERO_COPY.get() {
                Some(&val) => val,
                None => {
                    let val = check_zero_copy_support().await;
                    let _ = USE_ZERO_COPY.set(val);
                    val
                }
            };

            if !use_zero_copy {
                let provider = crate::provider::NativeCryptoProvider;
                let mut buffer = buffer;
                provider.decrypt_in_place(&key, &iv, &aad, buffer.as_ciphertext_mut(len), &tag)?;
                return Ok(buffer);
            }

            let subtle = get_subtle_crypto()?;

            // 1. Import Key
            let key_data = js_sys::Uint8Array::from(key.as_ref());
            let algorithm = Object::new();
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;
            js_sys::Reflect::set(
                &algorithm,
                &JsValue::from_str("length"),
                &JsValue::from_f64(256.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let usages = js_sys::Array::new();
            usages.push(&JsValue::from_str("decrypt"));

            let key_promise = subtle
                .import_key_with_object("raw", &key_data, &algorithm, false, &usages)
                .map_err(|e| FileFormatError::IoError(format!("importKey error: {:?}", e)))?;

            let key_val = wasm_bindgen_futures::JsFuture::from(key_promise)
                .await
                .map_err(|e| {
                    FileFormatError::IoError(format!("importKey promise error: {:?}", e))
                })?;
            let crypto_key = web_sys::CryptoKey::from(key_val);

            // 2. Decrypt
            let decrypt_params = Object::new();
            js_sys::Reflect::set(
                &decrypt_params,
                &JsValue::from_str("name"),
                &JsValue::from_str("AES-GCM"),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let iv_js = js_sys::Uint8Array::from(iv.as_ref());
            js_sys::Reflect::set(&decrypt_params, &JsValue::from_str("iv"), &iv_js)
                .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            let aad_js = js_sys::Uint8Array::from(aad.as_slice());
            js_sys::Reflect::set(
                &decrypt_params,
                &JsValue::from_str("additionalData"),
                &aad_js,
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            js_sys::Reflect::set(
                &decrypt_params,
                &JsValue::from_str("tagLength"),
                &JsValue::from_f64(128.0),
            )
            .map_err(|e| FileFormatError::IoError(format!("Reflect error: {:?}", e)))?;

            // Get direct WASM memory view
            let memory = wasm_bindgen::memory();
            let memory: js_sys::WebAssembly::Memory = wasm_bindgen::JsCast::dyn_into(memory)
                .map_err(|e| FileFormatError::IoError(format!("Memory cast error: {:?}", e)))?;
            let ct_and_tag_js = js_sys::Uint8Array::new_with_byte_offset_and_length(
                &memory.buffer(),
                buffer.ciphertext_ptr() as u32,
                (len + 16) as u32,
            );

            let decrypt_fn = js_sys::Reflect::get(&subtle, &JsValue::from_str("decrypt"))
                .map_err(|_| FileFormatError::AesGcmDecryptFailed)?
                .dyn_into::<js_sys::Function>()
                .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

            let dec_promise = decrypt_fn
                .call3(&subtle, &decrypt_params, &crypto_key, &ct_and_tag_js)
                .map_err(|_| FileFormatError::AesGcmDecryptFailed)?
                .dyn_into::<js_sys::Promise>()
                .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

            let dec_val = wasm_bindgen_futures::JsFuture::from(dec_promise)
                .await
                .map_err(|_| FileFormatError::AesGcmDecryptFailed)?;

            let array_buffer = js_sys::ArrayBuffer::from(dec_val);
            let uint8_array = js_sys::Uint8Array::new(&array_buffer);

            let pt_len = uint8_array.length() as usize;
            if pt_len != len {
                return Err(FileFormatError::AesGcmDecryptFailed);
            }

            // Write output array buffer directly to WASM memory view
            let memory = wasm_bindgen::memory();
            let memory: js_sys::WebAssembly::Memory = wasm_bindgen::JsCast::dyn_into(memory)
                .map_err(|e| FileFormatError::IoError(format!("Memory cast error: {:?}", e)))?;
            let dest_view = js_sys::Uint8Array::new_with_byte_offset_and_length(
                &memory.buffer(),
                buffer.plaintext_ptr() as u32,
                len as u32,
            );

            dest_view.set(&uint8_array, 0);

            Ok(buffer)
        })
    }
}

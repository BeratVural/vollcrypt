//! Test suite for the WebAssembly integration tests.
#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use vollcrypt_files_wasm::*;
use wasm_bindgen_test::*;

// wasm_bindgen_test_configure!(run_in_browser);


#[wasm_bindgen_test]
fn test_generators() {
    let dek = generate_dek();
    assert_eq!(dek.len(), 32);

    let file_id = generate_file_id();
    assert_eq!(file_id.len(), 16);

    let salt = generate_salt();
    assert_eq!(salt.len(), 16);

    let gk = generate_gk();
    assert_eq!(gk.len(), 32);
}

#[wasm_bindgen_test]
fn test_chunk_encryption() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = b"Hello WASM Crypt Chunk! Quantum is coming.";

    let env_js = encrypt_chunk(&dek, &file_id, 0, plaintext).unwrap();
    let decrypted = decrypt_chunk(&dek, &file_id, 0, env_js).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn test_password_wrapping() {
    let dek = generate_dek();
    let password = "SuperSecretPassword123!";

    let kdf = KdfChoice {
        kind: "Argon2id".to_string(),
        rounds: None,
        m_cost: Some(16384),
        t_cost: Some(1),
        p_cost: Some(1),
        salt: None,
    };
    let kdf_js = serde_wasm_bindgen::to_value(&kdf).unwrap();

    let wrap_js = wrap_dek_with_password(&dek, password, kdf_js).unwrap();
    let unwrapped = unwrap_dek_with_password(wrap_js, password).unwrap();
    assert_eq!(unwrapped, dek);
}

#[wasm_bindgen_test]
fn test_recipient_wrapping() {
    let dek = generate_dek();
    let recipient_id = b"recipient1234567"; // 16 bytes
    let keypair_js = generate_recipient_keypair().unwrap();

    let keypair: RecipientKeypair = serde_wasm_bindgen::from_value(keypair_js).unwrap();
    let pk_js = serde_wasm_bindgen::to_value(&keypair.public_key).unwrap();
    let sk_js = serde_wasm_bindgen::to_value(&keypair.secret_key).unwrap();

    let wrap_js = wrap_key_to_recipient(&dek, recipient_id, 1, pk_js).unwrap();
    let unwrapped = unwrap_key_with_recipient_key(wrap_js, sk_js).unwrap();
    assert_eq!(unwrapped, dek);
}

#[wasm_bindgen_test]
fn test_ed25519() {
    let kp_js = ed25519_keypair_generate().unwrap();
    let kp: Ed25519KeypairObj = serde_wasm_bindgen::from_value(kp_js).unwrap();

    let msg = b"Signature payload for eIDAS verification";
    let sig = ed25519_sign(&kp.secret_key, msg).unwrap();
    let verified = ed25519_verify(&kp.public_key, msg, &sig).unwrap();
    assert!(verified);
}

#[wasm_bindgen_test]
async fn test_async_pipelined_roundtrip() {
    use wasm_bindgen::JsValue;

    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = b"This is a relatively long file plaintext to test async pipelined file encryption and decryption using browser WebCrypto APIs under WASM headless chrome! Let's make sure it works perfectly.";
    let chunk_size = 16;
    let wraps = JsValue::from(js_sys::Array::new());
    let mode = 0; // Mode::Password
    let sign_info = JsValue::null();

    // Call async encrypt
    let enc_result_js = encrypt_file_pipelined_async_wasm(plaintext, &dek, &file_id, chunk_size, wraps, mode, sign_info, JsValue::null()).await.unwrap();
    
    #[derive(serde::Deserialize)]
    struct EncResult {
        ciphertext: Vec<u8>,
    }
    let enc_res: EncResult = serde_wasm_bindgen::from_value(enc_result_js).unwrap();
    
    // Call async decrypt
    let dec_result_js = decrypt_file_pipelined_async_wasm(&enc_res.ciphertext, &dek).await.unwrap();
    
    #[derive(serde::Deserialize)]
    struct DecResult {
        plaintext: Vec<u8>,
    }
    let dec_res: DecResult = serde_wasm_bindgen::from_value(dec_result_js).unwrap();
    
    assert_eq!(dec_res.plaintext, plaintext);
}



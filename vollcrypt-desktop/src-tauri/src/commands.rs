use std::io::{Read, Seek};
use vollcrypt_files_core::{
    encrypt_file_pipelined, decrypt_file_pipelined,
    pipelined_io::{encrypt_file_pipelined_async, decrypt_file_pipelined_async},
    generate_dek, generate_file_id, generate_salt,
    wrap_dek_with_password, unwrap_dek_with_password,
    generate_recipient_keypair, wrap_key_to_recipient, unwrap_key_with_recipient_key,
    Mode, KdfChoice, RecipientPublicKey, RecipientSecretKey,
};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RecipientKeypairJson {
    pub public_key: String,
    pub secret_key: String,
}

// Helper utilities for hex conversion without external dependencies
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex character: {}", e))
        })
        .collect()
}

fn serialize_pk(pk: &RecipientPublicKey) -> String {
    let mut bytes = Vec::with_capacity(1216);
    bytes.extend_from_slice(&pk.x25519);
    bytes.extend_from_slice(pk.ml_kem.as_ref());
    bytes_to_hex(&bytes)
}

fn deserialize_pk(hex: &str) -> Result<RecipientPublicKey, String> {
    let bytes = hex_to_bytes(hex)?;
    if bytes.len() != 1216 {
        return Err(format!("Invalid public key length: expected 1216, got {}", bytes.len()));
    }
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&bytes[0..32]);
    let mut ml_kem = [0u8; 1184];
    ml_kem.copy_from_slice(&bytes[32..1216]);
    Ok(RecipientPublicKey {
        x25519,
        ml_kem: Box::new(ml_kem),
    })
}

fn serialize_sk(sk: &RecipientSecretKey) -> String {
    let mut bytes = Vec::with_capacity(2432);
    bytes.extend_from_slice(&sk.x25519);
    bytes.extend_from_slice(sk.ml_kem.as_ref());
    bytes_to_hex(&bytes)
}

fn deserialize_sk(hex: &str) -> Result<RecipientSecretKey, String> {
    let bytes = hex_to_bytes(hex)?;
    if bytes.len() != 2432 {
        return Err(format!("Invalid secret key length: expected 2432, got {}", bytes.len()));
    }
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&bytes[0..32]);
    let mut ml_kem = [0u8; 2400];
    ml_kem.copy_from_slice(&bytes[32..2432]);
    Ok(RecipientSecretKey {
        x25519,
        ml_kem: Box::new(ml_kem),
    })
}

#[tauri::command]
pub fn generate_keypair() -> Result<RecipientKeypairJson, String> {
    let (pk, sk) = generate_recipient_keypair();
    Ok(RecipientKeypairJson {
        public_key: serialize_pk(&pk),
        secret_key: serialize_sk(&sk),
    })
}

#[tauri::command]
pub async fn encrypt_file_password(
    source_path: String,
    dest_path: String,
    password: String,
    kdf_choice: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let dek = generate_dek();
        let file_id = generate_file_id();

        let kdf = match kdf_choice.as_str() {
            "PBKDF2" => KdfChoice::pbkdf2_default(),
            _ => KdfChoice::argon2id_interactive(),
        };

        let wrap = wrap_dek_with_password(&dek, password.as_bytes(), kdf)
            .map_err(|e| e.to_string())?;

        let source = std::fs::File::open(&source_path)
            .map_err(|e| format!("Failed to open source file: {}", e))?;
        let dest = std::fs::File::create(&dest_path)
            .map_err(|e| format!("Failed to create destination file: {}", e))?;

        encrypt_file_pipelined(
            source,
            dest,
            &dek,
            &file_id,
            1024 * 1024, // 1MB chunks
            vec![wrap],
            Mode::Password,
            4, // 4 worker threads
            None,
            None,
        )
        .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn decrypt_file_password(
    source_path: String,
    dest_path: String,
    password: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut source = std::fs::File::open(&source_path)
            .map_err(|e| format!("Failed to open source file: {}", e))?;
        
        let mut buffer = vec![0u8; 65536];
        let bytes_read = source.read(&mut buffer)
            .map_err(|e| format!("Failed to read file header: {}", e))?;

        let (header, _) = vollcrypt_files_core::Header::parse(&buffer[..bytes_read])
            .map_err(|e| format!("Failed to parse file header: {}", e))?;

        let wrap = header.wraps.first()
            .ok_or_else(|| "No wrap entries found in header".to_string())?;

        let dek = unwrap_dek_with_password(wrap, password.as_bytes())
            .map_err(|e| format!("Wrong password or corrupted file: {}", e))?;

        source.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("Failed to reset file read pointer: {}", e))?;

        let dest = std::fs::File::create(&dest_path)
            .map_err(|e| format!("Failed to create destination file: {}", e))?;

        decrypt_file_pipelined(source, dest, &dek, 4)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn encrypt_file_recipient(
    source_path: String,
    dest_path: String,
    recipient_pk_hex: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let pk = deserialize_pk(&recipient_pk_hex)?;
        let dek = generate_dek();
        let file_id = generate_file_id();

        let recipient_id = generate_salt();
        let wrap = wrap_key_to_recipient(&dek, recipient_id, 1, &pk)
            .map_err(|e| e.to_string())?;

        let source = std::fs::File::open(&source_path)
            .map_err(|e| format!("Failed to open source file: {}", e))?;
        let dest = std::fs::File::create(&dest_path)
            .map_err(|e| format!("Failed to create destination file: {}", e))?;

        encrypt_file_pipelined(
            source,
            dest,
            &dek,
            &file_id,
            1024 * 1024,
            vec![wrap],
            Mode::Recipient,
            4,
            None,
            None,
        )
        .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn decrypt_file_recipient(
    source_path: String,
    dest_path: String,
    recipient_sk_hex: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let sk = deserialize_sk(&recipient_sk_hex)?;
        let mut source = std::fs::File::open(&source_path)
            .map_err(|e| format!("Failed to open source file: {}", e))?;
        
        let mut buffer = vec![0u8; 65536];
        let bytes_read = source.read(&mut buffer)
            .map_err(|e| format!("Failed to read file header: {}", e))?;

        let (header, _) = vollcrypt_files_core::Header::parse(&buffer[..bytes_read])
            .map_err(|e| format!("Failed to parse file header: {}", e))?;

        let wrap = header.wraps.first()
            .ok_or_else(|| "No wrap entries found in header".to_string())?;

        let dek = unwrap_key_with_recipient_key(wrap, &sk)
            .map_err(|e| format!("Failed to unwrap DEK (ensure key is correct): {}", e))?;

        source.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("Failed to reset file read pointer: {}", e))?;

        let dest = std::fs::File::create(&dest_path)
            .map_err(|e| format!("Failed to create destination file: {}", e))?;

        decrypt_file_pipelined(source, dest, &dek, 4)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn encrypt_text_password(
    text: String,
    password: String,
    kdf_choice: String,
) -> Result<String, String> {
    let dek = generate_dek();
    let file_id = generate_file_id();

    let kdf = match kdf_choice.as_str() {
        "PBKDF2" => KdfChoice::pbkdf2_default(),
        _ => KdfChoice::argon2id_interactive(),
    };

    let wrap = wrap_dek_with_password(&dek, password.as_bytes(), kdf)
        .map_err(|e| e.to_string())?;

    let (_, ciphertext) = encrypt_file_pipelined_async(
        text.as_bytes(),
        &dek,
        &file_id,
        65536, // 64KB chunk size for text
        vec![wrap],
        Mode::Password,
        None,
    )
    .await
    .map_err(|e| format!("Encryption failed: {}", e))?;

    // Return hex of container bytes
    Ok(bytes_to_hex(&ciphertext))
}

#[tauri::command]
pub async fn decrypt_text_password(
    ciphertext_hex: String,
    password: String,
) -> Result<String, String> {
    let ciphertext = hex_to_bytes(&ciphertext_hex)
        .map_err(|e| format!("Invalid hex container: {}", e))?;

    let (header, _) = vollcrypt_files_core::Header::parse(&ciphertext)
        .map_err(|e| format!("Invalid header: {}", e))?;

    let wrap = header.wraps.first()
        .ok_or_else(|| "No wrap entries found".to_string())?;

    let dek = unwrap_dek_with_password(wrap, password.as_bytes())
        .map_err(|e| format!("Wrong password or corrupted payload: {}", e))?;

    let (_, plaintext_bytes) = decrypt_file_pipelined_async(&ciphertext, &dek)
        .await
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext_bytes)
        .map_err(|e| format!("Plaintext is not valid UTF-8: {}", e))
}

#[tauri::command]
pub async fn encrypt_text_recipient(
    text: String,
    recipient_pk_hex: String,
) -> Result<String, String> {
    let pk = deserialize_pk(&recipient_pk_hex)?;
    let dek = generate_dek();
    let file_id = generate_file_id();

    let recipient_id = generate_salt();
    let wrap = wrap_key_to_recipient(&dek, recipient_id, 1, &pk)
        .map_err(|e| e.to_string())?;

    let (_, ciphertext) = encrypt_file_pipelined_async(
        text.as_bytes(),
        &dek,
        &file_id,
        65536,
        vec![wrap],
        Mode::Recipient,
        None,
    )
    .await
    .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(bytes_to_hex(&ciphertext))
}

#[tauri::command]
pub async fn decrypt_text_recipient(
    ciphertext_hex: String,
    recipient_sk_hex: String,
) -> Result<String, String> {
    let sk = deserialize_sk(&recipient_sk_hex)?;
    let ciphertext = hex_to_bytes(&ciphertext_hex)
        .map_err(|e| format!("Invalid hex container: {}", e))?;

    let (header, _) = vollcrypt_files_core::Header::parse(&ciphertext)
        .map_err(|e| format!("Invalid header: {}", e))?;

    let wrap = header.wraps.first()
        .ok_or_else(|| "No wrap entries found".to_string())?;

    let dek = unwrap_key_with_recipient_key(wrap, &sk)
        .map_err(|e| format!("Failed to unwrap DEK: {}", e))?;

    let (_, plaintext_bytes) = decrypt_file_pipelined_async(&ciphertext, &dek)
        .await
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext_bytes)
        .map_err(|e| format!("Plaintext is not valid UTF-8: {}", e))
}

#[tauri::command]
pub fn save_text_file(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write file: {}", e))
}

#[tauri::command]
pub fn load_text_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read file: {}", e))
}

#[tauri::command]
pub fn save_bin_file(path: String, hex_content: String) -> Result<(), String> {
    let bytes = hex_to_bytes(&hex_content)?;
    std::fs::write(&path, bytes)
        .map_err(|e| format!("Failed to write binary file: {}", e))
}

#[tauri::command]
pub fn load_bin_file(path: String) -> Result<String, String> {
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("Failed to read binary file: {}", e))?;
    Ok(bytes_to_hex(&bytes))
}



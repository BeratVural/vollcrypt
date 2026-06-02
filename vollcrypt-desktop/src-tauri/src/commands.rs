use std::io::{Read, Seek};
use vollcrypt_files_core::{
    encrypt_file_pipelined, decrypt_file_pipelined,
    pipelined_io::{encrypt_file_pipelined_async, decrypt_file_pipelined_async},
    decrypt_file_pipelined_with_policy,
    generate_dek, generate_file_id, generate_salt,
    wrap_dek_with_password, unwrap_dek_with_password,
    generate_recipient_keypair, wrap_key_to_recipient, unwrap_key_with_recipient_key,
    wrap_dek_with_threshold, unwrap_dek_with_threshold, encode_share, decode_share,
    Mode, KdfChoice, RecipientPublicKey, RecipientSecretKey,
    is_sealed,
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
    shield: Option<ShieldPolicyJson>,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut source = std::fs::File::open(&source_path)
            .map_err(|e| format!("Failed to open source file: {}", e))?;
        
        let mut buffer = vec![0u8; 65536];
        let bytes_read = source.read(&mut buffer)
            .map_err(|e| format!("Failed to read file header: {}", e))?;

        let (header, _) = vollcrypt_files_core::Header::parse(&buffer[..bytes_read])
            .map_err(|e| format!("Failed to parse file header: {}", e))?;

        if is_sealed(&header) {
            return Err("ContainerSealed".to_string());
        }

        let wrap = header.wraps.first()
            .ok_or_else(|| "No wrap entries found in header".to_string())?;

        let dek = unwrap_dek_with_password(wrap, password.as_bytes())
            .map_err(|e| format!("Wrong password or corrupted file: {}", e))?;

        source.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("Failed to reset file read pointer: {}", e))?;

        let dest = std::fs::File::create(&dest_path)
            .map_err(|e| format!("Failed to create destination file: {}", e))?;

        let core_policy = match shield {
            Some(p) => Some(to_core_policy(p)?),
            None => None,
        };

        if let Some(ref pol) = core_policy {
            decrypt_file_pipelined_with_policy(source, dest, &dek, 4, Some(pol))
                .map_err(|e| match e {
                    vollcrypt_files_core::FileFormatError::ContainerSealed => "ContainerSealed".to_string(),
                    other => format!("Decryption failed: {}", other),
                })?;
        } else {
            decrypt_file_pipelined(source, dest, &dek, 4)
                .map_err(|e| match e {
                    vollcrypt_files_core::FileFormatError::ContainerSealed => "ContainerSealed".to_string(),
                    other => format!("Decryption failed: {}", other),
                })?;
        }

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
    shield: Option<ShieldPolicyJson>,
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

        if is_sealed(&header) {
            return Err("ContainerSealed".to_string());
        }

        let wrap = header.wraps.first()
            .ok_or_else(|| "No wrap entries found in header".to_string())?;

        let dek = unwrap_key_with_recipient_key(wrap, &sk)
            .map_err(|e| format!("Failed to unwrap DEK (ensure key is correct): {}", e))?;

        source.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("Failed to reset file read pointer: {}", e))?;

        let dest = std::fs::File::create(&dest_path)
            .map_err(|e| format!("Failed to create destination file: {}", e))?;

        let core_policy = match shield {
            Some(p) => Some(to_core_policy(p)?),
            None => None,
        };

        if let Some(ref pol) = core_policy {
            decrypt_file_pipelined_with_policy(source, dest, &dek, 4, Some(pol))
                .map_err(|e| match e {
                    vollcrypt_files_core::FileFormatError::ContainerSealed => "ContainerSealed".to_string(),
                    other => format!("Decryption failed: {}", other),
                })?;
        } else {
            decrypt_file_pipelined(source, dest, &dek, 4)
                .map_err(|e| match e {
                    vollcrypt_files_core::FileFormatError::ContainerSealed => "ContainerSealed".to_string(),
                    other => format!("Decryption failed: {}", other),
                })?;
        }

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

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct ShieldPolicyJson {
    #[serde(rename = "releaseMode")]
    pub release_mode: String,
    pub signature: String,
    #[serde(rename = "rollbackPin")]
    pub rollback_pin: Option<u64>,
    #[serde(rename = "founderAnchor")]
    pub founder_anchor: Option<bool>,
    #[serde(rename = "onTamper")]
    pub on_tamper: String,
}

fn to_core_policy(policy_json: ShieldPolicyJson) -> Result<vollcrypt_files_core::ShieldPolicy, String> {
    let release_mode = match policy_json.release_mode.as_str() {
        "verified" => vollcrypt_files_core::ReleaseMode::Verified,
        "streaming" => vollcrypt_files_core::ReleaseMode::Streaming,
        _ => return Err("Invalid releaseMode".to_string()),
    };
    let signature = match policy_json.signature.as_str() {
        "required" => vollcrypt_files_core::SignaturePolicy::Required,
        "optional" => vollcrypt_files_core::SignaturePolicy::Optional,
        _ => return Err("Invalid signature policy".to_string()),
    };
    let on_tamper = match policy_json.on_tamper.as_str() {
        "abort" => vollcrypt_files_core::OnTamper::Abort,
        "report" => vollcrypt_files_core::OnTamper::AbortWithReport,
        "recover" => vollcrypt_files_core::OnTamper::AttemptRecovery,
        _ => return Err("Invalid onTamper option".to_string()),
    };
    Ok(vollcrypt_files_core::ShieldPolicy {
        release_mode,
        signature,
        rollback_pin: policy_json.rollback_pin,
        founder_anchor: policy_json.founder_anchor.unwrap_or(true),
        on_tamper,
        verify_sealed_marker: true,
    })
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct PipelinedSignInfoJson {
    pub kind: String,
    #[serde(rename = "signerPk")]
    pub signer_pk: String,
    #[serde(rename = "signerSk")]
    pub signer_sk: String,
    #[serde(rename = "keyLogId")]
    pub key_log_id: String,
    pub timestamp: u64,
}

fn parse_sign_info(
    pk_hex: &str,
    sk_hex: &str,
    key_log_id_hex: &str,
    timestamp: u64,
) -> Result<vollcrypt_files_core::PipelinedSignInfo, String> {
    let pk_bytes = hex_to_bytes(pk_hex)?;
    let sk_bytes = hex_to_bytes(sk_hex)?;
    let key_log_id_bytes = hex_to_bytes(key_log_id_hex)?;
    let mut key_log_id = [0u8; 32];
    if key_log_id_bytes.len() != 32 {
        return Err("Invalid key_log_id length (must be 32 bytes/64 hex characters)".to_string());
    }
    key_log_id.copy_from_slice(&key_log_id_bytes);

    let signer_pk = vollcrypt_files_core::HybridPublicKey::parse(&pk_bytes)
        .map_err(|e| format!("Invalid signature public key: {:?}", e))?;
    let signer_sk = vollcrypt_files_core::HybridSecretKey::parse(&sk_bytes)
        .map_err(|e| format!("Invalid signature secret key: {:?}", e))?;

    Ok(vollcrypt_files_core::PipelinedSignInfo::Plain {
        signer_pk,
        signer_sk,
        key_log_id,
        timestamp,
    })
}

#[derive(serde::Serialize)]
pub struct InspectResultJson {
    pub version: u8,
    #[serde(rename = "fileId")]
    pub file_id: String,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u32,
    #[serde(rename = "plaintextSize")]
    pub plaintext_size: u64,
    #[serde(rename = "merkleRoot")]
    pub merkle_root: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(rename = "sealedMode")]
    pub sealed_mode: Option<u8>,
    pub reason: Option<String>,
    pub timestamp: Option<u64>,
    #[serde(rename = "ciphertextPresent")]
    pub ciphertext_present: bool,
}

#[tauri::command]
pub async fn seal_file(
    path: String,
    mode: String,
    reason: Option<String>,
    sign_info: Option<PipelinedSignInfoJson>,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let source_file = std::fs::File::open(&path)
            .map_err(|e| format!("Failed to open file: {}", e))?;
        
        let temp_path = format!("{}.tmp_seal", path);
        let dest_file = std::fs::File::create(&temp_path)
            .map_err(|e| format!("Failed to create temporary file: {}", e))?;

        let core_mode = match mode.as_str() {
            "seal" => vollcrypt_files_core::SealMode::Seal,
            "purge" => vollcrypt_files_core::SealMode::Purge,
            _ => return Err("Invalid seal mode".to_string()),
        };

        let core_sign_info = match sign_info {
            Some(si) => Some(parse_sign_info(&si.signer_pk, &si.signer_sk, &si.key_log_id, si.timestamp)?),
            None => None,
        };

        let opts = vollcrypt_files_core::SealOptions {
            mode: core_mode,
            reason,
            sign_info: core_sign_info,
        };

        vollcrypt_files_core::seal_container(source_file, dest_file, opts)
            .map_err(|e| format!("Sealing failed: {}", e))?;

        // Replace original file with temporary file
        std::fs::rename(&temp_path, &path)
            .map_err(|e| format!("Failed to replace original file with sealed container: {}", e))?;

        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn inspect_sealed_file(path: String) -> Result<InspectResultJson, String> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        let res = vollcrypt_files_core::inspect_sealed(file)
            .map_err(|e| format!("Failed to inspect sealed container: {}", e))?;

        Ok(InspectResultJson {
            version: res.version,
            file_id: bytes_to_hex(&res.file_id),
            chunk_size: res.chunk_size,
            plaintext_size: res.plaintext_size,
            merkle_root: bytes_to_hex(&res.merkle_root),
            hash_algorithm: format!("{:?}", res.hash_algorithm),
            sealed_mode: res.sealed_mode,
            reason: res.reason,
            timestamp: res.timestamp,
            ciphertext_present: res.ciphertext_present,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn verify_container_file(
    path: String,
    policy: ShieldPolicyJson,
) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        let core_policy = to_core_policy(policy)?;
        let report = vollcrypt_files_core::verify_container(file, &core_policy);

        Ok(format!("{:?}", report))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(serde::Serialize)]
pub struct EncryptTextThresholdResult {
    #[serde(rename = "ciphertextHex")]
    pub ciphertext_hex: String,
    pub shares: Vec<String>,
}

#[tauri::command]
pub async fn encrypt_file_threshold(
    source_path: String,
    dest_path: String,
    t: u8,
    n: u8,
) -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(move || {
        let dek = generate_dek();
        let file_id = generate_file_id();

        let (wrap, shares) = wrap_dek_with_threshold(&dek, &file_id, t, n, 0)
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

        let share_strs = shares
            .iter()
            .map(|s| encode_share(s))
            .collect();

        Ok(share_strs)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn decrypt_file_threshold(
    source_path: String,
    dest_path: String,
    shares: Vec<String>,
    shield: Option<ShieldPolicyJson>,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut source = std::fs::File::open(&source_path)
            .map_err(|e| format!("Failed to open source file: {}", e))?;
        
        let mut buffer = vec![0u8; 65536];
        let bytes_read = source.read(&mut buffer)
            .map_err(|e| format!("Failed to read file header: {}", e))?;

        let (header, _) = vollcrypt_files_core::Header::parse(&buffer[..bytes_read])
            .map_err(|e| format!("Failed to parse file header: {}", e))?;

        if is_sealed(&header) {
            return Err("ContainerSealed".to_string());
        }

        let wrap = header.wraps.first()
            .ok_or_else(|| "No wrap entries found in header".to_string())?;

        let mut decoded_shares = Vec::with_capacity(shares.len());
        for s in &shares {
            let decoded = decode_share(s)
                .map_err(|e| format!("Invalid share: {}", e))?;
            decoded_shares.push(decoded);
        }

        let dek = unwrap_dek_with_threshold(
            wrap,
            &header.file_id,
            &decoded_shares,
            header.cipher_id as u8,
        )
        .map_err(|e| format!("Failed to unwrap DEK (ensure threshold is met and shares are correct): {}", e))?;

        source.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("Failed to reset file read pointer: {}", e))?;

        let dest = std::fs::File::create(&dest_path)
            .map_err(|e| format!("Failed to create destination file: {}", e))?;

        let core_policy = match shield {
            Some(p) => Some(to_core_policy(p)?),
            None => None,
        };

        if let Some(ref pol) = core_policy {
            decrypt_file_pipelined_with_policy(source, dest, &dek, 4, Some(pol))
                .map_err(|e| match e {
                    vollcrypt_files_core::FileFormatError::ContainerSealed => "ContainerSealed".to_string(),
                    other => format!("Decryption failed: {}", other),
                })?;
        } else {
            decrypt_file_pipelined(source, dest, &dek, 4)
                .map_err(|e| match e {
                    vollcrypt_files_core::FileFormatError::ContainerSealed => "ContainerSealed".to_string(),
                    other => format!("Decryption failed: {}", other),
                })?;
        }

        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn encrypt_text_threshold(
    text: String,
    t: u8,
    n: u8,
) -> Result<EncryptTextThresholdResult, String> {
    let dek = generate_dek();
    let file_id = generate_file_id();

    let (wrap, shares) = wrap_dek_with_threshold(&dek, &file_id, t, n, 0)
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

    let share_strs = shares
        .iter()
        .map(|s| encode_share(s))
        .collect();

    Ok(EncryptTextThresholdResult {
        ciphertext_hex: bytes_to_hex(&ciphertext),
        shares: share_strs,
    })
}

#[tauri::command]
pub async fn decrypt_text_threshold(
    ciphertext_hex: String,
    shares: Vec<String>,
) -> Result<String, String> {
    let ciphertext = hex_to_bytes(&ciphertext_hex)
        .map_err(|e| format!("Invalid hex container: {}", e))?;

    let (header, _) = vollcrypt_files_core::Header::parse(&ciphertext)
        .map_err(|e| format!("Invalid header: {}", e))?;

    let wrap = header.wraps.first()
        .ok_or_else(|| "No wrap entries found".to_string())?;

    let mut decoded_shares = Vec::with_capacity(shares.len());
    for s in &shares {
        let decoded = decode_share(s)
            .map_err(|e| format!("Invalid share: {}", e))?;
        decoded_shares.push(decoded);
    }

    let dek = unwrap_dek_with_threshold(
        wrap,
        &header.file_id,
        &decoded_shares,
        header.cipher_id as u8,
    )
    .map_err(|e| format!("Failed to unwrap DEK (ensure threshold is met and shares are correct): {}", e))?;

    let (_, plaintext_bytes) = decrypt_file_pipelined_async(&ciphertext, &dek)
        .await
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext_bytes)
        .map_err(|e| format!("Plaintext is not valid UTF-8: {}", e))
}



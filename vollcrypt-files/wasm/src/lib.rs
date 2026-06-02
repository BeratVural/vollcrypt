use serde::{Deserialize, Serialize};
use vollcrypt_files_core::{
    self, decrypt_chunk as core_decrypt_chunk, encrypt_chunk as core_encrypt_chunk,
    generate_recipient_keypair as core_generate_recipient_keypair,
    unwrap_key_with_recipient_key as core_unwrap_key_with_recipient_key,
    wrap_key_to_recipient as core_wrap_key_to_recipient, RecipientPublicKey, RecipientSecretKey,
};
use vollcrypt_files_core::hybrid_sig::{HybridPublicKey, HybridSecretKey, HybridSignature};
use wasm_bindgen::prelude::*;

pub mod wasm_bridge;

// Helper utility to convert errors
fn to_js_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_hybrid_pubkey(slice: &[u8], name: &str) -> Result<HybridPublicKey, JsValue> {
    if slice.len() == 32 {
        let mut ed25519 = [0u8; 32];
        ed25519.copy_from_slice(slice);
        Ok(HybridPublicKey {
            ed25519,
            mldsa: [0u8; 1952],
        })
    } else {
        HybridPublicKey::parse(slice)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key {}: {}", name, e)))
    }
}

fn to_hybrid_secret_key(slice: &[u8], name: &str) -> Result<HybridSecretKey, JsValue> {
    if slice.len() == 32 {
        let mut ed25519 = [0u8; 32];
        ed25519.copy_from_slice(slice);
        Ok(HybridSecretKey {
            ed25519,
            mldsa: [0u8; 4032],
        })
    } else {
        HybridSecretKey::parse(slice)
            .map_err(|e| JsValue::from_str(&format!("Invalid secret key {}: {}", name, e)))
    }
}

// Fixed size array parsers
fn to_arr32(slice: &[u8], name: &str) -> Result<[u8; 32], JsValue> {
    if slice.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "{} must be exactly 32 bytes, got {}",
            name,
            slice.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn to_arr16(slice: &[u8], name: &str) -> Result<[u8; 16], JsValue> {
    if slice.len() != 16 {
        return Err(JsValue::from_str(&format!(
            "{} must be exactly 16 bytes, got {}",
            name,
            slice.len()
        )));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn to_arr12(slice: &[u8], name: &str) -> Result<[u8; 12], JsValue> {
    if slice.len() != 12 {
        return Err(JsValue::from_str(&format!(
            "{} must be exactly 12 bytes, got {}",
            name,
            slice.len()
        )));
    }
    let mut arr = [0u8; 12];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn to_arr40(slice: &[u8], name: &str) -> Result<[u8; 40], JsValue> {
    if slice.len() != 40 {
        return Err(JsValue::from_str(&format!(
            "{} must be exactly 40 bytes, got {}",
            name,
            slice.len()
        )));
    }
    let mut arr = [0u8; 40];
    arr.copy_from_slice(slice);
    Ok(arr)
}

// ==================== Random Generation ====================

#[wasm_bindgen(js_name = generateDek)]
pub fn generate_dek() -> Vec<u8> {
    vollcrypt_files_core::generate_dek().to_vec()
}

#[wasm_bindgen(js_name = generateFileId)]
pub fn generate_file_id() -> Vec<u8> {
    vollcrypt_files_core::generate_file_id().to_vec()
}

#[wasm_bindgen(js_name = generateSalt)]
pub fn generate_salt() -> Vec<u8> {
    vollcrypt_files_core::generate_salt().to_vec()
}

#[wasm_bindgen(js_name = generateGk)]
pub fn generate_gk() -> Vec<u8> {
    vollcrypt_files_core::generate_gk().to_vec()
}

// ==================== Chunk Operations ====================

#[derive(Serialize, Deserialize)]
pub struct ChunkEnvelope {
    #[serde(rename = "chunkIndex")]
    pub chunk_index: u32,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[wasm_bindgen(js_name = encryptChunk)]
pub fn encrypt_chunk(
    dek: &[u8],
    file_id: &[u8],
    chunk_index: u32,
    plaintext: &[u8],
) -> Result<JsValue, JsValue> {
    let dek_arr = to_arr32(dek, "dek")?;
    let file_id_arr = to_arr16(file_id, "file_id")?;

    match core_encrypt_chunk(&dek_arr, &file_id_arr, chunk_index, plaintext, None) {
        Ok(envelope) => {
            let env_obj = ChunkEnvelope {
                chunk_index: envelope.chunk_index,
                iv: envelope.iv.to_vec(),
                ciphertext: envelope.ciphertext,
                tag: envelope.tag.to_vec(),
            };
            serde_wasm_bindgen::to_value(&env_obj).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = decryptChunk)]
pub fn decrypt_chunk(
    dek: &[u8],
    file_id: &[u8],
    chunk_index: u32,
    envelope: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let dek_arr = to_arr32(dek, "dek")?;
    let file_id_arr = to_arr16(file_id, "file_id")?;

    let env_obj: ChunkEnvelope = serde_wasm_bindgen::from_value(envelope).map_err(to_js_err)?;
    let iv_arr = to_arr12(&env_obj.iv, "envelope.iv")?;
    let mut tag_arr = [0u8; 16];
    if env_obj.tag.len() != 16 {
        return Err(JsValue::from_str("Tag must be exactly 16 bytes"));
    }
    tag_arr.copy_from_slice(&env_obj.tag);

    let core_envelope = vollcrypt_files_core::ChunkEnvelope {
        chunk_index,
        iv: iv_arr,
        ciphertext: env_obj.ciphertext,
        tag: tag_arr,
    };

    match core_decrypt_chunk(&dek_arr, &file_id_arr, chunk_index, &core_envelope, None) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = chunkLeafHash)]
pub fn chunk_leaf_hash(envelope: JsValue) -> Result<Vec<u8>, JsValue> {
    let env_obj: ChunkEnvelope = serde_wasm_bindgen::from_value(envelope).map_err(to_js_err)?;
    let iv_arr = to_arr12(&env_obj.iv, "envelope.iv")?;
    let mut tag_arr = [0u8; 16];
    if env_obj.tag.len() != 16 {
        return Err(JsValue::from_str("Tag must be exactly 16 bytes"));
    }
    tag_arr.copy_from_slice(&env_obj.tag);

    let core_envelope = vollcrypt_files_core::ChunkEnvelope {
        chunk_index: env_obj.chunk_index,
        iv: iv_arr,
        ciphertext: env_obj.ciphertext,
        tag: tag_arr,
    };

    let hash = vollcrypt_files_core::chunk_leaf_hash(&core_envelope);
    Ok(hash.to_vec())
}

// ==================== Merkle Tree ====================

#[wasm_bindgen(js_name = merkleRoot)]
pub fn merkle_root(leaves: JsValue) -> Result<Vec<u8>, JsValue> {
    let leaves_vec: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(leaves).map_err(to_js_err)?;
    let mut core_leaves = Vec::with_capacity(leaves_vec.len());
    for leaf in leaves_vec {
        let arr = to_arr32(&leaf, "leaf")?;
        core_leaves.push(arr);
    }
    let tree = vollcrypt_files_core::MerkleTree::from_leaves(core_leaves);
    Ok(tree.root().to_vec())
}

#[wasm_bindgen(js_name = merkleProof)]
pub fn merkle_proof(leaves: JsValue, leaf_index: u32) -> Result<JsValue, JsValue> {
    let leaves_vec: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(leaves).map_err(to_js_err)?;
    let mut core_leaves = Vec::with_capacity(leaves_vec.len());
    for leaf in leaves_vec {
        let arr = to_arr32(&leaf, "leaf")?;
        core_leaves.push(arr);
    }
    let tree = vollcrypt_files_core::MerkleTree::from_leaves(core_leaves);
    let proof = tree.proof(leaf_index as usize);
    let proof_vecs: Vec<Vec<u8>> = proof.into_iter().map(|p| p.to_vec()).collect();
    serde_wasm_bindgen::to_value(&proof_vecs).map_err(to_js_err)
}

#[wasm_bindgen(js_name = verifyMerkleProof)]
pub fn verify_merkle_proof(
    leaf: &[u8],
    leaf_index: u32,
    total_leaves: u32,
    proof: JsValue,
    expected_root: &[u8],
) -> Result<bool, JsValue> {
    let leaf_arr = to_arr32(leaf, "leaf")?;
    let root_arr = to_arr32(expected_root, "expected_root")?;

    let proof_vecs: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(proof).map_err(to_js_err)?;
    let mut core_proof = Vec::with_capacity(proof_vecs.len());
    for p in proof_vecs {
        let arr = to_arr32(&p, "proof_element")?;
        core_proof.push(arr);
    }

    Ok(vollcrypt_files_core::verify_merkle_proof(
        &leaf_arr,
        leaf_index as usize,
        total_leaves as usize,
        &core_proof,
        &root_arr,
    ))
}

// ==================== Password Mode & WrapEntry Mappings ====================

#[derive(Serialize, Deserialize)]
pub struct KdfChoice {
    pub kind: String, // "Pbkdf2" | "Argon2id"
    pub rounds: Option<u32>,
    #[serde(rename = "mCost")]
    pub m_cost: Option<u32>,
    #[serde(rename = "tCost")]
    pub t_cost: Option<u32>,
    #[serde(rename = "pCost")]
    pub p_cost: Option<u32>,
    pub salt: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct WrapEntry {
    pub kind: String, // "PasswordPbkdf2" | "PasswordArgon2id" | "HybridKem" | "GroupWrap" | "Threshold"
    pub salt: Option<Vec<u8>>,
    pub rounds: Option<u32>,
    #[serde(rename = "mCost")]
    pub m_cost: Option<u32>,
    #[serde(rename = "tCost")]
    pub t_cost: Option<u32>,
    #[serde(rename = "pCost")]
    pub p_cost: Option<u32>,
    #[serde(rename = "recipientId")]
    pub recipient_id: Option<Vec<u8>>,
    #[serde(rename = "gkVersion")]
    pub gk_version: Option<u32>,
    #[serde(rename = "ephemeralX25519")]
    pub ephemeral_x25519: Option<Vec<u8>>,
    #[serde(rename = "ciphertextMlKem")]
    pub ciphertext_ml_kem: Option<Vec<u8>>,
    #[serde(rename = "groupId")]
    pub group_id: Option<Vec<u8>>,
    #[serde(rename = "wrappedKey")]
    pub wrapped_key: Vec<u8>,
    pub t: Option<u8>,
    pub n: Option<u8>,
    #[serde(rename = "shareSetId")]
    pub share_set_id: Option<Vec<u8>>,
}

fn wrap_entry_to_serde(entry: vollcrypt_files_core::WrapEntry) -> WrapEntry {
    match entry {
        vollcrypt_files_core::WrapEntry::PasswordPbkdf2 {
            salt,
            iterations,
            wrapped_dek,
        } => WrapEntry {
            kind: "PasswordPbkdf2".to_string(),
            salt: Some(salt.to_vec()),
            rounds: Some(iterations),
            m_cost: None,
            t_cost: None,
            p_cost: None,
            recipient_id: None,
            gk_version: None,
            ephemeral_x25519: None,
            ciphertext_ml_kem: None,
            group_id: None,
            wrapped_key: wrapped_dek.to_vec(),
            t: None,
            n: None,
            share_set_id: None,
        },
        vollcrypt_files_core::WrapEntry::PasswordArgon2id {
            salt,
            m_cost,
            t_cost,
            p_cost,
            wrapped_dek,
        } => WrapEntry {
            kind: "PasswordArgon2id".to_string(),
            salt: Some(salt.to_vec()),
            rounds: None,
            m_cost: Some(m_cost),
            t_cost: Some(t_cost),
            p_cost: Some(p_cost),
            recipient_id: None,
            gk_version: None,
            ephemeral_x25519: None,
            ciphertext_ml_kem: None,
            group_id: None,
            wrapped_key: wrapped_dek.to_vec(),
            t: None,
            n: None,
            share_set_id: None,
        },
        vollcrypt_files_core::WrapEntry::HybridKem {
            recipient_id,
            gk_version,
            x25519_ephemeral,
            mlkem_ciphertext,
            wrapped_dek,
        } => WrapEntry {
            kind: "HybridKem".to_string(),
            salt: None,
            rounds: None,
            m_cost: None,
            t_cost: None,
            p_cost: None,
            recipient_id: Some(recipient_id.to_vec()),
            gk_version: Some(gk_version),
            ephemeral_x25519: Some(x25519_ephemeral.to_vec()),
            ciphertext_ml_kem: Some(mlkem_ciphertext),
            group_id: None,
            wrapped_key: wrapped_dek.to_vec(),
            t: None,
            n: None,
            share_set_id: None,
        },
        vollcrypt_files_core::WrapEntry::GroupWrap {
            group_id,
            gk_version,
            wrapped_dek,
        } => WrapEntry {
            kind: "GroupWrap".to_string(),
            salt: None,
            rounds: None,
            m_cost: None,
            t_cost: None,
            p_cost: None,
            recipient_id: None,
            gk_version: Some(gk_version),
            ephemeral_x25519: None,
            ciphertext_ml_kem: None,
            group_id: Some(group_id.to_vec()),
            wrapped_key: wrapped_dek.to_vec(),
            t: None,
            n: None,
            share_set_id: None,
        },
        vollcrypt_files_core::WrapEntry::Threshold {
            t,
            n,
            share_set_id,
            wrapped_dek,
        } => WrapEntry {
            kind: "Threshold".to_string(),
            salt: None,
            rounds: None,
            m_cost: None,
            t_cost: None,
            p_cost: None,
            recipient_id: None,
            gk_version: None,
            ephemeral_x25519: None,
            ciphertext_ml_kem: None,
            group_id: None,
            wrapped_key: wrapped_dek.to_vec(),
            t: Some(t),
            n: Some(n),
            share_set_id: Some(share_set_id.to_vec()),
        },
    }
}

fn serde_to_wrap_entry(entry: WrapEntry) -> Result<vollcrypt_files_core::WrapEntry, JsValue> {
    match entry.kind.as_str() {
        "PasswordPbkdf2" => {
            let salt_buf = entry
                .salt
                .ok_or_else(|| JsValue::from_str("Missing salt for PasswordPbkdf2"))?;
            let mut salt = [0u8; 16];
            if salt_buf.len() != 16 {
                return Err(JsValue::from_str("Salt must be exactly 16 bytes"));
            }
            salt.copy_from_slice(&salt_buf);
            let iterations = entry
                .rounds
                .ok_or_else(|| JsValue::from_str("Missing rounds for PasswordPbkdf2"))?;
            let wrapped_dek = to_arr40(&entry.wrapped_key, "wrappedKey")?;
            Ok(vollcrypt_files_core::WrapEntry::PasswordPbkdf2 {
                salt,
                iterations,
                wrapped_dek,
            })
        }
        "PasswordArgon2id" => {
            let salt_buf = entry
                .salt
                .ok_or_else(|| JsValue::from_str("Missing salt for PasswordArgon2id"))?;
            let mut salt = [0u8; 16];
            if salt_buf.len() != 16 {
                return Err(JsValue::from_str("Salt must be exactly 16 bytes"));
            }
            salt.copy_from_slice(&salt_buf);
            let m_cost = entry
                .m_cost
                .ok_or_else(|| JsValue::from_str("Missing mCost for PasswordArgon2id"))?;
            let t_cost = entry
                .t_cost
                .ok_or_else(|| JsValue::from_str("Missing tCost for PasswordArgon2id"))?;
            let p_cost = entry
                .p_cost
                .ok_or_else(|| JsValue::from_str("Missing pCost for PasswordArgon2id"))?;
            let wrapped_dek = to_arr40(&entry.wrapped_key, "wrappedKey")?;
            Ok(vollcrypt_files_core::WrapEntry::PasswordArgon2id {
                salt,
                m_cost,
                t_cost,
                p_cost,
                wrapped_dek,
            })
        }
        "HybridKem" => {
            let recipient_id_buf = entry
                .recipient_id
                .ok_or_else(|| JsValue::from_str("Missing recipientId for HybridKem"))?;
            let recipient_id = to_arr16(&recipient_id_buf, "recipientId")?;
            let gk_version = entry
                .gk_version
                .ok_or_else(|| JsValue::from_str("Missing gkVersion for HybridKem"))?;
            let ephemeral_x25519_buf = entry
                .ephemeral_x25519
                .ok_or_else(|| JsValue::from_str("Missing ephemeralX25519 for HybridKem"))?;
            let x25519_ephemeral = to_arr32(&ephemeral_x25519_buf, "ephemeralX25519")?;
            let mlkem_ciphertext = entry
                .ciphertext_ml_kem
                .ok_or_else(|| JsValue::from_str("Missing ciphertextMlKem for HybridKem"))?;
            let wrapped_dek = to_arr40(&entry.wrapped_key, "wrappedKey")?;
            Ok(vollcrypt_files_core::WrapEntry::HybridKem {
                recipient_id,
                gk_version,
                x25519_ephemeral,
                mlkem_ciphertext,
                wrapped_dek,
            })
        }
        "GroupWrap" => {
            let group_id_buf = entry
                .group_id
                .ok_or_else(|| JsValue::from_str("Missing groupId for GroupWrap"))?;
            let group_id = to_arr16(&group_id_buf, "groupId")?;
            let gk_version = entry
                .gk_version
                .ok_or_else(|| JsValue::from_str("Missing gkVersion for GroupWrap"))?;
            let wrapped_dek = to_arr40(&entry.wrapped_key, "wrappedKey")?;
            Ok(vollcrypt_files_core::WrapEntry::GroupWrap {
                group_id,
                gk_version,
                wrapped_dek,
            })
        }
        "Threshold" => {
            let t = entry
                .t
                .ok_or_else(|| JsValue::from_str("Missing t for Threshold"))?;
            let n = entry
                .n
                .ok_or_else(|| JsValue::from_str("Missing n for Threshold"))?;
            let share_set_id_buf = entry
                .share_set_id
                .ok_or_else(|| JsValue::from_str("Missing shareSetId for Threshold"))?;
            let share_set_id = to_arr16(&share_set_id_buf, "shareSetId")?;
            let wrapped_dek = to_arr40(&entry.wrapped_key, "wrappedKey")?;
            Ok(vollcrypt_files_core::WrapEntry::Threshold {
                t,
                n,
                share_set_id,
                wrapped_dek,
            })
        }
        _ => Err(JsValue::from_str(&format!(
            "Unknown WrapEntry kind: {}",
            entry.kind
        ))),
    }
}

fn serde_to_kdf_choice(choice: KdfChoice) -> Result<vollcrypt_files_core::KdfChoice, JsValue> {
    match choice.kind.as_str() {
        "Pbkdf2" => {
            let iterations = choice
                .rounds
                .ok_or_else(|| JsValue::from_str("Missing rounds for Pbkdf2"))?;
            Ok(vollcrypt_files_core::KdfChoice::Pbkdf2 { iterations })
        }
        "Argon2id" => {
            let m_cost = choice
                .m_cost
                .ok_or_else(|| JsValue::from_str("Missing mCost for Argon2id"))?;
            let t_cost = choice
                .t_cost
                .ok_or_else(|| JsValue::from_str("Missing tCost for Argon2id"))?;
            let p_cost = choice
                .p_cost
                .ok_or_else(|| JsValue::from_str("Missing pCost for Argon2id"))?;
            Ok(vollcrypt_files_core::KdfChoice::Argon2id {
                m_cost,
                t_cost,
                p_cost,
            })
        }
        _ => Err(JsValue::from_str(&format!(
            "Unknown KdfChoice kind: {}",
            choice.kind
        ))),
    }
}

#[wasm_bindgen(js_name = wrapDekWithPassword)]
pub fn wrap_dek_with_password(
    dek: &[u8],
    password: &str,
    kdf: JsValue,
) -> Result<JsValue, JsValue> {
    let dek_arr = to_arr32(dek, "dek")?;
    let kdf_obj: KdfChoice = serde_wasm_bindgen::from_value(kdf).map_err(to_js_err)?;
    let core_kdf = serde_to_kdf_choice(kdf_obj)?;

    match vollcrypt_files_core::wrap_dek_with_password(&dek_arr, password.as_bytes(), core_kdf) {
        Ok(entry) => {
            let ser_entry = wrap_entry_to_serde(entry);
            serde_wasm_bindgen::to_value(&ser_entry).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = unwrapDekWithPassword)]
pub fn unwrap_dek_with_password(wrap: JsValue, password: &str) -> Result<Vec<u8>, JsValue> {
    let entry_obj: WrapEntry = serde_wasm_bindgen::from_value(wrap).map_err(to_js_err)?;
    let core_wrap = serde_to_wrap_entry(entry_obj)?;

    match vollcrypt_files_core::unwrap_dek_with_password(&core_wrap, password.as_bytes()) {
        Ok(dek) => Ok(dek.to_vec()),
        Err(e) => Err(to_js_err(e)),
    }
}

// ==================== Recipient / KEM Mode ====================

#[derive(Serialize, Deserialize)]
pub struct KeySubpair {
    pub x25519: Vec<u8>,
    #[serde(rename = "mlKem")]
    pub ml_kem: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct RecipientKeypair {
    #[serde(rename = "publicKey")]
    pub public_key: KeySubpair,
    #[serde(rename = "secretKey")]
    pub secret_key: KeySubpair,
}

#[wasm_bindgen(js_name = generateRecipientKeypair)]
pub fn generate_recipient_keypair() -> Result<JsValue, JsValue> {
    let (pk, sk) = core_generate_recipient_keypair();
    let pair = RecipientKeypair {
        public_key: KeySubpair {
            x25519: pk.x25519.to_vec(),
            ml_kem: pk.ml_kem.to_vec(),
        },
        secret_key: KeySubpair {
            x25519: sk.x25519.to_vec(),
            ml_kem: sk.ml_kem.to_vec(),
        },
    };
    serde_wasm_bindgen::to_value(&pair).map_err(to_js_err)
}

#[wasm_bindgen(js_name = wrapKeyToRecipient)]
pub fn wrap_key_to_recipient(
    key: &[u8],
    recipient_id: &[u8],
    gk_version: u32,
    recipient_pk: JsValue,
) -> Result<JsValue, JsValue> {
    let key_arr = to_arr32(key, "key")?;
    let r_id_arr = to_arr16(recipient_id, "recipient_id")?;

    let pk_obj: KeySubpair = serde_wasm_bindgen::from_value(recipient_pk).map_err(to_js_err)?;
    let pk_x25519 = to_arr32(&pk_obj.x25519, "recipient_pk.x25519")?;
    let mut pk_mlkem = [0u8; 1184];
    if pk_obj.ml_kem.len() != 1184 {
        return Err(JsValue::from_str("ML-KEM public key must be 1184 bytes"));
    }
    pk_mlkem.copy_from_slice(&pk_obj.ml_kem);

    let core_pk = RecipientPublicKey {
        x25519: pk_x25519,
        ml_kem: Box::new(pk_mlkem),
    };

    match core_wrap_key_to_recipient(&key_arr, r_id_arr, gk_version, &core_pk) {
        Ok(entry) => {
            let ser_entry = wrap_entry_to_serde(entry);
            serde_wasm_bindgen::to_value(&ser_entry).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = unwrapKeyWithRecipientKey)]
pub fn unwrap_key_with_recipient_key(
    wrap: JsValue,
    recipient_sk: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let entry_obj: WrapEntry = serde_wasm_bindgen::from_value(wrap).map_err(to_js_err)?;
    let core_wrap = serde_to_wrap_entry(entry_obj)?;

    let sk_obj: KeySubpair = serde_wasm_bindgen::from_value(recipient_sk).map_err(to_js_err)?;
    let sk_x25519 = to_arr32(&sk_obj.x25519, "recipient_sk.x25519")?;
    let mut sk_mlkem = [0u8; 2400];
    if sk_obj.ml_kem.len() != 2400 {
        return Err(JsValue::from_str("ML-KEM secret key must be 2400 bytes"));
    }
    sk_mlkem.copy_from_slice(&sk_obj.ml_kem);

    let core_sk = RecipientSecretKey {
        x25519: sk_x25519,
        ml_kem: Box::new(sk_mlkem),
    };

    match core_unwrap_key_with_recipient_key(&core_wrap, &core_sk) {
        Ok(key) => Ok(key.to_vec()),
        Err(e) => Err(to_js_err(e)),
    }
}

// ==================== Group Operations ====================

#[wasm_bindgen(js_name = wrapDekForGroup)]
pub fn wrap_dek_for_group(
    dek: &[u8],
    group_id: &[u8],
    gk_version: u32,
    gk: &[u8],
) -> Result<JsValue, JsValue> {
    let dek_arr = to_arr32(dek, "dek")?;
    let group_id_arr = to_arr16(group_id, "group_id")?;
    let gk_arr = to_arr32(gk, "gk")?;

    let entry =
        vollcrypt_files_core::wrap_dek_for_group(&dek_arr, group_id_arr, gk_version, &gk_arr);
    let ser_entry = wrap_entry_to_serde(entry);
    serde_wasm_bindgen::to_value(&ser_entry).map_err(to_js_err)
}

#[wasm_bindgen(js_name = unwrapDekWithGroupKey)]
pub fn unwrap_dek_with_group_key(wrap: JsValue, gk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let entry_obj: WrapEntry = serde_wasm_bindgen::from_value(wrap).map_err(to_js_err)?;
    let core_wrap = serde_to_wrap_entry(entry_obj)?;
    let gk_arr = to_arr32(gk, "gk")?;

    match vollcrypt_files_core::unwrap_dek_with_group_key(&core_wrap, &gk_arr) {
        Ok(dek) => Ok(dek.to_vec()),
        Err(e) => Err(to_js_err(e)),
    }
}

// ==================== Threshold SSS Mode ====================

#[derive(Serialize, Deserialize)]
pub struct WrapThresholdResult {
    pub wrap: WrapEntry,
    pub shares: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ShareJson {
    #[serde(rename = "shareSetId")]
    pub share_set_id: Vec<u8>,
    pub t: u8,
    pub n: u8,
    pub x: u8,
    pub y: Vec<u8>,
}

#[wasm_bindgen(js_name = wrapDekWithThreshold)]
pub fn wrap_dek_with_threshold(
    dek: &[u8],
    file_id: &[u8],
    t: u8,
    n: u8,
    cipher_suite_id: u8,
) -> Result<JsValue, JsValue> {
    let dek_arr = to_arr32(dek, "dek")?;
    let file_id_arr = to_arr16(file_id, "fileId")?;

    match vollcrypt_files_core::wrap_dek_with_threshold(&dek_arr, &file_id_arr, t, n, cipher_suite_id) {
        Ok((core_wrap, core_shares)) => {
            let wrap = wrap_entry_to_serde(core_wrap);
            let shares = core_shares
                .iter()
                .map(|s| vollcrypt_files_core::encode_share(s))
                .collect();
            let res = WrapThresholdResult { wrap, shares };
            serde_wasm_bindgen::to_value(&res).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = unwrapDekWithThresholdShares)]
pub fn unwrap_dek_with_threshold_shares(
    wrap: JsValue,
    file_id: &[u8],
    shares: JsValue,
    cipher_suite_id: u8,
) -> Result<Vec<u8>, JsValue> {
    let entry_obj: WrapEntry = serde_wasm_bindgen::from_value(wrap).map_err(to_js_err)?;
    let core_wrap = serde_to_wrap_entry(entry_obj)?;
    let file_id_arr = to_arr16(file_id, "fileId")?;

    let shares_vec: Vec<String> = serde_wasm_bindgen::from_value(shares).map_err(to_js_err)?;
    let mut core_shares = Vec::with_capacity(shares_vec.len());
    for s in &shares_vec {
        let decoded = vollcrypt_files_core::decode_share(s).map_err(to_js_err)?;
        core_shares.push(decoded);
    }

    match vollcrypt_files_core::unwrap_dek_with_threshold(
        &core_wrap,
        &file_id_arr,
        &core_shares,
        cipher_suite_id,
    ) {
        Ok(dek) => Ok(dek.to_vec()),
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = encodeShare)]
pub fn encode_share(share: JsValue) -> Result<String, JsValue> {
    let share_obj: ShareJson = serde_wasm_bindgen::from_value(share).map_err(to_js_err)?;
    let share_set_id = to_arr16(&share_obj.share_set_id, "shareSetId")?;
    let y = to_arr32(&share_obj.y, "y")?;
    let core_share = vollcrypt_files_core::Share {
        share_set_id,
        t: share_obj.t,
        n: share_obj.n,
        x: share_obj.x,
        y,
    };
    Ok(vollcrypt_files_core::encode_share(&core_share))
}

#[wasm_bindgen(js_name = decodeShare)]
pub fn decode_share(s: &str) -> Result<JsValue, JsValue> {
    match vollcrypt_files_core::decode_share(s) {
        Ok(core_share) => {
            let res = ShareJson {
                share_set_id: core_share.share_set_id.to_vec(),
                t: core_share.t,
                n: core_share.n,
                x: core_share.x,
                y: core_share.y.to_vec(),
            };
            serde_wasm_bindgen::to_value(&res).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

// ==================== Ed25519 Signatures ====================

#[derive(Serialize, Deserialize)]
pub struct Ed25519KeypairObj {
    #[serde(rename = "publicKey")]
    pub public_key: Vec<u8>,
    #[serde(rename = "secretKey")]
    pub secret_key: Vec<u8>,
}

#[wasm_bindgen(js_name = ed25519KeypairGenerate)]
pub fn ed25519_keypair_generate() -> Result<JsValue, JsValue> {
    let (pk, sk) = vollcrypt_files_core::ed25519_keypair_generate();
    let kp = Ed25519KeypairObj {
        public_key: pk.to_vec(),
        secret_key: sk.to_vec(),
    };
    serde_wasm_bindgen::to_value(&kp).map_err(to_js_err)
}

#[wasm_bindgen(js_name = ed25519Sign)]
pub fn ed25519_sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sk_arr = to_arr32(sk, "sk")?;
    let sig = vollcrypt_files_core::ed25519_sign(&sk_arr, message);
    Ok(sig.to_vec())
}

#[wasm_bindgen(js_name = ed25519Verify)]
pub fn ed25519_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let pk_arr = to_arr32(pk, "pk")?;
    if signature.len() != 64 {
        return Err(JsValue::from_str("Signature must be exactly 64 bytes"));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature);

    Ok(vollcrypt_files_core::ed25519_verify(&pk_arr, message, &sig_arr).is_ok())
}

// ==================== Hybrid Signatures ====================

#[derive(Serialize, Deserialize)]
pub struct HybridKeypairObj {
    #[serde(rename = "publicKey")]
    pub public_key: Vec<u8>,
    #[serde(rename = "secretKey")]
    pub secret_key: Vec<u8>,
}

#[wasm_bindgen(js_name = hybridKeypairGenerate)]
pub fn hybrid_keypair_generate() -> Result<JsValue, JsValue> {
    let (pk, sk) = vollcrypt_files_core::hybrid_keypair_generate();
    let kp = HybridKeypairObj {
        public_key: pk.write(),
        secret_key: sk.write(),
    };
    serde_wasm_bindgen::to_value(&kp).map_err(to_js_err)
}

#[wasm_bindgen(js_name = hybridSign)]
pub fn hybrid_sign(
    sk: &[u8],
    pk: &[u8],
    domain: &str,
    context: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk_val = to_hybrid_secret_key(sk, "sk")?;
    let pk_val = to_hybrid_pubkey(pk, "pk")?;
    let sig = vollcrypt_files_core::hybrid_sign(&sk_val, &pk_val, domain, context, payload);
    Ok(sig.write())
}

#[wasm_bindgen(js_name = hybridVerify)]
pub fn hybrid_verify(
    pk: &[u8],
    domain: &str,
    context: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    let pk_val = to_hybrid_pubkey(pk, "pk")?;
    let sig_val = HybridSignature::parse(signature)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature: {}", e)))?;
    Ok(vollcrypt_files_core::hybrid_verify(&pk_val, domain, context, payload, &sig_val))
}

// ==================== GroupManifest Class ====================

#[derive(Serialize, Deserialize)]
pub struct MemberPublicKeyObj {
    pub recipient: KeySubpair,
    #[serde(rename = "signingPk")]
    pub signing_pk: Vec<u8>,
}

#[wasm_bindgen]
pub struct GroupManifest {
    inner: vollcrypt_files_core::GroupManifest,
}

#[wasm_bindgen]
impl GroupManifest {
    #[wasm_bindgen]
    pub fn genesis(
        group_id: &[u8],
        initial_gk: &[u8],
        founder_member_id: &[u8],
        founder_recipient_pk: JsValue,
        founder_ed25519_pk: &[u8],
        founder_ed25519_sk: &[u8],
        _timestamp: u32,
    ) -> Result<GroupManifest, JsValue> {
        let group_id_arr = to_arr16(group_id, "group_id")?;
        let initial_gk_arr = to_arr32(initial_gk, "initial_gk")?;
        let founder_id_arr = to_arr16(founder_member_id, "founder_member_id")?;

        let rec_obj: KeySubpair =
            serde_wasm_bindgen::from_value(founder_recipient_pk).map_err(to_js_err)?;
        let r_x25519 = to_arr32(&rec_obj.x25519, "founder_recipient_pk.x25519")?;
        let mut r_mlkem = [0u8; 1184];
        if rec_obj.ml_kem.len() != 1184 {
            return Err(JsValue::from_str("ML-KEM public key must be 1184 bytes"));
        }
        r_mlkem.copy_from_slice(&rec_obj.ml_kem);

        let rec_pk = RecipientPublicKey {
            x25519: r_x25519,
            ml_kem: Box::new(r_mlkem),
        };

        let f_signing_pk = to_hybrid_pubkey(founder_ed25519_pk, "founder_ed25519_pk")?;
        let f_signing_sk = to_hybrid_secret_key(founder_ed25519_sk, "founder_ed25519_sk")?;

        let gk_wrap = core_wrap_key_to_recipient(&initial_gk_arr, founder_id_arr, 1, &rec_pk)
            .map_err(to_js_err)?;

        let inner = vollcrypt_files_core::GroupManifest::genesis(
            group_id_arr,
            founder_id_arr,
            &f_signing_sk,
            f_signing_pk,
            rec_pk,
            gk_wrap,
        );

        Ok(GroupManifest { inner })
    }

    #[wasm_bindgen]
    pub fn parse(bytes: &[u8]) -> Result<GroupManifest, JsValue> {
        match vollcrypt_files_core::GroupManifest::parse(bytes) {
            Ok((inner, _)) => Ok(GroupManifest { inner }),
            Err(e) => Err(to_js_err(e)),
        }
    }

    #[wasm_bindgen]
    pub fn write(&self) -> Vec<u8> {
        self.inner.write()
    }

    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner.verify().map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(
        &mut self,
        new_member_id: &[u8],
        new_member_pk: JsValue,
        current_gk: &[u8],
        _admin_pk: &[u8],
        admin_sk: &[u8],
        _timestamp: u32,
    ) -> Result<(), JsValue> {
        let member_id_arr = to_arr16(new_member_id, "new_member_id")?;
        let admin_sk_arr = to_hybrid_secret_key(admin_sk, "admin_sk")?;
        let current_gk_arr = to_arr32(current_gk, "current_gk")?;

        let m_pk_obj: MemberPublicKeyObj =
            serde_wasm_bindgen::from_value(new_member_pk).map_err(to_js_err)?;
        let rx = to_arr32(&m_pk_obj.recipient.x25519, "new_member_pk.recipient.x25519")?;
        let mut rm = [0u8; 1184];
        if m_pk_obj.recipient.ml_kem.len() != 1184 {
            return Err(JsValue::from_str("ML-KEM public key must be 1184 bytes"));
        }
        rm.copy_from_slice(&m_pk_obj.recipient.ml_kem);

        let rec_pk = RecipientPublicKey {
            x25519: rx,
            ml_kem: Box::new(rm),
        };

        let signing_pk = to_hybrid_pubkey(&m_pk_obj.signing_pk, "new_member_pk.signing_pk")?;

        let current_version = self.inner.current_gk_version();
        let gk_wrap =
            core_wrap_key_to_recipient(&current_gk_arr, member_id_arr, current_version, &rec_pk)
                .map_err(to_js_err)?;

        self.inner
            .add_member(&admin_sk_arr, member_id_arr, signing_pk, rec_pk, gk_wrap)
            .map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(
        &mut self,
        removed_member_id: &[u8],
        _admin_pk: &[u8],
        admin_sk: &[u8],
        _timestamp: u32,
    ) -> Result<(), JsValue> {
        let member_id_arr = to_arr16(removed_member_id, "removed_member_id")?;
        let admin_sk_arr = to_hybrid_secret_key(admin_sk, "admin_sk")?;

        self.inner
            .remove_member(&admin_sk_arr, member_id_arr)
            .map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = rotateGroupKey)]
    pub fn rotate_group_key(
        &mut self,
        new_gk: &[u8],
        _admin_pk: &[u8],
        admin_sk: &[u8],
        timestamp: u32,
    ) -> Result<u32, JsValue> {
        let new_gk_arr = to_arr32(new_gk, "new_gk")?;
        let admin_sk_arr = to_hybrid_secret_key(admin_sk, "admin_sk")?;

        self.inner
            .rotate_group_key(&new_gk_arr, &admin_sk_arr, timestamp as u64)
            .map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = shredGroupKey)]
    pub fn shred_group_key(
        &mut self,
        version_to_shred: u32,
        reason: String,
        _admin_pk: &[u8],
        admin_sk: &[u8],
        timestamp: u32,
    ) -> Result<(), JsValue> {
        let admin_sk_arr = to_hybrid_secret_key(admin_sk, "admin_sk")?;

        self.inner
            .shred_group_key(
                version_to_shred,
                &reason,
                &admin_sk_arr,
                timestamp as u64,
            )
            .map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = currentMembers)]
    pub fn current_members(&self) -> Result<JsValue, JsValue> {
        let members: Vec<Vec<u8>> = self
            .inner
            .current_members()
            .into_iter()
            .map(|m| m.to_vec())
            .collect();
        serde_wasm_bindgen::to_value(&members).map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = currentGkVersion)]
    pub fn current_gk_version(&self) -> u32 {
        self.inner.current_gk_version()
    }

    #[wasm_bindgen(js_name = findMemberWrap)]
    pub fn find_member_wrap(&self, member_id: &[u8]) -> Result<JsValue, JsValue> {
        let member_id_arr = to_arr16(member_id, "member_id")?;
        match self.inner.find_member_wrap(&member_id_arr) {
            Ok(wrap) => {
                let ser = wrap_entry_to_serde(wrap);
                serde_wasm_bindgen::to_value(&ser).map_err(to_js_err)
            }
            Err(e) => Err(to_js_err(e)),
        }
    }

    #[wasm_bindgen(js_name = findMemberWrapForVersion)]
    pub fn find_member_wrap_for_version(
        &self,
        member_id: &[u8],
        gk_version: u32,
    ) -> Result<JsValue, JsValue> {
        let member_id_arr = to_arr16(member_id, "member_id")?;
        match self
            .inner
            .find_member_wrap_for_version(&member_id_arr, gk_version)
        {
            Ok(wrap) => {
                let ser = wrap_entry_to_serde(wrap);
                serde_wasm_bindgen::to_value(&ser).map_err(to_js_err)
            }
            Err(e) => Err(to_js_err(e)),
        }
    }

    #[wasm_bindgen(js_name = isVersionShredded)]
    pub fn is_version_shredded(&self, gk_version: u32) -> bool {
        self.inner.is_version_shredded(gk_version)
    }
}

// ==================== Header Structure Mappings ====================

#[derive(Serialize, Deserialize)]
pub struct SignedMetadata {
    pub kind: String, // "Plain" | "Sealed" | "SovereignSealed"
    #[serde(rename = "signerPubkey")]
    pub signer_pubkey: Option<Vec<u8>>,
    pub timestamp: u32,
    #[serde(rename = "keyLogId")]
    pub key_log_id: Option<Vec<u8>>,
    #[serde(rename = "sealedGroupId")]
    pub sealed_group_id: Option<Vec<u8>>,
    #[serde(rename = "sealedGkVersion")]
    pub sealed_gk_version: Option<u32>,
    pub iv: Option<Vec<u8>>,
    #[serde(rename = "sealedPayload")]
    pub sealed_payload: Option<Vec<u8>>,
    #[serde(rename = "sealedTag")]
    pub sealed_tag: Option<Vec<u8>>,
    #[serde(rename = "sealedMode")]
    pub sealed_mode: Option<u32>,
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct HeaderObj {
    pub version: u8,
    pub mode: u8,
    #[serde(rename = "cipherId")]
    pub cipher_id: u8,
    #[serde(rename = "fileId")]
    pub file_id: Vec<u8>,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u32,
    #[serde(rename = "plaintextSize")]
    pub plaintext_size: f64,
    #[serde(rename = "merkleRoot")]
    pub merkle_root: Vec<u8>,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: u8,
    pub wraps: Vec<WrapEntry>,
    #[serde(rename = "signedMetadata")]
    pub signed_metadata: Option<SignedMetadata>,
    pub signature: Option<Vec<u8>>,
}

fn signed_metadata_to_serde(meta: vollcrypt_files_core::SignedMetadata) -> SignedMetadata {
    match meta {
        vollcrypt_files_core::SignedMetadata::Plain {
            signer_pubkey,
            timestamp,
            key_log_id,
        } => SignedMetadata {
            kind: "Plain".to_string(),
            signer_pubkey: Some(
                if signer_pubkey.mldsa == [0u8; 1952] {
                    signer_pubkey.ed25519.to_vec()
                } else {
                    signer_pubkey.write()
                }
            ),
            timestamp: timestamp as u32,
            key_log_id: Some(key_log_id.to_vec()),
            sealed_group_id: None,
            sealed_gk_version: None,
            iv: None,
            sealed_payload: None,
            sealed_tag: None,
            sealed_mode: None,
            reason: None,
        },
        vollcrypt_files_core::SignedMetadata::Sealed {
            sealed_group_id,
            sealed_gk_version,
            iv,
            sealed_payload,
            sealed_tag,
            timestamp,
        } => SignedMetadata {
            kind: "Sealed".to_string(),
            signer_pubkey: None,
            timestamp: timestamp as u32,
            key_log_id: None,
            sealed_group_id: Some(sealed_group_id.to_vec()),
            sealed_gk_version: Some(sealed_gk_version),
            iv: Some(iv.to_vec()),
            sealed_payload: Some(sealed_payload),
            sealed_tag: Some(sealed_tag.to_vec()),
            sealed_mode: None,
            reason: None,
        },
        vollcrypt_files_core::SignedMetadata::SovereignSealed {
            signer_pubkey,
            mode,
            reason,
            timestamp,
        } => SignedMetadata {
            kind: "SovereignSealed".to_string(),
            signer_pubkey: Some(
                if signer_pubkey.mldsa == [0u8; 1952] {
                    signer_pubkey.ed25519.to_vec()
                } else {
                    signer_pubkey.write()
                }
            ),
            timestamp: timestamp as u32,
            key_log_id: None,
            sealed_group_id: None,
            sealed_gk_version: None,
            iv: None,
            sealed_payload: None,
            sealed_tag: None,
            sealed_mode: Some(mode as u32),
            reason: Some(reason),
        },
    }
}

fn serde_to_signed_metadata(
    meta: SignedMetadata,
) -> Result<vollcrypt_files_core::SignedMetadata, JsValue> {
    match meta.kind.as_str() {
        "Plain" => {
            let pk_buf = meta
                .signer_pubkey
                .ok_or_else(|| JsValue::from_str("Missing signerPubkey"))?;
            let signer_pubkey = to_hybrid_pubkey(&pk_buf, "signerPubkey")?;

            let kl_buf = meta
                .key_log_id
                .ok_or_else(|| JsValue::from_str("Missing keyLogId"))?;
            let key_log_id = to_arr32(&kl_buf, "keyLogId")?;

            Ok(vollcrypt_files_core::SignedMetadata::Plain {
                signer_pubkey,
                timestamp: meta.timestamp as u64,
                key_log_id,
            })
        }
        "Sealed" => {
            let sg_buf = meta
                .sealed_group_id
                .ok_or_else(|| JsValue::from_str("Missing sealedGroupId"))?;
            let sealed_group_id = to_arr16(&sg_buf, "sealedGroupId")?;

            let sealed_gk_version = meta
                .sealed_gk_version
                .ok_or_else(|| JsValue::from_str("Missing sealedGkVersion"))?;

            let iv_buf = meta.iv.ok_or_else(|| JsValue::from_str("Missing iv"))?;
            let iv = to_arr12(&iv_buf, "iv")?;

            let sealed_payload = meta
                .sealed_payload
                .ok_or_else(|| JsValue::from_str("Missing sealedPayload"))?;

            let tag_buf = meta
                .sealed_tag
                .ok_or_else(|| JsValue::from_str("Missing sealedTag"))?;
            let mut sealed_tag = [0u8; 16];
            if tag_buf.len() != 16 {
                return Err(JsValue::from_str("sealedTag must be exactly 16 bytes"));
            }
            sealed_tag.copy_from_slice(&tag_buf);

            Ok(vollcrypt_files_core::SignedMetadata::Sealed {
                sealed_group_id,
                sealed_gk_version,
                iv,
                sealed_payload,
                sealed_tag,
                timestamp: meta.timestamp as u64,
            })
        }
        "SovereignSealed" => {
            let pk_buf = meta
                .signer_pubkey
                .ok_or_else(|| JsValue::from_str("Missing signerPubkey"))?;
            let signer_pubkey = to_hybrid_pubkey(&pk_buf, "signerPubkey")?;
            let mode = meta
                .sealed_mode
                .ok_or_else(|| JsValue::from_str("Missing sealedMode"))? as u8;
            let reason = meta.reason.clone().unwrap_or_default();

            Ok(vollcrypt_files_core::SignedMetadata::SovereignSealed {
                signer_pubkey,
                mode,
                reason,
                timestamp: meta.timestamp as u64,
            })
        }
        _ => Err(JsValue::from_str(&format!(
            "Unknown SignedMetadata kind: {}",
            meta.kind
        ))),
    }
}

fn header_to_serde(header: vollcrypt_files_core::Header) -> HeaderObj {
    HeaderObj {
        version: header.version,
        mode: header.mode as u8,
        cipher_id: header.cipher_id as u8,
        file_id: header.file_id.to_vec(),
        chunk_size: header.chunk_size,
        plaintext_size: header.plaintext_size as f64,
        merkle_root: header.merkle_root.to_vec(),
        hash_algorithm: header.hash_algorithm as u8,
        wraps: header.wraps.into_iter().map(wrap_entry_to_serde).collect(),
        signed_metadata: header.signed_metadata.map(signed_metadata_to_serde),
        signature: header.signature.map(|s| {
            if header.version == 3 {
                s.write()
            } else {
                s.ed25519.to_vec()
            }
        }),
    }
}

fn serde_to_header(obj: HeaderObj) -> Result<vollcrypt_files_core::Header, JsValue> {
    let file_id = to_arr16(&obj.file_id, "fileId")?;
    let merkle_root = to_arr32(&obj.merkle_root, "merkleRoot")?;

    let wraps = obj
        .wraps
        .into_iter()
        .map(serde_to_wrap_entry)
        .collect::<Result<Vec<_>, JsValue>>()?;

    let signed_metadata = match obj.signed_metadata {
        Some(m) => Some(serde_to_signed_metadata(m)?),
        None => None,
    };

    let signature = match obj.signature {
        Some(s) => {
            if s.len() == 64 {
                let mut ed_sig = [0u8; 64];
                ed_sig.copy_from_slice(&s);
                Some(HybridSignature {
                    ed25519: ed_sig,
                    mldsa: Vec::new(),
                })
            } else {
                match HybridSignature::parse(&s) {
                    Ok(sig) => Some(sig),
                    Err(e) => return Err(JsValue::from_str(&e.to_string())),
                }
            }
        }
        None => None,
    };

    let mode = vollcrypt_files_core::Mode::try_from(obj.mode)
        .map_err(|_| JsValue::from_str("Invalid mode value"))?;

    let cipher_id = vollcrypt_files_core::CipherId::try_from(obj.cipher_id)
        .map_err(|_| JsValue::from_str("Invalid cipherId value"))?;

    let hash_algorithm = match obj.hash_algorithm {
        0 => vollcrypt_files_core::HashAlgorithm::Sha256,
        1 => vollcrypt_files_core::HashAlgorithm::Blake3,
        other => {
            return Err(JsValue::from_str(&format!(
                "Invalid hashAlgorithm value: {}",
                other
            )))
        }
    };

    Ok(vollcrypt_files_core::Header {
        version: obj.version,
        mode,
        cipher_id,
        file_id,
        chunk_size: obj.chunk_size,
        plaintext_size: obj.plaintext_size as u64,
        merkle_root,
        hash_algorithm,
        wraps,
        signed_metadata,
        signature,
    })
}

#[derive(Serialize, Deserialize)]
pub struct ParsedHeaderObj {
    pub header: HeaderObj,
    #[serde(rename = "headerLen")]
    pub header_len: u32,
}

#[wasm_bindgen]
pub struct HeaderClass;

#[wasm_bindgen]
impl HeaderClass {
    #[wasm_bindgen]
    pub fn parse(bytes: &[u8]) -> Result<JsValue, JsValue> {
        match vollcrypt_files_core::Header::parse(bytes) {
            Ok((header, header_len)) => {
                let parsed = ParsedHeaderObj {
                    header: header_to_serde(header),
                    header_len: header_len as u32,
                };
                serde_wasm_bindgen::to_value(&parsed).map_err(to_js_err)
            }
            Err(e) => Err(to_js_err(e)),
        }
    }

    #[wasm_bindgen]
    pub fn write(header: JsValue) -> Result<Vec<u8>, JsValue> {
        let obj: HeaderObj = serde_wasm_bindgen::from_value(header).map_err(to_js_err)?;
        let core_header = serde_to_header(obj)?;
        Ok(core_header.write())
    }
}

// ==================== File-Level Operations ====================

#[derive(Serialize, Deserialize)]
pub struct RewrapResult {
    pub header: Vec<u8>,
    #[serde(rename = "updatedCount")]
    pub updated_count: u32,
}

#[wasm_bindgen(js_name = rewrapDekInHeader)]
pub fn rewrap_dek_in_header(
    header_bytes: &[u8],
    old_gk: &[u8],
    new_gk: &[u8],
    new_gk_version: u32,
) -> Result<JsValue, JsValue> {
    let old_gk_arr = to_arr32(old_gk, "old_gk")?;
    let new_gk_arr = to_arr32(new_gk, "new_gk")?;

    let (mut header, _) = vollcrypt_files_core::Header::parse(header_bytes).map_err(to_js_err)?;

    match vollcrypt_files_core::rewrap_dek_in_header(
        &mut header,
        &old_gk_arr,
        &new_gk_arr,
        new_gk_version,
    ) {
        Ok(updated_count) => {
            let res = RewrapResult {
                header: header.write(),
                updated_count: updated_count as u32,
            };
            serde_wasm_bindgen::to_value(&res).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = cryptoShredHeader)]
pub fn crypto_shred_header(header_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let (mut header, _) = vollcrypt_files_core::Header::parse(header_bytes).map_err(to_js_err)?;

    vollcrypt_files_core::crypto_shred_header(&mut header);
    Ok(header.write())
}

// ==================== Signature Plain / Sealed ====================

#[wasm_bindgen(js_name = signHeaderPlain)]
pub fn sign_header_plain(
    header: JsValue,
    signer_pk: &[u8],
    signer_sk: &[u8],
    key_log_id: &[u8],
    timestamp: u32,
) -> Result<JsValue, JsValue> {
    let obj: HeaderObj = serde_wasm_bindgen::from_value(header).map_err(to_js_err)?;
    let mut core_header = serde_to_header(obj)?;
    let signer_pk_arr = to_hybrid_pubkey(signer_pk, "signer_pk")?;
    let signer_sk_arr = to_hybrid_secret_key(signer_sk, "signer_sk")?;
    let key_log_id_arr = to_arr32(key_log_id, "key_log_id")?;

    vollcrypt_files_core::sign_header_plain(
        &mut core_header,
        &signer_pk_arr,
        &signer_sk_arr,
        key_log_id_arr,
        timestamp as u64,
    )
    .map_err(to_js_err)?;

    let ser = header_to_serde(core_header);
    serde_wasm_bindgen::to_value(&ser).map_err(to_js_err)
}

#[wasm_bindgen(js_name = signHeaderSealed)]
#[allow(clippy::too_many_arguments)]
pub fn sign_header_sealed(
    header: JsValue,
    signer_pk: &[u8],
    signer_sk: &[u8],
    key_log_id: &[u8],
    timestamp: u32,
    sealed_group_id: &[u8],
    sealed_gk_version: u32,
    sealed_gk: &[u8],
) -> Result<JsValue, JsValue> {
    let obj: HeaderObj = serde_wasm_bindgen::from_value(header).map_err(to_js_err)?;
    let mut core_header = serde_to_header(obj)?;
    let signer_pk_arr = to_hybrid_pubkey(signer_pk, "signer_pk")?;
    let signer_sk_arr = to_hybrid_secret_key(signer_sk, "signer_sk")?;
    let key_log_id_arr = to_arr32(key_log_id, "key_log_id")?;
    let group_id_arr = to_arr16(sealed_group_id, "sealed_group_id")?;
    let sealed_gk_arr = to_arr32(sealed_gk, "sealed_gk")?;

    vollcrypt_files_core::sign_header_sealed(
        &mut core_header,
        &signer_pk_arr,
        &signer_sk_arr,
        key_log_id_arr,
        timestamp as u64,
        group_id_arr,
        sealed_gk_version,
        &sealed_gk_arr,
    )
    .map_err(to_js_err)?;

    let ser = header_to_serde(core_header);
    serde_wasm_bindgen::to_value(&ser).map_err(to_js_err)
}

#[wasm_bindgen(js_name = verifyHeaderSignaturePlain)]
pub fn verify_header_signature_plain(header: JsValue) -> Result<Vec<u8>, JsValue> {
    let obj: HeaderObj = serde_wasm_bindgen::from_value(header).map_err(to_js_err)?;
    let core_header = serde_to_header(obj)?;
    match vollcrypt_files_core::verify_header_signature_plain(&core_header, vollcrypt_files_core::VerificationPolicy::RequireSigned) {
        Ok(pubkey) => Ok(pubkey.write()),
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = verifyHeaderSignatureSealed)]
pub fn verify_header_signature_sealed(
    header: JsValue,
    sealed_gk: &[u8],
    key_log: &KeyLog,
) -> Result<Vec<u8>, JsValue> {
    let obj: HeaderObj = serde_wasm_bindgen::from_value(header).map_err(to_js_err)?;
    let core_header = serde_to_header(obj)?;
    let gk_arr = to_arr32(sealed_gk, "sealed_gk")?;
    match vollcrypt_files_core::verify_header_signature_sealed(&core_header, &gk_arr, &key_log.inner, vollcrypt_files_core::VerificationPolicy::RequireSigned) {
        Ok(pubkey) => Ok(pubkey.write()),
        Err(e) => Err(to_js_err(e)),
    }
}

// ==================== KeyLog Class ====================

#[derive(Serialize, Deserialize)]
pub struct KeyLogEntry {
    pub kind: String, // "DeviceRegister" | "DeviceRevoke"
    #[serde(rename = "userId")]
    pub user_id: Option<Vec<u8>>,
    #[serde(rename = "deviceId")]
    pub device_id: Vec<u8>,
    #[serde(rename = "devicePubkey")]
    pub device_pubkey: Option<Vec<u8>>,
    #[serde(rename = "humanLabel")]
    pub human_label: Option<String>,
    #[serde(rename = "prevHash")]
    pub prev_hash: Vec<u8>,
    pub timestamp: u32,
    pub signature: Vec<u8>,
}

fn entry_to_serde(entry: &vollcrypt_files_core::KeyLogEntry) -> KeyLogEntry {
    match &entry.entry {
        vollcrypt_files_core::KeyLogEntryType::DeviceRegister {
            user_id,
            device_id,
            device_pubkey,
            human_label,
        } => KeyLogEntry {
            kind: "DeviceRegister".to_string(),
            user_id: Some(user_id.to_vec()),
            device_id: device_id.to_vec(),
            device_pubkey: Some(device_pubkey.write()),
            human_label: Some(human_label.clone()),
            prev_hash: entry.prev_hash.to_vec(),
            timestamp: entry.timestamp as u32,
            signature: entry.signature.write(),
        },
        vollcrypt_files_core::KeyLogEntryType::DeviceRevoke { device_id } => KeyLogEntry {
            kind: "DeviceRevoke".to_string(),
            user_id: None,
            device_id: device_id.to_vec(),
            device_pubkey: None,
            human_label: None,
            prev_hash: entry.prev_hash.to_vec(),
            timestamp: entry.timestamp as u32,
            signature: entry.signature.write(),
        },
    }
}

#[wasm_bindgen]
pub struct KeyLog {
    inner: vollcrypt_files_core::KeyLog,
}

#[wasm_bindgen]
impl KeyLog {
    #[wasm_bindgen]
    pub fn create(authority_pubkey: &[u8]) -> Result<KeyLog, JsValue> {
        let auth_pk = to_hybrid_pubkey(authority_pubkey, "authority_pubkey")?;
        Ok(KeyLog {
            inner: vollcrypt_files_core::KeyLog::new(auth_pk),
        })
    }

    #[wasm_bindgen]
    pub fn parse(bytes: &[u8]) -> Result<KeyLog, JsValue> {
        match vollcrypt_files_core::KeyLog::parse(bytes) {
            Ok(inner) => Ok(KeyLog { inner }),
            Err(e) => Err(to_js_err(e)),
        }
    }

    #[wasm_bindgen]
    pub fn write(&self) -> Vec<u8> {
        self.inner.write()
    }

    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner.verify().map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = registerDevice)]
    pub fn register_device(
        &mut self,
        user_id: &[u8],
        device_id: &[u8],
        device_pk: &[u8],
        human_label: String,
        authority_sk: &[u8],
        timestamp: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let u_id = to_arr16(user_id, "user_id")?;
        let d_id = to_arr16(device_id, "device_id")?;
        let d_pk = to_hybrid_pubkey(device_pk, "device_pk")?;
        let auth_sk = to_hybrid_secret_key(authority_sk, "authority_sk")?;

        match self
            .inner
            .register_device(u_id, d_id, d_pk, &human_label, &auth_sk, timestamp as u64)
        {
            Ok(hash) => Ok(hash.to_vec()),
            Err(e) => Err(to_js_err(e)),
        }
    }

    #[wasm_bindgen(js_name = revokeDevice)]
    pub fn revoke_device(
        &mut self,
        device_id: &[u8],
        authority_sk: &[u8],
        timestamp: u32,
    ) -> Result<(), JsValue> {
        let d_id = to_arr16(device_id, "device_id")?;
        let auth_sk = to_hybrid_secret_key(authority_sk, "authority_sk")?;

        self.inner
            .revoke_device(d_id, &auth_sk, timestamp as u64)
            .map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = lookupByEntryHash)]
    pub fn lookup_by_entry_hash(&self, hash: &[u8]) -> Result<JsValue, JsValue> {
        let hash_arr = to_arr32(hash, "hash")?;
        let opt_entry = self
            .inner
            .lookup_by_entry_hash(&hash_arr)
            .map(entry_to_serde);
        serde_wasm_bindgen::to_value(&opt_entry).map_err(to_js_err)
    }

    #[wasm_bindgen(js_name = deviceWasActiveAt)]
    pub fn device_was_active_at(&self, device_id: &[u8], timestamp: u32) -> Result<bool, JsValue> {
        let d_id = to_arr16(device_id, "device_id")?;
        Ok(self.inner.device_was_active_at(&d_id, timestamp as u64))
    }

    #[wasm_bindgen(js_name = userForDevice)]
    pub fn user_for_device(&self, device_id: &[u8]) -> Result<JsValue, JsValue> {
        let d_id = to_arr16(device_id, "device_id")?;
        let opt_user = self.inner.user_for_device(&d_id).map(|u| u.to_vec());
        serde_wasm_bindgen::to_value(&opt_user).map_err(to_js_err)
    }
}

// ==================== Sender Resolution ====================

#[derive(Serialize, Deserialize)]
pub struct SenderInfo {
    #[serde(rename = "signerPubkey")]
    pub signer_pubkey: Vec<u8>,
    #[serde(rename = "userId")]
    pub user_id: Vec<u8>,
    #[serde(rename = "deviceId")]
    pub device_id: Vec<u8>,
    #[serde(rename = "deviceWasActive")]
    pub device_was_active: bool,
    #[serde(rename = "humanLabel")]
    pub human_label: Option<String>,
}

#[wasm_bindgen(js_name = resolveSender)]
pub fn resolve_sender(
    header: JsValue,
    key_log: &KeyLog,
    sealed_gk: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let obj: HeaderObj = serde_wasm_bindgen::from_value(header).map_err(to_js_err)?;
    let core_header = serde_to_header(obj)?;

    let mut core_sealed_gk = None;
    if let Some(gk) = sealed_gk {
        let gk_arr = to_arr32(&gk, "sealed_gk")?;
        core_sealed_gk = Some(gk_arr);
    }

    match vollcrypt_files_core::resolve_sender(
        &core_header,
        &key_log.inner,
        core_sealed_gk.as_ref(),
        vollcrypt_files_core::VerificationPolicy::RequireSigned,
    ) {
        Ok(info) => {
            let res = SenderInfo {
                signer_pubkey: info.signer_pubkey.write(),
                user_id: info.user_id.to_vec(),
                device_id: info.device_id.to_vec(),
                device_was_active: info.device_was_active,
                human_label: info.human_label,
            };
            serde_wasm_bindgen::to_value(&res).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[derive(Deserialize)]
pub struct SignInfoJs {
    kind: String, // "Plain" | "Sealed"
    #[serde(rename = "signerPk")]
    signer_pk: Vec<u8>,
    #[serde(rename = "signerSk")]
    signer_sk: Vec<u8>,
    #[serde(rename = "keyLogId")]
    key_log_id: Vec<u8>,
    timestamp: u64,
    #[serde(rename = "sealedGroupId")]
    sealed_group_id: Option<Vec<u8>>,
    #[serde(rename = "sealedGkVersion")]
    sealed_gk_version: Option<u32>,
    #[serde(rename = "sealedGk")]
    sealed_gk: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct IoWriteMode {
    pub mode: String,
    #[serde(rename = "batchSize")]
    pub batch_size: Option<u32>,
}

#[wasm_bindgen(js_name = encryptFilePipelinedAsync)]
pub async fn encrypt_file_pipelined_async_wasm(
    plaintext: &[u8],
    dek: &[u8],
    file_id: &[u8],
    chunk_size: usize,
    wraps: JsValue,
    mode_val: u8,
    sign_info_val: JsValue,
    write_mode_val: JsValue,
) -> Result<JsValue, JsValue> {
    let dek_arr = to_arr32(dek, "dek")?;
    let file_id_arr = to_arr16(file_id, "file_id")?;

    let wraps_objs: Vec<WrapEntry> = serde_wasm_bindgen::from_value(wraps).map_err(to_js_err)?;
    let mut core_wraps = Vec::with_capacity(wraps_objs.len());
    for w in wraps_objs {
        core_wraps.push(serde_to_wrap_entry(w)?);
    }

    let mode = vollcrypt_files_core::Mode::try_from(mode_val)
        .map_err(|_| JsValue::from_str("Invalid mode value"))?;

    let sign_info: Option<vollcrypt_files_core::PipelinedSignInfo> =
        if sign_info_val.is_null() || sign_info_val.is_undefined() {
            None
        } else {
            let js_info: SignInfoJs =
                serde_wasm_bindgen::from_value(sign_info_val).map_err(to_js_err)?;
            let signer_pk = to_hybrid_pubkey(&js_info.signer_pk, "signerPk")?;
            let signer_sk = to_hybrid_secret_key(&js_info.signer_sk, "signerSk")?;
            let key_log_id = to_arr32(&js_info.key_log_id, "keyLogId")?;

            match js_info.kind.as_str() {
                "Plain" => Some(vollcrypt_files_core::PipelinedSignInfo::Plain {
                    signer_pk,
                    signer_sk,
                    key_log_id,
                    timestamp: js_info.timestamp,
                }),
                "Sealed" => {
                    let group_id_buf = js_info
                        .sealed_group_id
                        .ok_or_else(|| JsValue::from_str("Missing sealedGroupId"))?;
                    let sealed_group_id = to_arr16(&group_id_buf, "sealedGroupId")?;
                    let sealed_gk_version = js_info
                        .sealed_gk_version
                        .ok_or_else(|| JsValue::from_str("Missing sealedGkVersion"))?;
                    let sealed_gk_buf = js_info
                        .sealed_gk
                        .ok_or_else(|| JsValue::from_str("Missing sealedGk"))?;
                    let sealed_gk = to_arr32(&sealed_gk_buf, "sealedGk")?;
                    Some(vollcrypt_files_core::PipelinedSignInfo::Sealed {
                        signer_pk,
                        signer_sk,
                        key_log_id,
                        timestamp: js_info.timestamp,
                        sealed_group_id,
                        sealed_gk_version,
                        sealed_gk,
                    })
                }
                _ => return Err(JsValue::from_str("Unknown PipelinedSignInfo kind")),
            }
        };

    // Parse write_mode to ensure JS caller passed valid schema, though ignored in in-memory WASM mode
    let _write_mode: Option<IoWriteMode> =
        if write_mode_val.is_null() || write_mode_val.is_undefined() {
            None
        } else {
            Some(serde_wasm_bindgen::from_value(write_mode_val).map_err(to_js_err)?)
        };

    // Register WasmWebCryptoProvider
    #[cfg(target_arch = "wasm32")]
    let _ = vollcrypt_files_core::set_crypto_provider(Box::new(
        vollcrypt_files_core::WasmWebCryptoProvider,
    ));

    match vollcrypt_files_core::pipelined_io::encrypt_file_pipelined_async(
        plaintext,
        &dek_arr,
        &file_id_arr,
        chunk_size,
        core_wraps,
        mode,
        sign_info,
    )
    .await
    {
        Ok((header, encrypted_data)) => {
            #[derive(Serialize)]
            struct EncryptResultJs {
                header: HeaderObj,
                ciphertext: Vec<u8>,
            }
            let res = EncryptResultJs {
                header: header_to_serde(header),
                ciphertext: encrypted_data,
            };
            serde_wasm_bindgen::to_value(&res).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[wasm_bindgen(js_name = decryptFilePipelinedAsync)]
pub async fn decrypt_file_pipelined_async_wasm(
    ciphertext: &[u8],
    dek: &[u8],
) -> Result<JsValue, JsValue> {
    let dek_arr = to_arr32(dek, "dek")?;

    // Register WasmWebCryptoProvider
    #[cfg(target_arch = "wasm32")]
    let _ = vollcrypt_files_core::set_crypto_provider(Box::new(
        vollcrypt_files_core::WasmWebCryptoProvider,
    ));

    match vollcrypt_files_core::pipelined_io::decrypt_file_pipelined_async(ciphertext, &dek_arr)
        .await
    {
        Ok((header, plaintext)) => {
            #[derive(Serialize)]
            struct DecryptResultJs {
                header: HeaderObj,
                plaintext: Vec<u8>,
            }
            let res = DecryptResultJs {
                header: header_to_serde(header),
                plaintext,
            };
            serde_wasm_bindgen::to_value(&res).map_err(to_js_err)
        }
        Err(e) => Err(to_js_err(e)),
    }
}

#[derive(Deserialize)]
pub struct WasmSealOptions {
    pub mode: String, // "seal" | "purge"
    pub reason: Option<String>,
    #[serde(rename = "signInfo")]
    pub sign_info: Option<SignInfoJs>,
}

fn wasm_to_seal_options(opts: WasmSealOptions) -> Result<vollcrypt_files_core::SealOptions, JsValue> {
    let mode = match opts.mode.as_str() {
        "seal" => vollcrypt_files_core::SealMode::Seal,
        "purge" => vollcrypt_files_core::SealMode::Purge,
        _ => return Err(JsValue::from_str("mode must be 'seal' or 'purge'")),
    };
    let sign_info = match opts.sign_info {
        Some(si) => {
            let signer_pk = to_hybrid_pubkey(&si.signer_pk, "signerPk")?;
            let signer_sk = to_hybrid_secret_key(&si.signer_sk, "signerSk")?;
            let key_log_id = to_arr32(&si.key_log_id, "keyLogId")?;
            match si.kind.as_str() {
                "Plain" => Some(vollcrypt_files_core::PipelinedSignInfo::Plain {
                    signer_pk,
                    signer_sk,
                    key_log_id,
                    timestamp: si.timestamp,
                }),
                "Sealed" => {
                    let group_id_buf = si.sealed_group_id.ok_or_else(|| JsValue::from_str("Missing sealedGroupId"))?;
                    let sealed_group_id = to_arr16(&group_id_buf, "sealedGroupId")?;
                    let sealed_gk_version = si.sealed_gk_version.ok_or_else(|| JsValue::from_str("Missing sealedGkVersion"))?;
                    let sealed_gk_buf = si.sealed_gk.ok_or_else(|| JsValue::from_str("Missing sealedGk"))?;
                    let sealed_gk = to_arr32(&sealed_gk_buf, "sealedGk")?;
                    Some(vollcrypt_files_core::PipelinedSignInfo::Sealed {
                        signer_pk,
                        signer_sk,
                        key_log_id,
                        timestamp: si.timestamp,
                        sealed_group_id,
                        sealed_gk_version,
                        sealed_gk,
                    })
                }
                _ => return Err(JsValue::from_str("Unknown PipelinedSignInfo kind")),
            }
        }
        None => None,
    };
    Ok(vollcrypt_files_core::SealOptions {
        mode,
        reason: opts.reason,
        sign_info,
    })
}

#[derive(Deserialize)]
pub struct WasmShieldPolicy {
    #[serde(rename = "releaseMode")]
    pub release_mode: String,
    pub signature: String,
    #[serde(rename = "rollbackPin")]
    pub rollback_pin: Option<f64>,
    #[serde(rename = "founderAnchor")]
    pub founder_anchor: Option<bool>,
    #[serde(rename = "onTamper")]
    pub on_tamper: String,
    #[serde(rename = "verifySealedMarker")]
    pub verify_sealed_marker: Option<bool>,
}

fn wasm_to_shield_policy(policy: WasmShieldPolicy) -> Result<vollcrypt_files_core::ShieldPolicy, JsValue> {
    let release_mode = match policy.release_mode.as_str() {
        "verified" => vollcrypt_files_core::ReleaseMode::Verified,
        "streaming" => vollcrypt_files_core::ReleaseMode::Streaming,
        _ => return Err(JsValue::from_str("releaseMode must be 'verified' or 'streaming'")),
    };
    let signature = match policy.signature.as_str() {
        "required" => vollcrypt_files_core::SignaturePolicy::Required,
        "optional" => vollcrypt_files_core::SignaturePolicy::Optional,
        _ => return Err(JsValue::from_str("signature must be 'required' or 'optional'")),
    };
    let on_tamper = match policy.on_tamper.as_str() {
        "abort" => vollcrypt_files_core::OnTamper::Abort,
        "report" => vollcrypt_files_core::OnTamper::AbortWithReport,
        "recover" => vollcrypt_files_core::OnTamper::AttemptRecovery,
        _ => return Err(JsValue::from_str("onTamper must be 'abort', 'report' or 'recover'")),
    };
    Ok(vollcrypt_files_core::ShieldPolicy {
        release_mode,
        signature,
        rollback_pin: policy.rollback_pin.map(|p| p as u64),
        founder_anchor: policy.founder_anchor.unwrap_or(true),
        on_tamper,
        verify_sealed_marker: policy.verify_sealed_marker.unwrap_or(true),
    })
}

#[wasm_bindgen(js_name = isSealed)]
pub fn is_sealed_wasm(header_obj: JsValue) -> Result<bool, JsValue> {
    let header_serde: HeaderObj = serde_wasm_bindgen::from_value(header_obj).map_err(to_js_err)?;
    let core_header = serde_to_header(header_serde)?;
    Ok(vollcrypt_files_core::is_sealed(&core_header))
}

#[wasm_bindgen(js_name = sealContainer)]
pub fn seal_container_wasm(
    container_bytes: &[u8],
    options: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let opts_wasm: WasmSealOptions = serde_wasm_bindgen::from_value(options).map_err(to_js_err)?;
    let core_opts = wasm_to_seal_options(opts_wasm)?;

    let mut source = std::io::Cursor::new(container_bytes);
    let mut dest_buf = Vec::new();
    let mut dest = std::io::Cursor::new(&mut dest_buf);

    vollcrypt_files_core::seal_container(&mut source, &mut dest, core_opts)
        .map_err(to_js_err)?;

    Ok(dest_buf)
}

#[derive(Serialize)]
pub struct WasmSealedInspection {
    pub version: u8,
    #[serde(rename = "fileId")]
    pub file_id: Vec<u8>,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u32,
    #[serde(rename = "plaintextSize")]
    pub plaintext_size: f64,
    #[serde(rename = "merkleRoot")]
    pub merkle_root: Vec<u8>,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: u8,
    #[serde(rename = "sealedMode")]
    pub sealed_mode: Option<u32>,
    pub reason: Option<String>,
    pub timestamp: Option<u32>,
    #[serde(rename = "ciphertextPresent")]
    pub ciphertext_present: bool,
}

#[wasm_bindgen(js_name = inspectSealedContainer)]
pub fn inspect_sealed_wasm(
    container_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let cursor = std::io::Cursor::new(container_bytes);
    let output = vollcrypt_files_core::inspect_sealed(cursor).map_err(to_js_err)?;

    let res = WasmSealedInspection {
        version: output.version,
        file_id: output.file_id.to_vec(),
        chunk_size: output.chunk_size,
        plaintext_size: output.plaintext_size as f64,
        merkle_root: output.merkle_root.to_vec(),
        hash_algorithm: output.hash_algorithm as u8,
        sealed_mode: output.sealed_mode.map(|m| m as u32),
        reason: output.reason,
        timestamp: output.timestamp.map(|t| t as u32),
        ciphertext_present: output.ciphertext_present,
    };

    serde_wasm_bindgen::to_value(&res).map_err(to_js_err)
}

#[wasm_bindgen(js_name = verifyContainer)]
pub fn verify_container_wasm(
    container_bytes: &[u8],
    policy: JsValue,
) -> Result<String, JsValue> {
    let policy_wasm: WasmShieldPolicy = serde_wasm_bindgen::from_value(policy).map_err(to_js_err)?;
    let core_policy = wasm_to_shield_policy(policy_wasm)?;

    let cursor = std::io::Cursor::new(container_bytes);
    let report = vollcrypt_files_core::verify_container(cursor, &core_policy);
    Ok(format!("{:?}", report))
}

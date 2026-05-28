use napi::{
    bindgen_prelude::{AsyncTask, Buffer, Uint8Array},
    Env, Error, Result, Task,
};
use napi_derive::napi;
use vollcrypt_files_core::{
    self, decrypt_chunk as core_decrypt_chunk, encrypt_chunk as core_encrypt_chunk,
    generate_recipient_keypair as core_generate_recipient_keypair,
    unwrap_key_with_recipient_key as core_unwrap_key_with_recipient_key,
    wrap_key_to_recipient as core_wrap_key_to_recipient, RecipientPublicKey, RecipientSecretKey,
};

// Helper utilities to parse slices into fixed-size arrays without panicking
fn to_arr32(slice: &[u8], name: &str) -> Result<[u8; 32]> {
    if slice.len() != 32 {
        return Err(Error::from_reason(format!(
            "{} must be exactly 32 bytes, got {}",
            name,
            slice.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn to_arr16(slice: &[u8], name: &str) -> Result<[u8; 16]> {
    if slice.len() != 16 {
        return Err(Error::from_reason(format!(
            "{} must be exactly 16 bytes, got {}",
            name,
            slice.len()
        )));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn to_arr12(slice: &[u8], name: &str) -> Result<[u8; 12]> {
    if slice.len() != 12 {
        return Err(Error::from_reason(format!(
            "{} must be exactly 12 bytes, got {}",
            name,
            slice.len()
        )));
    }
    let mut arr = [0u8; 12];
    arr.copy_from_slice(slice);
    Ok(arr)
}

fn to_arr40(slice: &[u8], name: &str) -> Result<[u8; 40]> {
    if slice.len() != 40 {
        return Err(Error::from_reason(format!(
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

#[napi]
pub fn generate_dek() -> Buffer {
    Buffer::from(vollcrypt_files_core::generate_dek().to_vec())
}

#[napi]
pub fn generate_file_id() -> Buffer {
    Buffer::from(vollcrypt_files_core::generate_file_id().to_vec())
}

#[napi]
pub fn generate_salt() -> Buffer {
    Buffer::from(vollcrypt_files_core::generate_salt().to_vec())
}

#[napi]
pub fn generate_gk() -> Buffer {
    Buffer::from(vollcrypt_files_core::generate_gk().to_vec())
}

// ==================== Chunk Operations ====================

#[napi(object)]
pub struct ChunkEnvelope {
    pub chunk_index: u32,
    pub iv: Buffer,
    pub ciphertext: Buffer,
    pub tag: Buffer,
}

#[napi]
pub fn encrypt_chunk(
    dek: Uint8Array,
    file_id: Uint8Array,
    chunk_index: u32,
    plaintext: Uint8Array,
) -> Result<ChunkEnvelope> {
    let dek_arr = to_arr32(dek.as_ref(), "dek")?;
    let file_id_arr = to_arr16(file_id.as_ref(), "file_id")?;

    match core_encrypt_chunk(&dek_arr, &file_id_arr, chunk_index, plaintext.as_ref()) {
        Ok(envelope) => Ok(ChunkEnvelope {
            chunk_index: envelope.chunk_index,
            iv: Buffer::from(envelope.iv.to_vec()),
            ciphertext: Buffer::from(envelope.ciphertext),
            tag: Buffer::from(envelope.tag.to_vec()),
        }),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn decrypt_chunk(
    dek: Uint8Array,
    file_id: Uint8Array,
    chunk_index: u32,
    envelope: ChunkEnvelope,
) -> Result<Buffer> {
    let dek_arr = to_arr32(dek.as_ref(), "dek")?;
    let file_id_arr = to_arr16(file_id.as_ref(), "file_id")?;
    let iv_arr = to_arr12(envelope.iv.as_ref(), "envelope.iv")?;
    let mut tag_arr = [0u8; 16];
    if envelope.tag.len() != 16 {
        return Err(Error::from_reason("Tag must be exactly 16 bytes"));
    }
    tag_arr.copy_from_slice(envelope.tag.as_ref());

    let core_envelope = vollcrypt_files_core::ChunkEnvelope {
        chunk_index,
        iv: iv_arr,
        ciphertext: envelope.ciphertext.to_vec(),
        tag: tag_arr,
    };

    match core_decrypt_chunk(&dek_arr, &file_id_arr, chunk_index, &core_envelope) {
        Ok(plaintext) => Ok(Buffer::from(plaintext)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn chunk_leaf_hash(envelope: ChunkEnvelope) -> Result<Buffer> {
    let iv_arr = to_arr12(envelope.iv.as_ref(), "envelope.iv")?;
    let mut tag_arr = [0u8; 16];
    if envelope.tag.len() != 16 {
        return Err(Error::from_reason("Tag must be exactly 16 bytes"));
    }
    tag_arr.copy_from_slice(envelope.tag.as_ref());

    let core_envelope = vollcrypt_files_core::ChunkEnvelope {
        chunk_index: envelope.chunk_index,
        iv: iv_arr,
        ciphertext: envelope.ciphertext.to_vec(),
        tag: tag_arr,
    };

    let hash = vollcrypt_files_core::chunk_leaf_hash(&core_envelope);
    Ok(Buffer::from(hash.to_vec()))
}

// ==================== Merkle Tree ====================

#[napi]
pub fn merkle_root(leaves: Vec<Uint8Array>) -> Result<Buffer> {
    let mut core_leaves = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        let arr = to_arr32(leaf.as_ref(), "leaf")?;
        core_leaves.push(arr);
    }
    let tree = vollcrypt_files_core::MerkleTree::from_leaves(core_leaves);
    Ok(Buffer::from(tree.root().to_vec()))
}

#[napi]
pub fn merkle_proof(leaves: Vec<Uint8Array>, leaf_index: u32) -> Result<Vec<Buffer>> {
    let mut core_leaves = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        let arr = to_arr32(leaf.as_ref(), "leaf")?;
        core_leaves.push(arr);
    }
    let tree = vollcrypt_files_core::MerkleTree::from_leaves(core_leaves);
    let proof = tree.proof(leaf_index as usize);
    Ok(proof
        .into_iter()
        .map(|p| Buffer::from(p.to_vec()))
        .collect())
}

#[napi]
pub fn verify_merkle_proof(
    leaf: Uint8Array,
    leaf_index: u32,
    total_leaves: u32,
    proof: Vec<Uint8Array>,
    expected_root: Uint8Array,
) -> Result<bool> {
    let leaf_arr = to_arr32(leaf.as_ref(), "leaf")?;
    let root_arr = to_arr32(expected_root.as_ref(), "expected_root")?;

    let mut core_proof = Vec::with_capacity(proof.len());
    for p in proof {
        let arr = to_arr32(p.as_ref(), "proof_element")?;
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

#[napi(object)]
pub struct KdfChoice {
    pub kind: String, // "Pbkdf2" | "Argon2id"
    pub rounds: Option<u32>,
    pub m_cost: Option<u32>,
    pub t_cost: Option<u32>,
    pub p_cost: Option<u32>,
    pub salt: Option<Buffer>,
}

#[napi(object)]
pub struct WrapEntry {
    pub kind: String, // "PasswordPbkdf2" | "PasswordArgon2id" | "HybridKem" | "GroupWrap"
    pub salt: Option<Buffer>,
    pub rounds: Option<u32>,
    pub m_cost: Option<u32>,
    pub t_cost: Option<u32>,
    pub p_cost: Option<u32>,
    pub recipient_id: Option<Buffer>,
    pub gk_version: Option<u32>,
    pub ephemeral_x25519: Option<Buffer>,
    pub ciphertext_ml_kem: Option<Buffer>,
    pub group_id: Option<Buffer>,
    pub wrapped_key: Buffer,
}

fn wrap_entry_to_napi(entry: vollcrypt_files_core::WrapEntry) -> WrapEntry {
    match entry {
        vollcrypt_files_core::WrapEntry::PasswordPbkdf2 {
            salt,
            iterations,
            wrapped_dek,
        } => WrapEntry {
            kind: "PasswordPbkdf2".to_string(),
            salt: Some(Buffer::from(salt.to_vec())),
            rounds: Some(iterations),
            m_cost: None,
            t_cost: None,
            p_cost: None,
            recipient_id: None,
            gk_version: None,
            ephemeral_x25519: None,
            ciphertext_ml_kem: None,
            group_id: None,
            wrapped_key: Buffer::from(wrapped_dek.to_vec()),
        },
        vollcrypt_files_core::WrapEntry::PasswordArgon2id {
            salt,
            m_cost,
            t_cost,
            p_cost,
            wrapped_dek,
        } => WrapEntry {
            kind: "PasswordArgon2id".to_string(),
            salt: Some(Buffer::from(salt.to_vec())),
            rounds: None,
            m_cost: Some(m_cost),
            t_cost: Some(t_cost),
            p_cost: Some(p_cost),
            recipient_id: None,
            gk_version: None,
            ephemeral_x25519: None,
            ciphertext_ml_kem: None,
            group_id: None,
            wrapped_key: Buffer::from(wrapped_dek.to_vec()),
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
            recipient_id: Some(Buffer::from(recipient_id.to_vec())),
            gk_version: Some(gk_version),
            ephemeral_x25519: Some(Buffer::from(x25519_ephemeral.to_vec())),
            ciphertext_ml_kem: Some(Buffer::from(mlkem_ciphertext)),
            group_id: None,
            wrapped_key: Buffer::from(wrapped_dek.to_vec()),
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
            group_id: Some(Buffer::from(group_id.to_vec())),
            wrapped_key: Buffer::from(wrapped_dek.to_vec()),
        },
    }
}

fn napi_to_wrap_entry(entry: WrapEntry) -> Result<vollcrypt_files_core::WrapEntry> {
    match entry.kind.as_str() {
        "PasswordPbkdf2" => {
            let salt_buf = entry
                .salt
                .ok_or_else(|| Error::from_reason("Missing salt for PasswordPbkdf2"))?;
            let mut salt = [0u8; 16];
            if salt_buf.len() != 16 {
                return Err(Error::from_reason(
                    "Salt must be 16 bytes for PasswordPbkdf2",
                ));
            }
            salt.copy_from_slice(salt_buf.as_ref());
            let iterations = entry
                .rounds
                .ok_or_else(|| Error::from_reason("Missing rounds for PasswordPbkdf2"))?;
            let wrapped_dek = to_arr40(entry.wrapped_key.as_ref(), "wrapped_key")?;
            Ok(vollcrypt_files_core::WrapEntry::PasswordPbkdf2 {
                salt,
                iterations,
                wrapped_dek,
            })
        }
        "PasswordArgon2id" => {
            let salt_buf = entry
                .salt
                .ok_or_else(|| Error::from_reason("Missing salt for PasswordArgon2id"))?;
            let mut salt = [0u8; 16];
            if salt_buf.len() != 16 {
                return Err(Error::from_reason(
                    "Salt must be 16 bytes for PasswordArgon2id",
                ));
            }
            salt.copy_from_slice(salt_buf.as_ref());
            let m_cost = entry
                .m_cost
                .ok_or_else(|| Error::from_reason("Missing m_cost for PasswordArgon2id"))?;
            let t_cost = entry
                .t_cost
                .ok_or_else(|| Error::from_reason("Missing t_cost for PasswordArgon2id"))?;
            let p_cost = entry
                .p_cost
                .ok_or_else(|| Error::from_reason("Missing p_cost for PasswordArgon2id"))?;
            let wrapped_dek = to_arr40(entry.wrapped_key.as_ref(), "wrapped_key")?;
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
                .ok_or_else(|| Error::from_reason("Missing recipient_id for HybridKem"))?;
            let recipient_id = to_arr16(recipient_id_buf.as_ref(), "recipient_id")?;
            let gk_version = entry
                .gk_version
                .ok_or_else(|| Error::from_reason("Missing gk_version for HybridKem"))?;
            let ephemeral_x25519_buf = entry
                .ephemeral_x25519
                .ok_or_else(|| Error::from_reason("Missing ephemeral_x25519 for HybridKem"))?;
            let x25519_ephemeral = to_arr32(ephemeral_x25519_buf.as_ref(), "ephemeral_x25519")?;
            let mlkem_ciphertext = entry
                .ciphertext_ml_kem
                .ok_or_else(|| Error::from_reason("Missing ciphertext_ml_kem for HybridKem"))?
                .to_vec();
            let wrapped_dek = to_arr40(entry.wrapped_key.as_ref(), "wrapped_key")?;
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
                .ok_or_else(|| Error::from_reason("Missing group_id for GroupWrap"))?;
            let group_id = to_arr16(group_id_buf.as_ref(), "group_id")?;
            let gk_version = entry
                .gk_version
                .ok_or_else(|| Error::from_reason("Missing gk_version for GroupWrap"))?;
            let wrapped_dek = to_arr40(entry.wrapped_key.as_ref(), "wrapped_key")?;
            Ok(vollcrypt_files_core::WrapEntry::GroupWrap {
                group_id,
                gk_version,
                wrapped_dek,
            })
        }
        _ => Err(Error::from_reason(format!(
            "Unknown WrapEntry kind: {}",
            entry.kind
        ))),
    }
}

fn napi_to_kdf_choice(choice: KdfChoice) -> Result<vollcrypt_files_core::KdfChoice> {
    match choice.kind.as_str() {
        "Pbkdf2" => {
            let iterations = choice
                .rounds
                .ok_or_else(|| Error::from_reason("Missing rounds for Pbkdf2"))?;
            Ok(vollcrypt_files_core::KdfChoice::Pbkdf2 { iterations })
        }
        "Argon2id" => {
            let m_cost = choice
                .m_cost
                .ok_or_else(|| Error::from_reason("Missing m_cost for Argon2id"))?;
            let t_cost = choice
                .t_cost
                .ok_or_else(|| Error::from_reason("Missing t_cost for Argon2id"))?;
            let p_cost = choice
                .p_cost
                .ok_or_else(|| Error::from_reason("Missing p_cost for Argon2id"))?;
            Ok(vollcrypt_files_core::KdfChoice::Argon2id {
                m_cost,
                t_cost,
                p_cost,
            })
        }
        _ => Err(Error::from_reason(format!(
            "Unknown KdfChoice kind: {}",
            choice.kind
        ))),
    }
}

#[napi]
pub fn wrap_dek_with_password(
    dek: Uint8Array,
    password: String,
    kdf: KdfChoice,
) -> Result<WrapEntry> {
    let dek_arr = to_arr32(dek.as_ref(), "dek")?;
    let core_kdf = napi_to_kdf_choice(kdf)?;

    match vollcrypt_files_core::wrap_dek_with_password(&dek_arr, password.as_bytes(), core_kdf) {
        Ok(entry) => Ok(wrap_entry_to_napi(entry)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn unwrap_dek_with_password(wrap: WrapEntry, password: String) -> Result<Buffer> {
    let core_wrap = napi_to_wrap_entry(wrap)?;
    match vollcrypt_files_core::unwrap_dek_with_password(&core_wrap, password.as_bytes()) {
        Ok(dek) => Ok(Buffer::from(dek.to_vec())),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

pub struct PasswordUnwrapTask {
    wrap: vollcrypt_files_core::WrapEntry,
    password: String,
}

impl Task for PasswordUnwrapTask {
    type Output = [u8; 32];
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        match vollcrypt_files_core::unwrap_dek_with_password(&self.wrap, self.password.as_bytes()) {
            Ok(dek) => Ok(dek),
            Err(e) => Err(Error::from_reason(e.to_string())),
        }
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(Buffer::from(output.to_vec()))
    }
}

#[napi]
pub fn unwrap_dek_with_password_async(
    wrap: WrapEntry,
    password: String,
) -> Result<AsyncTask<PasswordUnwrapTask>> {
    let core_wrap = napi_to_wrap_entry(wrap)?;
    Ok(AsyncTask::new(PasswordUnwrapTask {
        wrap: core_wrap,
        password,
    }))
}

// ==================== Recipient / KEM Mode ====================

#[napi(object)]
pub struct KeySubpair {
    pub x25519: Buffer,
    pub ml_kem: Buffer,
}

#[napi(object)]
pub struct RecipientKeypair {
    pub public_key: KeySubpair,
    pub secret_key: KeySubpair,
}

#[napi]
pub fn generate_recipient_keypair() -> Result<RecipientKeypair> {
    let (pk, sk) = core_generate_recipient_keypair();
    Ok(RecipientKeypair {
        public_key: KeySubpair {
            x25519: Buffer::from(pk.x25519.to_vec()),
            ml_kem: Buffer::from(pk.ml_kem.to_vec()),
        },
        secret_key: KeySubpair {
            x25519: Buffer::from(sk.x25519.to_vec()),
            ml_kem: Buffer::from(sk.ml_kem.to_vec()),
        },
    })
}

#[napi]
pub fn wrap_key_to_recipient(
    key: Uint8Array,
    recipient_id: Uint8Array,
    gk_version: u32,
    recipient_pk: KeySubpair,
) -> Result<WrapEntry> {
    let key_arr = to_arr32(key.as_ref(), "key")?;
    let r_id_arr = to_arr16(recipient_id.as_ref(), "recipient_id")?;

    let pk_x25519 = to_arr32(recipient_pk.x25519.as_ref(), "recipient_pk.x25519")?;
    let mut pk_mlkem = [0u8; 1184];
    if recipient_pk.ml_kem.len() != 1184 {
        return Err(Error::from_reason("ML-KEM public key must be 1184 bytes"));
    }
    pk_mlkem.copy_from_slice(recipient_pk.ml_kem.as_ref());

    let core_pk = RecipientPublicKey {
        x25519: pk_x25519,
        ml_kem: Box::new(pk_mlkem),
    };

    match core_wrap_key_to_recipient(&key_arr, r_id_arr, gk_version, &core_pk) {
        Ok(entry) => Ok(wrap_entry_to_napi(entry)),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn unwrap_key_with_recipient_key(wrap: WrapEntry, recipient_sk: KeySubpair) -> Result<Buffer> {
    let core_wrap = napi_to_wrap_entry(wrap)?;

    let sk_x25519 = to_arr32(recipient_sk.x25519.as_ref(), "recipient_sk.x25519")?;
    let mut sk_mlkem = [0u8; 2400];
    if recipient_sk.ml_kem.len() != 2400 {
        return Err(Error::from_reason("ML-KEM secret key must be 2400 bytes"));
    }
    sk_mlkem.copy_from_slice(recipient_sk.ml_kem.as_ref());

    let core_sk = RecipientSecretKey {
        x25519: sk_x25519,
        ml_kem: Box::new(sk_mlkem),
    };

    match core_unwrap_key_with_recipient_key(&core_wrap, &core_sk) {
        Ok(key) => Ok(Buffer::from(key.to_vec())),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// ==================== Group Operations ====================

#[napi]
pub fn wrap_dek_for_group(
    dek: Uint8Array,
    group_id: Uint8Array,
    gk_version: u32,
    gk: Uint8Array,
) -> Result<WrapEntry> {
    let dek_arr = to_arr32(dek.as_ref(), "dek")?;
    let group_id_arr = to_arr16(group_id.as_ref(), "group_id")?;
    let gk_arr = to_arr32(gk.as_ref(), "gk")?;

    let entry =
        vollcrypt_files_core::wrap_dek_for_group(&dek_arr, group_id_arr, gk_version, &gk_arr);
    Ok(wrap_entry_to_napi(entry))
}

#[napi]
pub fn unwrap_dek_with_group_key(wrap: WrapEntry, gk: Uint8Array) -> Result<Buffer> {
    let core_wrap = napi_to_wrap_entry(wrap)?;
    let gk_arr = to_arr32(gk.as_ref(), "gk")?;

    match vollcrypt_files_core::unwrap_dek_with_group_key(&core_wrap, &gk_arr) {
        Ok(dek) => Ok(Buffer::from(dek.to_vec())),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// ==================== Ed25519 Signatures ====================

#[napi(object)]
pub struct Ed25519KeypairObj {
    pub public_key: Buffer,
    pub secret_key: Buffer,
}

#[napi]
pub fn ed25519_keypair_generate() -> Ed25519KeypairObj {
    let (pk, sk) = vollcrypt_files_core::ed25519_keypair_generate();
    Ed25519KeypairObj {
        public_key: Buffer::from(pk.to_vec()),
        secret_key: Buffer::from(sk.to_vec()),
    }
}

#[napi]
pub fn ed25519_sign(sk: Uint8Array, message: Uint8Array) -> Result<Buffer> {
    let sk_arr = to_arr32(sk.as_ref(), "sk")?;
    let sig = vollcrypt_files_core::ed25519_sign(&sk_arr, message.as_ref());
    Ok(Buffer::from(sig.to_vec()))
}

#[napi]
pub fn ed25519_verify(pk: Uint8Array, message: Uint8Array, signature: Uint8Array) -> Result<bool> {
    let pk_arr = to_arr32(pk.as_ref(), "pk")?;
    if signature.len() != 64 {
        return Err(Error::from_reason("Signature must be exactly 64 bytes"));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature.as_ref());

    Ok(vollcrypt_files_core::ed25519_verify(&pk_arr, message.as_ref(), &sig_arr).is_ok())
}

// ==================== GroupManifest Class ====================

#[napi(object)]
pub struct MemberPublicKeyObj {
    pub recipient: KeySubpair,
    pub signing_pk: Buffer,
}

#[napi]
pub struct GroupManifest {
    inner: vollcrypt_files_core::GroupManifest,
}

#[napi]
impl GroupManifest {
    #[napi]
    pub fn genesis(
        group_id: Uint8Array,
        initial_gk: Uint8Array,
        founder_member_id: Uint8Array,
        founder_recipient_pk: KeySubpair,
        founder_ed25519_pk: Uint8Array,
        founder_ed25519_sk: Uint8Array,
        _timestamp: u32,
    ) -> Result<GroupManifest> {
        let group_id_arr = to_arr16(group_id.as_ref(), "group_id")?;
        let initial_gk_arr = to_arr32(initial_gk.as_ref(), "initial_gk")?;
        let founder_id_arr = to_arr16(founder_member_id.as_ref(), "founder_member_id")?;

        let r_x25519 = to_arr32(
            founder_recipient_pk.x25519.as_ref(),
            "founder_recipient_pk.x25519",
        )?;
        let mut r_mlkem = [0u8; 1184];
        if founder_recipient_pk.ml_kem.len() != 1184 {
            return Err(Error::from_reason("ML-KEM public key must be 1184 bytes"));
        }
        r_mlkem.copy_from_slice(founder_recipient_pk.ml_kem.as_ref());

        let rec_pk = RecipientPublicKey {
            x25519: r_x25519,
            ml_kem: Box::new(r_mlkem),
        };

        let f_ed_pk = to_arr32(founder_ed25519_pk.as_ref(), "founder_ed25519_pk")?;
        let f_ed_sk = to_arr32(founder_ed25519_sk.as_ref(), "founder_ed25519_sk")?;

        // In manifest genesis, the initial group key is wrapped to the founder's key.
        let gk_wrap = core_wrap_key_to_recipient(&initial_gk_arr, founder_id_arr, 1, &rec_pk)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let inner = vollcrypt_files_core::GroupManifest::genesis(
            group_id_arr,
            founder_id_arr,
            &f_ed_sk,
            f_ed_pk,
            rec_pk,
            gk_wrap,
        );

        Ok(GroupManifest { inner })
    }

    #[napi]
    pub fn parse(bytes: Uint8Array) -> Result<GroupManifest> {
        match vollcrypt_files_core::GroupManifest::parse(bytes.as_ref()) {
            Ok((inner, _)) => Ok(GroupManifest { inner }),
            Err(e) => Err(Error::from_reason(e.to_string())),
        }
    }

    #[napi]
    pub fn write(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.inner.write()))
    }

    #[napi]
    pub fn verify(&self) -> Result<()> {
        self.inner
            .verify()
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn add_member(
        &mut self,
        new_member_id: Uint8Array,
        new_member_pk: MemberPublicKeyObj,
        current_gk: Uint8Array,
        admin_pk: Uint8Array,
        admin_sk: Uint8Array,
        _timestamp: u32,
    ) -> Result<()> {
        let member_id_arr = to_arr16(new_member_id.as_ref(), "new_member_id")?;
        let admin_sk_arr = to_arr32(admin_sk.as_ref(), "admin_sk")?;
        let _admin_pk_arr = to_arr32(admin_pk.as_ref(), "admin_pk")?;
        let current_gk_arr = to_arr32(current_gk.as_ref(), "current_gk")?;

        let rx = to_arr32(
            new_member_pk.recipient.x25519.as_ref(),
            "new_member_pk.recipient.x25519",
        )?;
        let mut rm = [0u8; 1184];
        if new_member_pk.recipient.ml_kem.len() != 1184 {
            return Err(Error::from_reason("ML-KEM public key must be 1184 bytes"));
        }
        rm.copy_from_slice(new_member_pk.recipient.ml_kem.as_ref());

        let rec_pk = RecipientPublicKey {
            x25519: rx,
            ml_kem: Box::new(rm),
        };

        let signing_pk = to_arr32(
            new_member_pk.signing_pk.as_ref(),
            "new_member_pk.signing_pk",
        )?;

        // Automatically wrap current GK for new member using the manifest's current GK version
        let current_version = self.inner.current_gk_version();
        let gk_wrap =
            core_wrap_key_to_recipient(&current_gk_arr, member_id_arr, current_version, &rec_pk)
                .map_err(|e| Error::from_reason(e.to_string()))?;

        self.inner
            .add_member(&admin_sk_arr, member_id_arr, signing_pk, rec_pk, gk_wrap)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn remove_member(
        &mut self,
        removed_member_id: Uint8Array,
        _admin_pk: Uint8Array,
        admin_sk: Uint8Array,
        _timestamp: u32,
    ) -> Result<()> {
        let member_id_arr = to_arr16(removed_member_id.as_ref(), "removed_member_id")?;
        let admin_sk_arr = to_arr32(admin_sk.as_ref(), "admin_sk")?;

        self.inner
            .remove_member(&admin_sk_arr, member_id_arr)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn rotate_group_key(
        &mut self,
        new_gk: Uint8Array,
        admin_pk: Uint8Array,
        admin_sk: Uint8Array,
        timestamp: u32,
    ) -> Result<u32> {
        let new_gk_arr = to_arr32(new_gk.as_ref(), "new_gk")?;
        let admin_pk_arr = to_arr32(admin_pk.as_ref(), "admin_pk")?;
        let admin_sk_arr = to_arr32(admin_sk.as_ref(), "admin_sk")?;

        self.inner
            .rotate_group_key(&new_gk_arr, &admin_pk_arr, &admin_sk_arr, timestamp as u64)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn shred_group_key(
        &mut self,
        version_to_shred: u32,
        reason: String,
        admin_pk: Uint8Array,
        admin_sk: Uint8Array,
        timestamp: u32,
    ) -> Result<()> {
        let admin_pk_arr = to_arr32(admin_pk.as_ref(), "admin_pk")?;
        let admin_sk_arr = to_arr32(admin_sk.as_ref(), "admin_sk")?;

        self.inner
            .shred_group_key(
                version_to_shred,
                &reason,
                &admin_pk_arr,
                &admin_sk_arr,
                timestamp as u64,
            )
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn current_members(&self) -> Vec<Buffer> {
        self.inner
            .current_members()
            .into_iter()
            .map(|m| Buffer::from(m.to_vec()))
            .collect()
    }

    #[napi]
    pub fn current_gk_version(&self) -> u32 {
        self.inner.current_gk_version()
    }

    #[napi]
    pub fn find_member_wrap(&self, member_id: Uint8Array) -> Result<WrapEntry> {
        let member_id_arr = to_arr16(member_id.as_ref(), "member_id")?;
        match self.inner.find_member_wrap(&member_id_arr) {
            Ok(wrap) => Ok(wrap_entry_to_napi(wrap)),
            Err(e) => Err(Error::from_reason(e.to_string())),
        }
    }

    #[napi]
    pub fn find_member_wrap_for_version(
        &self,
        member_id: Uint8Array,
        gk_version: u32,
    ) -> Result<WrapEntry> {
        let member_id_arr = to_arr16(member_id.as_ref(), "member_id")?;
        match self
            .inner
            .find_member_wrap_for_version(&member_id_arr, gk_version)
        {
            Ok(wrap) => Ok(wrap_entry_to_napi(wrap)),
            Err(e) => Err(Error::from_reason(e.to_string())),
        }
    }

    #[napi]
    pub fn is_version_shredded(&self, gk_version: u32) -> bool {
        self.inner.is_version_shredded(gk_version)
    }
}

// ==================== Header Structure Mappings ====================

#[napi(object)]
pub struct SignedMetadata {
    pub kind: String, // "Plain" | "Sealed"
    pub signer_pubkey: Option<Buffer>,
    pub timestamp: u32,
    pub key_log_id: Option<Buffer>,
    pub sealed_group_id: Option<Buffer>,
    pub sealed_gk_version: Option<u32>,
    pub iv: Option<Buffer>,
    pub sealed_payload: Option<Buffer>,
    pub sealed_tag: Option<Buffer>,
}

#[napi(object)]
pub struct HeaderObj {
    pub version: u8,
    pub mode: u8,
    pub cipher_id: u8,
    pub file_id: Buffer,
    pub chunk_size: u32,
    pub plaintext_size: f64,
    pub merkle_root: Buffer,
    pub hash_algorithm: u8,
    pub wraps: Vec<WrapEntry>,
    pub signed_metadata: Option<SignedMetadata>,
    pub signature: Option<Buffer>,
}

fn signed_metadata_to_napi(meta: vollcrypt_files_core::SignedMetadata) -> SignedMetadata {
    match meta {
        vollcrypt_files_core::SignedMetadata::Plain {
            signer_pubkey,
            timestamp,
            key_log_id,
        } => SignedMetadata {
            kind: "Plain".to_string(),
            signer_pubkey: Some(Buffer::from(signer_pubkey.to_vec())),
            timestamp: timestamp as u32,
            key_log_id: Some(Buffer::from(key_log_id.to_vec())),
            sealed_group_id: None,
            sealed_gk_version: None,
            iv: None,
            sealed_payload: None,
            sealed_tag: None,
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
            sealed_group_id: Some(Buffer::from(sealed_group_id.to_vec())),
            sealed_gk_version: Some(sealed_gk_version),
            iv: Some(Buffer::from(iv.to_vec())),
            sealed_payload: Some(Buffer::from(sealed_payload)),
            sealed_tag: Some(Buffer::from(sealed_tag.to_vec())),
        },
    }
}

fn napi_to_signed_metadata(meta: SignedMetadata) -> Result<vollcrypt_files_core::SignedMetadata> {
    match meta.kind.as_str() {
        "Plain" => {
            let pk_buf = meta
                .signer_pubkey
                .ok_or_else(|| Error::from_reason("Missing signer_pubkey"))?;
            let signer_pubkey = to_arr32(pk_buf.as_ref(), "signer_pubkey")?;

            let kl_buf = meta
                .key_log_id
                .ok_or_else(|| Error::from_reason("Missing key_log_id"))?;
            let key_log_id = to_arr32(kl_buf.as_ref(), "key_log_id")?;

            Ok(vollcrypt_files_core::SignedMetadata::Plain {
                signer_pubkey,
                timestamp: meta.timestamp as u64,
                key_log_id,
            })
        }
        "Sealed" => {
            let sg_buf = meta
                .sealed_group_id
                .ok_or_else(|| Error::from_reason("Missing sealed_group_id"))?;
            let sealed_group_id = to_arr16(sg_buf.as_ref(), "sealed_group_id")?;

            let sealed_gk_version = meta
                .sealed_gk_version
                .ok_or_else(|| Error::from_reason("Missing sealed_gk_version"))?;

            let iv_buf = meta.iv.ok_or_else(|| Error::from_reason("Missing iv"))?;
            let iv = to_arr12(iv_buf.as_ref(), "iv")?;

            let sealed_payload = meta
                .sealed_payload
                .ok_or_else(|| Error::from_reason("Missing sealed_payload"))?
                .to_vec();

            let tag_buf = meta
                .sealed_tag
                .ok_or_else(|| Error::from_reason("Missing sealed_tag"))?;
            let mut sealed_tag = [0u8; 16];
            if tag_buf.len() != 16 {
                return Err(Error::from_reason("sealed_tag must be exactly 16 bytes"));
            }
            sealed_tag.copy_from_slice(tag_buf.as_ref());

            Ok(vollcrypt_files_core::SignedMetadata::Sealed {
                sealed_group_id,
                sealed_gk_version,
                iv,
                sealed_payload,
                sealed_tag,
                timestamp: meta.timestamp as u64,
            })
        }
        _ => Err(Error::from_reason(format!(
            "Unknown SignedMetadata kind: {}",
            meta.kind
        ))),
    }
}

fn header_to_napi(header: vollcrypt_files_core::Header) -> HeaderObj {
    HeaderObj {
        version: header.version,
        mode: header.mode as u8,
        cipher_id: header.cipher_id as u8,
        file_id: Buffer::from(header.file_id.to_vec()),
        chunk_size: header.chunk_size,
        plaintext_size: header.plaintext_size as f64,
        merkle_root: Buffer::from(header.merkle_root.to_vec()),
        hash_algorithm: header.hash_algorithm as u8,
        wraps: header.wraps.into_iter().map(wrap_entry_to_napi).collect(),
        signed_metadata: header.signed_metadata.map(signed_metadata_to_napi),
        signature: header.signature.map(|s| Buffer::from(s.to_vec())),
    }
}

fn napi_to_header(obj: HeaderObj) -> Result<vollcrypt_files_core::Header> {
    let file_id = to_arr16(obj.file_id.as_ref(), "file_id")?;
    let merkle_root = to_arr32(obj.merkle_root.as_ref(), "merkle_root")?;

    let wraps = obj
        .wraps
        .into_iter()
        .map(napi_to_wrap_entry)
        .collect::<Result<Vec<_>>>()?;

    let signed_metadata = match obj.signed_metadata {
        Some(m) => Some(napi_to_signed_metadata(m)?),
        None => None,
    };

    let signature = match obj.signature {
        Some(s) => {
            if s.len() != 64 {
                return Err(Error::from_reason("signature must be 64 bytes"));
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(s.as_ref());
            Some(sig)
        }
        None => None,
    };

    let mode = vollcrypt_files_core::Mode::try_from(obj.mode)
        .map_err(|_| Error::from_reason("Invalid mode value"))?;

    let cipher_id = vollcrypt_files_core::CipherId::try_from(obj.cipher_id)
        .map_err(|_| Error::from_reason("Invalid cipher_id value"))?;

    let hash_algorithm = match obj.hash_algorithm {
        0 => vollcrypt_files_core::HashAlgorithm::Sha256,
        1 => vollcrypt_files_core::HashAlgorithm::Blake3,
        other => return Err(Error::from_reason(format!("Invalid hash_algorithm value: {}", other))),
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

#[napi(object)]
pub struct ParsedHeaderObj {
    pub header: HeaderObj,
    pub header_len: u32,
}

#[napi]
pub struct HeaderClass;

#[napi]
impl HeaderClass {
    #[napi]
    pub fn parse(bytes: Uint8Array) -> Result<ParsedHeaderObj> {
        match vollcrypt_files_core::Header::parse(bytes.as_ref()) {
            Ok((header, header_len)) => Ok(ParsedHeaderObj {
                header: header_to_napi(header),
                header_len: header_len as u32,
            }),
            Err(e) => Err(Error::from_reason(e.to_string())),
        }
    }

    #[napi]
    pub fn write(header: HeaderObj) -> Result<Buffer> {
        let core_header = napi_to_header(header)?;
        Ok(Buffer::from(core_header.write()))
    }
}

// ==================== File-Level Operations ====================

#[napi(object)]
pub struct RewrapResult {
    pub header: Buffer,
    pub updated_count: u32,
}

#[napi]
pub fn rewrap_dek_in_header(
    header_bytes: Uint8Array,
    old_gk: Uint8Array,
    new_gk: Uint8Array,
    new_gk_version: u32,
) -> Result<RewrapResult> {
    let old_gk_arr = to_arr32(old_gk.as_ref(), "old_gk")?;
    let new_gk_arr = to_arr32(new_gk.as_ref(), "new_gk")?;

    let (mut header, _) = vollcrypt_files_core::Header::parse(header_bytes.as_ref())
        .map_err(|e| Error::from_reason(e.to_string()))?;

    match vollcrypt_files_core::rewrap_dek_in_header(
        &mut header,
        &old_gk_arr,
        &new_gk_arr,
        new_gk_version,
    ) {
        Ok(updated_count) => Ok(RewrapResult {
            header: Buffer::from(header.write()),
            updated_count: updated_count as u32,
        }),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn crypto_shred_header(header_bytes: Uint8Array) -> Result<Buffer> {
    let (mut header, _) = vollcrypt_files_core::Header::parse(header_bytes.as_ref())
        .map_err(|e| Error::from_reason(e.to_string()))?;

    vollcrypt_files_core::crypto_shred_header(&mut header);
    Ok(Buffer::from(header.write()))
}

// ==================== Signature Plain / Sealed ====================

#[napi]
pub fn sign_header_plain(
    header: HeaderObj,
    signer_pk: Uint8Array,
    signer_sk: Uint8Array,
    key_log_id: Uint8Array,
    timestamp: u32,
) -> Result<HeaderObj> {
    let mut core_header = napi_to_header(header)?;
    let signer_pk_arr = to_arr32(signer_pk.as_ref(), "signer_pk")?;
    let signer_sk_arr = to_arr32(signer_sk.as_ref(), "signer_sk")?;
    let key_log_id_arr = to_arr32(key_log_id.as_ref(), "key_log_id")?;

    vollcrypt_files_core::sign_header_plain(
        &mut core_header,
        &signer_pk_arr,
        &signer_sk_arr,
        key_log_id_arr,
        timestamp as u64,
    )
    .map_err(|e| Error::from_reason(e.to_string()))?;

    Ok(header_to_napi(core_header))
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_header_sealed(
    header: HeaderObj,
    signer_pk: Uint8Array,
    signer_sk: Uint8Array,
    key_log_id: Uint8Array,
    timestamp: u32,
    sealed_group_id: Uint8Array,
    sealed_gk_version: u32,
    sealed_gk: Uint8Array,
) -> Result<HeaderObj> {
    let mut core_header = napi_to_header(header)?;
    let signer_pk_arr = to_arr32(signer_pk.as_ref(), "signer_pk")?;
    let signer_sk_arr = to_arr32(signer_sk.as_ref(), "signer_sk")?;
    let key_log_id_arr = to_arr32(key_log_id.as_ref(), "key_log_id")?;
    let group_id_arr = to_arr16(sealed_group_id.as_ref(), "sealed_group_id")?;
    let sealed_gk_arr = to_arr32(sealed_gk.as_ref(), "sealed_gk")?;

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
    .map_err(|e| Error::from_reason(e.to_string()))?;

    Ok(header_to_napi(core_header))
}

#[napi]
pub fn verify_header_signature_plain(header: HeaderObj) -> Result<Buffer> {
    let core_header = napi_to_header(header)?;
    match vollcrypt_files_core::verify_header_signature_plain(&core_header) {
        Ok(pubkey) => Ok(Buffer::from(pubkey.to_vec())),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

#[napi]
pub fn verify_header_signature_sealed(header: HeaderObj, sealed_gk: Uint8Array) -> Result<Buffer> {
    let core_header = napi_to_header(header)?;
    let gk_arr = to_arr32(sealed_gk.as_ref(), "sealed_gk")?;
    match vollcrypt_files_core::verify_header_signature_sealed(&core_header, &gk_arr) {
        Ok(pubkey) => Ok(Buffer::from(pubkey.to_vec())),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// ==================== KeyLog Class ====================

#[napi(object)]
pub struct KeyLogEntry {
    pub kind: String, // "DeviceRegister" | "DeviceRevoke"
    pub user_id: Option<Buffer>,
    pub device_id: Buffer,
    pub device_pubkey: Option<Buffer>,
    pub human_label: Option<String>,
    pub prev_hash: Buffer,
    pub timestamp: u32,
    pub signature: Buffer,
}

fn entry_to_napi(entry: &vollcrypt_files_core::KeyLogEntry) -> KeyLogEntry {
    match &entry.entry {
        vollcrypt_files_core::KeyLogEntryType::DeviceRegister {
            user_id,
            device_id,
            device_pubkey,
            human_label,
        } => KeyLogEntry {
            kind: "DeviceRegister".to_string(),
            user_id: Some(Buffer::from(user_id.to_vec())),
            device_id: Buffer::from(device_id.to_vec()),
            device_pubkey: Some(Buffer::from(device_pubkey.to_vec())),
            human_label: Some(human_label.clone()),
            prev_hash: Buffer::from(entry.prev_hash.to_vec()),
            timestamp: entry.timestamp as u32,
            signature: Buffer::from(entry.signature.to_vec()),
        },
        vollcrypt_files_core::KeyLogEntryType::DeviceRevoke { device_id } => KeyLogEntry {
            kind: "DeviceRevoke".to_string(),
            user_id: None,
            device_id: Buffer::from(device_id.to_vec()),
            device_pubkey: None,
            human_label: None,
            prev_hash: Buffer::from(entry.prev_hash.to_vec()),
            timestamp: entry.timestamp as u32,
            signature: Buffer::from(entry.signature.to_vec()),
        },
    }
}

#[napi]
pub struct KeyLog {
    inner: vollcrypt_files_core::KeyLog,
}

#[napi]
impl KeyLog {
    #[napi]
    pub fn create(authority_pubkey: Uint8Array) -> Result<KeyLog> {
        let auth_pk = to_arr32(authority_pubkey.as_ref(), "authority_pubkey")?;
        Ok(KeyLog {
            inner: vollcrypt_files_core::KeyLog::new(auth_pk),
        })
    }

    #[napi]
    pub fn parse(bytes: Uint8Array) -> Result<KeyLog> {
        match vollcrypt_files_core::KeyLog::parse(bytes.as_ref()) {
            Ok(inner) => Ok(KeyLog { inner }),
            Err(e) => Err(Error::from_reason(e.to_string())),
        }
    }

    #[napi]
    pub fn write(&self) -> Buffer {
        Buffer::from(self.inner.write())
    }

    #[napi]
    pub fn verify(&self) -> Result<()> {
        self.inner
            .verify()
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn register_device(
        &mut self,
        user_id: Uint8Array,
        device_id: Uint8Array,
        device_pk: Uint8Array,
        human_label: String,
        authority_sk: Uint8Array,
        timestamp: u32,
    ) -> Result<Buffer> {
        let u_id = to_arr16(user_id.as_ref(), "user_id")?;
        let d_id = to_arr16(device_id.as_ref(), "device_id")?;
        let d_pk = to_arr32(device_pk.as_ref(), "device_pk")?;
        let auth_sk = to_arr32(authority_sk.as_ref(), "authority_sk")?;

        match self
            .inner
            .register_device(u_id, d_id, d_pk, &human_label, &auth_sk, timestamp as u64)
        {
            Ok(hash) => Ok(Buffer::from(hash.to_vec())),
            Err(e) => Err(Error::from_reason(e.to_string())),
        }
    }

    #[napi]
    pub fn revoke_device(
        &mut self,
        device_id: Uint8Array,
        authority_sk: Uint8Array,
        timestamp: u32,
    ) -> Result<()> {
        let d_id = to_arr16(device_id.as_ref(), "device_id")?;
        let auth_sk = to_arr32(authority_sk.as_ref(), "authority_sk")?;

        self.inner
            .revoke_device(d_id, &auth_sk, timestamp as u64)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn lookup_by_entry_hash(&self, hash: Uint8Array) -> Result<Option<KeyLogEntry>> {
        let hash_arr = to_arr32(hash.as_ref(), "hash")?;
        Ok(self
            .inner
            .lookup_by_entry_hash(&hash_arr)
            .map(entry_to_napi))
    }

    #[napi]
    pub fn device_was_active_at(&self, device_id: Uint8Array, timestamp: u32) -> Result<bool> {
        let d_id = to_arr16(device_id.as_ref(), "device_id")?;
        Ok(self.inner.device_was_active_at(&d_id, timestamp as u64))
    }

    #[napi]
    pub fn user_for_device(&self, device_id: Uint8Array) -> Result<Option<Buffer>> {
        let d_id = to_arr16(device_id.as_ref(), "device_id")?;
        Ok(self
            .inner
            .user_for_device(&d_id)
            .map(|u| Buffer::from(u.to_vec())))
    }
}

// ==================== Sender Resolution ====================

#[napi(object)]
pub struct SenderInfo {
    pub signer_pubkey: Buffer,
    pub user_id: Buffer,
    pub device_id: Buffer,
    pub device_was_active: bool,
    pub human_label: Option<String>,
}

#[napi]
pub fn resolve_sender(
    header: HeaderObj,
    key_log: &KeyLog,
    sealed_gk: Option<Uint8Array>,
) -> Result<SenderInfo> {
    let core_header = napi_to_header(header)?;

    let mut core_sealed_gk = None;
    if let Some(gk) = sealed_gk {
        let gk_arr = to_arr32(gk.as_ref(), "sealed_gk")?;
        core_sealed_gk = Some(gk_arr);
    }

    match vollcrypt_files_core::resolve_sender(&core_header, &key_log.inner, core_sealed_gk.as_ref())
    {
        Ok(info) => Ok(SenderInfo {
            signer_pubkey: Buffer::from(info.signer_pubkey.to_vec()),
            user_id: Buffer::from(info.user_id.to_vec()),
            device_id: Buffer::from(info.device_id.to_vec()),
            device_was_active: info.device_was_active,
            human_label: info.human_label,
        }),
        Err(e) => Err(Error::from_reason(e.to_string())),
    }
}

// ==================== Pipelined File-Level Operations ====================

#[napi(object)]
pub struct PipelinedSignInfoObj {
    pub kind: String, // "Plain" | "Sealed"
    pub signer_ed25519_pk: Buffer,
    pub signer_ed25519_sk: Buffer,
    pub key_log_id: Buffer,
    pub timestamp: u32,
    pub sealed_group_id: Option<Buffer>,
    pub sealed_gk_version: Option<u32>,
    pub sealed_gk: Option<Buffer>,
}

fn napi_to_pipelined_sign_info(
    obj: PipelinedSignInfoObj,
) -> Result<vollcrypt_files_core::PipelinedSignInfo> {
    let signer_pk_arr = to_arr32(obj.signer_ed25519_pk.as_ref(), "signer_ed25519_pk")?;
    let signer_sk_arr = to_arr32(obj.signer_ed25519_sk.as_ref(), "signer_ed25519_sk")?;
    let key_log_id_arr = to_arr32(obj.key_log_id.as_ref(), "key_log_id")?;
    let timestamp = obj.timestamp as u64;

    match obj.kind.as_str() {
        "Plain" => Ok(vollcrypt_files_core::PipelinedSignInfo::Plain {
            signer_ed25519_pk: signer_pk_arr,
            signer_ed25519_sk: signer_sk_arr,
            key_log_id: key_log_id_arr,
            timestamp,
        }),
        "Sealed" => {
            let sealed_group_id_buf = obj
                .sealed_group_id
                .ok_or_else(|| Error::from_reason("Missing sealed_group_id for Sealed signature"))?;
            let sealed_group_id = to_arr16(sealed_group_id_buf.as_ref(), "sealed_group_id")?;

            let sealed_gk_version = obj.sealed_gk_version.ok_or_else(|| {
                Error::from_reason("Missing sealed_gk_version for Sealed signature")
            })?;

            let sealed_gk_buf = obj
                .sealed_gk
                .ok_or_else(|| Error::from_reason("Missing sealed_gk for Sealed signature"))?;
            let sealed_gk = to_arr32(sealed_gk_buf.as_ref(), "sealed_gk")?;

            Ok(vollcrypt_files_core::PipelinedSignInfo::Sealed {
                signer_ed25519_pk: signer_pk_arr,
                signer_ed25519_sk: signer_sk_arr,
                key_log_id: key_log_id_arr,
                timestamp,
                sealed_group_id,
                sealed_gk_version,
                sealed_gk,
            })
        }
        _ => Err(Error::from_reason(format!(
            "Unknown PipelinedSignInfo kind: {}",
            obj.kind
        ))),
    }
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct IoWriteModeObj {
    pub mode: String,
    pub batch_size: Option<u32>,
}

fn napi_to_io_write_mode(obj: IoWriteModeObj) -> Result<vollcrypt_files_core::IoWriteMode> {
    match obj.mode.as_str() {
        "Sequential" => Ok(vollcrypt_files_core::IoWriteMode::Sequential),
        "DirectOffset" => Ok(vollcrypt_files_core::IoWriteMode::DirectOffset),
        "Batched" => {
            let batch_size = obj.batch_size.unwrap_or(16) as usize;
            Ok(vollcrypt_files_core::IoWriteMode::Batched { batch_size })
        }
        _ => Err(Error::from_reason(format!("Unknown write mode: {}", obj.mode))),
    }
}

pub struct EncryptFilePipelinedTask {
    source_path: String,
    dest_path: String,
    dek: [u8; 32],
    file_id: [u8; 16],
    chunk_size: usize,
    wraps: Vec<vollcrypt_files_core::WrapEntry>,
    mode: vollcrypt_files_core::Mode,
    num_workers: usize,
    sign_info: Option<vollcrypt_files_core::PipelinedSignInfo>,
    write_mode: Option<vollcrypt_files_core::IoWriteMode>,
}

impl Task for EncryptFilePipelinedTask {
    type Output = vollcrypt_files_core::Header;
    type JsValue = HeaderObj;

    fn compute(&mut self) -> Result<Self::Output> {
        let source_file = std::fs::File::open(&self.source_path)
            .map_err(|e| Error::from_reason(format!("Failed to open source file: {}", e)))?;
        let dest_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.dest_path)
            .map_err(|e| {
                Error::from_reason(format!("Failed to open/create destination file: {}", e))
            })?;

        vollcrypt_files_core::encrypt_file_pipelined(
            source_file,
            dest_file,
            &self.dek,
            &self.file_id,
            self.chunk_size,
            self.wraps.clone(),
            self.mode,
            self.num_workers,
            self.sign_info.clone(),
            self.write_mode,
        )
        .map_err(|e| Error::from_reason(e.to_string()))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(header_to_napi(output))
    }
}

pub struct DecryptFilePipelinedTask {
    source_path: String,
    dest_path: String,
    dek: [u8; 32],
    num_workers: usize,
}

impl Task for DecryptFilePipelinedTask {
    type Output = vollcrypt_files_core::Header;
    type JsValue = HeaderObj;

    fn compute(&mut self) -> Result<Self::Output> {
        let source_file = std::fs::File::open(&self.source_path)
            .map_err(|e| Error::from_reason(format!("Failed to open source file: {}", e)))?;
        let dest_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.dest_path)
            .map_err(|e| {
                Error::from_reason(format!("Failed to open/create destination file: {}", e))
            })?;

        vollcrypt_files_core::decrypt_file_pipelined(
            source_file,
            dest_file,
            &self.dek,
            self.num_workers,
        )
        .map_err(|e| Error::from_reason(e.to_string()))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(header_to_napi(output))
    }
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_file_pipelined_async(
    source_path: String,
    dest_path: String,
    dek: Uint8Array,
    file_id: Uint8Array,
    chunk_size: u32,
    wraps: Vec<WrapEntry>,
    mode: u8,
    num_workers: u32,
    sign_info: Option<PipelinedSignInfoObj>,
    write_mode: Option<IoWriteModeObj>,
) -> Result<AsyncTask<EncryptFilePipelinedTask>> {
    let dek_arr = to_arr32(dek.as_ref(), "dek")?;
    let file_id_arr = to_arr16(file_id.as_ref(), "file_id")?;

    let mut core_wraps = Vec::with_capacity(wraps.len());
    for w in wraps {
        core_wraps.push(napi_to_wrap_entry(w)?);
    }

    let core_mode = vollcrypt_files_core::Mode::try_from(mode)
        .map_err(|_| Error::from_reason("Invalid mode value"))?;

    let core_sign_info = match sign_info {
        Some(s) => Some(napi_to_pipelined_sign_info(s)?),
        None => None,
    };

    let core_write_mode = match write_mode {
        Some(w) => Some(napi_to_io_write_mode(w)?),
        None => None,
    };

    let task = EncryptFilePipelinedTask {
        source_path,
        dest_path,
        dek: dek_arr,
        file_id: file_id_arr,
        chunk_size: chunk_size as usize,
        wraps: core_wraps,
        mode: core_mode,
        num_workers: num_workers as usize,
        sign_info: core_sign_info,
        write_mode: core_write_mode,
    };

    Ok(AsyncTask::new(task))
}

#[napi]
pub fn decrypt_file_pipelined_async(
    source_path: String,
    dest_path: String,
    dek: Uint8Array,
    num_workers: u32,
) -> Result<AsyncTask<DecryptFilePipelinedTask>> {
    let dek_arr = to_arr32(dek.as_ref(), "dek")?;

    let task = DecryptFilePipelinedTask {
        source_path,
        dest_path,
        dek: dek_arr,
        num_workers: num_workers as usize,
    };

    Ok(AsyncTask::new(task))
}

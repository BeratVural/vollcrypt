#![forbid(unsafe_code)]

use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;
use vollcrypt_shield_core::{
    EntryKind, IntegrityEntry, MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey,
    MlDsa65Signature, NormalizedPath, SignedSnapshot, Snapshot,
};

#[napi(object)]
pub struct NapiKeyPair {
    pub public_key: Buffer,
    pub secret_seed: Buffer,
}

#[napi(object)]
pub struct NapiIntegrityEntry {
    pub path: String,
    pub kind: String,
    pub content_digest: Buffer,
    pub metadata_digest: Buffer,
    pub size: i64,
}

#[napi(object)]
pub struct NapiSnapshotSummary {
    pub scope_id: String,
    pub root: Buffer,
    pub entry_count: u32,
    pub signer_key_id: Buffer,
}

#[napi(js_name = "shieldCoreVersion")]
pub fn shield_core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[napi(js_name = "generateKeyPair")]
pub fn generate_key_pair() -> Result<NapiKeyPair> {
    let pair = MlDsa65KeyPair::generate().map_err(napi_error)?;
    Ok(NapiKeyPair {
        public_key: pair.public.as_bytes().to_vec().into(),
        secret_seed: pair.secret.expose_seed().to_vec().into(),
    })
}

#[napi(js_name = "sign")]
pub fn sign(payload: Buffer, secret_seed: Buffer) -> Result<Buffer> {
    let secret = MlDsa65SecretKey::from_seed(secret_seed.as_ref()).map_err(napi_error)?;
    Ok(secret
        .sign(payload.as_ref())
        .map_err(napi_error)?
        .as_bytes()
        .to_vec()
        .into())
}

#[napi(js_name = "verify")]
pub fn verify(payload: Buffer, public_key: Buffer, signature: Buffer) -> Result<bool> {
    let public = MlDsa65PublicKey::from_bytes(public_key.as_ref()).map_err(napi_error)?;
    let signature = MlDsa65Signature::from_bytes(signature.as_ref()).map_err(napi_error)?;
    Ok(public.verify(payload.as_ref(), &signature).is_ok())
}

#[napi(js_name = "createSignedSnapshot")]
pub fn create_signed_snapshot(
    scope_id: String,
    entries: Vec<NapiIntegrityEntry>,
    created_at_unix_ms: i64,
    secret_seed: Buffer,
) -> Result<Buffer> {
    if created_at_unix_ms < 0 {
        return Err(Error::new(
            Status::InvalidArg,
            "createdAtUnixMs cannot be negative",
        ));
    }
    let entries = entries
        .into_iter()
        .map(convert_entry)
        .collect::<Result<Vec<_>>>()?;
    let snapshot =
        Snapshot::new(scope_id, entries, created_at_unix_ms as u64).map_err(napi_error)?;
    let secret = MlDsa65SecretKey::from_seed(secret_seed.as_ref()).map_err(napi_error)?;
    Ok(SignedSnapshot::sign(&snapshot, &secret)
        .and_then(|signed| signed.to_cbor())
        .map_err(napi_error)?
        .into())
}

#[napi(js_name = "verifySignedSnapshot")]
pub fn verify_signed_snapshot(encoded: Buffer) -> Result<NapiSnapshotSummary> {
    let signed = SignedSnapshot::from_cbor(encoded.as_ref()).map_err(napi_error)?;
    let signer_key_id = signed.public_key().map_err(napi_error)?.key_id();
    let snapshot = signed.verify().map_err(napi_error)?;
    Ok(NapiSnapshotSummary {
        scope_id: snapshot.scope_id,
        root: snapshot.root.to_vec().into(),
        entry_count: u32::try_from(snapshot.entries.len())
            .map_err(|_| Error::new(Status::GenericFailure, "entry count exceeds u32"))?,
        signer_key_id: signer_key_id.to_vec().into(),
    })
}

fn convert_entry(entry: NapiIntegrityEntry) -> Result<IntegrityEntry> {
    if entry.size < 0 {
        return Err(Error::new(
            Status::InvalidArg,
            "entry size cannot be negative",
        ));
    }
    let kind = match entry.kind.as_str() {
        "file" => EntryKind::File,
        "directory" => EntryKind::Directory,
        "symlink" => EntryKind::Symlink,
        _ => {
            return Err(Error::new(
                Status::InvalidArg,
                "entry kind must be file, directory, or symlink",
            ));
        }
    };
    let content_digest: [u8; 32] = entry
        .content_digest
        .as_ref()
        .try_into()
        .map_err(|_| Error::new(Status::InvalidArg, "contentDigest must be 32 bytes"))?;
    let metadata_digest: [u8; 32] = entry
        .metadata_digest
        .as_ref()
        .try_into()
        .map_err(|_| Error::new(Status::InvalidArg, "metadataDigest must be 32 bytes"))?;
    Ok(IntegrityEntry::new(
        NormalizedPath::new(entry.path).map_err(napi_error)?,
        kind,
        content_digest,
        metadata_digest,
        entry.size as u64,
    ))
}

fn napi_error(error: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, error.to_string())
}

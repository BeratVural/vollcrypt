use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use minicbor::{Decode, Encode};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{
    EntryKind, FORMAT_VERSION, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
    NormalizedPath, Snapshot,
};

use crate::config::ScopeConfig;
use crate::error::{AgentError, Result};
use crate::metadata::CapturedMetadata;
use crate::state::write_atomic;

const FILE_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-FILE-v1\0";
const VAULT_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Vault v1";
const QUARANTINE_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Quarantine v1";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct VaultEntry {
    #[n(0)]
    pub path: String,
    #[n(1)]
    pub kind: EntryKind,
    #[n(2)]
    pub content_digest: [u8; 32],
    #[n(3)]
    pub object_name: Option<String>,
    #[n(4)]
    pub symlink_target: Option<String>,
    #[n(5)]
    pub metadata: CapturedMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct VaultManifest {
    #[n(0)]
    version: u16,
    #[n(1)]
    scope_id: String,
    #[n(2)]
    snapshot_root: [u8; 32],
    #[n(3)]
    entries: Vec<VaultEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct SignedVaultManifest {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct QuarantineRecord {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub scope_id: String,
    #[n(2)]
    pub original_path: String,
    #[n(3)]
    pub quarantine_object: String,
    #[n(4)]
    pub observed_digest: [u8; 32],
    #[n(5)]
    pub baseline_digest: Option<[u8; 32]>,
    #[n(6)]
    pub metadata: CapturedMetadata,
    #[n(7)]
    pub quarantined_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct SignedQuarantineRecord {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

pub struct Vault {
    root: PathBuf,
}

impl Vault {
    pub fn new(state_dir: &Path) -> Result<Self> {
        let root = state_dir.join("vault");
        std::fs::create_dir_all(root.join("objects"))?;
        std::fs::create_dir_all(root.join("manifests"))?;
        std::fs::create_dir_all(root.join("quarantine"))?;
        Ok(Self { root })
    }

    pub fn capture_baseline(
        &self,
        scope: &ScopeConfig,
        snapshot: &Snapshot,
        secret: &MlDsa65SecretKey,
    ) -> Result<()> {
        snapshot.validate()?;
        if snapshot.scope_id != scope.id {
            return Err(AgentError::Config(
                "snapshot and vault scope ids differ".to_owned(),
            ));
        }
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for entry in &snapshot.entries {
            let source = scope.root.join(entry.path.as_str());
            let integrity_metadata = CapturedMetadata::capture(&source, &scope.metadata)?;
            if integrity_metadata.digest()? != entry.metadata_digest {
                return Err(AgentError::Scan(format!(
                    "metadata changed while capturing baseline: {}",
                    source.display()
                )));
            }
            let metadata = CapturedMetadata::capture_complete(&source)?;
            let (object_name, symlink_target) = match entry.kind {
                EntryKind::File => {
                    let object_name = hex::encode(entry.content_digest);
                    let destination = self.root.join("objects").join(&object_name);
                    if destination.exists() {
                        let (actual, _) = hash_regular_file(&destination)?;
                        if actual != entry.content_digest {
                            return Err(AgentError::Quarantine(format!(
                                "existing baseline object is corrupted: {object_name}"
                            )));
                        }
                    } else {
                        copy_regular_verified(&source, &destination, &entry.content_digest)?;
                    }
                    (Some(object_name), None)
                }
                EntryKind::Directory => (None, None),
                EntryKind::Symlink => {
                    let target = std::fs::read_link(&source)?;
                    let target = target.to_str().ok_or_else(|| {
                        AgentError::Scan(format!("non-UTF-8 symlink target: {}", source.display()))
                    })?;
                    (None, Some(target.to_owned()))
                }
            };
            entries.push(VaultEntry {
                path: entry.path.to_string(),
                kind: entry.kind,
                content_digest: entry.content_digest,
                object_name,
                symlink_target,
                metadata,
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = VaultManifest {
            version: FORMAT_VERSION,
            scope_id: scope.id.clone(),
            snapshot_root: snapshot.root,
            entries,
        };
        let payload = minicbor::to_vec(manifest)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        let public = secret.public_key()?;
        let signature = secret.sign_with_context(&payload, VAULT_SIGNATURE_CONTEXT)?;
        let signed = SignedVaultManifest {
            payload,
            public_key: public.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        };
        let encoded = minicbor::to_vec(signed)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        write_atomic(&self.manifest_path(&scope.id), &encoded)
    }

    pub fn load_manifest(
        &self,
        scope_id: &str,
        trusted_key: &MlDsa65PublicKey,
    ) -> Result<VaultManifest> {
        let encoded = std::fs::read(self.manifest_path(scope_id))?;
        let signed: SignedVaultManifest = decode_exact(&encoded)?;
        let embedded = MlDsa65PublicKey::from_bytes(&signed.public_key)?;
        if embedded.key_id() != trusted_key.key_id() {
            return Err(AgentError::Config(
                "vault signer does not match configured agent key".to_owned(),
            ));
        }
        let signature = MlDsa65Signature::from_bytes(&signed.signature)?;
        trusted_key.verify_with_context(&signed.payload, VAULT_SIGNATURE_CONTEXT, &signature)?;
        let manifest: VaultManifest = decode_exact(&signed.payload)?;
        if manifest.version != FORMAT_VERSION || manifest.scope_id != scope_id {
            return Err(AgentError::Config(
                "vault manifest version or scope mismatch".to_owned(),
            ));
        }
        Ok(manifest)
    }

    pub fn quarantine_regular_file(
        &self,
        scope: &ScopeConfig,
        path: &NormalizedPath,
        observed_digest: [u8; 32],
        baseline_digest: Option<[u8; 32]>,
        now_unix_ms: u64,
        secret: &MlDsa65SecretKey,
    ) -> Result<QuarantineRecord> {
        let source = scope.root.join(path.as_str());
        let file_type = std::fs::symlink_metadata(&source)?.file_type();
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(AgentError::UnsafeResponseTarget(format!(
                "active quarantine supports regular files only in Phase 2: {}",
                source.display()
            )));
        }
        let parent = source.parent().ok_or_else(|| {
            AgentError::UnsafeResponseTarget(format!(
                "quarantine target has no parent: {}",
                source.display()
            ))
        })?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| AgentError::Quarantine(error.to_string()))?;
        let name = format!(
            "{}-{}-{}",
            now_unix_ms,
            hex::encode(path.key_digest()),
            hex::encode(nonce)
        );
        let staged = parent.join(format!(".vollcrypt-shield-quarantine-{name}"));
        if staged.exists() || std::fs::symlink_metadata(&staged).is_ok() {
            return Err(AgentError::Quarantine(
                "random quarantine staging path already exists".to_owned(),
            ));
        }
        std::fs::rename(&source, &staged)?;

        let result = (|| -> Result<QuarantineRecord> {
            let staged_type = std::fs::symlink_metadata(&staged)?.file_type();
            if !staged_type.is_file() || staged_type.is_symlink() {
                return Err(AgentError::UnsafeResponseTarget(format!(
                    "atomically staged quarantine target is not a regular file: {}",
                    staged.display()
                )));
            }
            let metadata = CapturedMetadata::capture_complete(&staged)?;
            let directory = self.root.join("quarantine").join(&scope.id);
            std::fs::create_dir_all(&directory)?;
            let object = directory.join(format!("{name}.object"));
            copy_regular_verified(&staged, &object, &observed_digest)?;

            let record = QuarantineRecord {
                version: FORMAT_VERSION,
                scope_id: scope.id.clone(),
                original_path: path.to_string(),
                quarantine_object: object.to_string_lossy().into_owned(),
                observed_digest,
                baseline_digest,
                metadata,
                quarantined_at_unix_ms: now_unix_ms,
            };
            let payload = minicbor::to_vec(&record)
                .map_err(|error| AgentError::Serialization(error.to_string()))?;
            let public = secret.public_key()?;
            let signature = secret.sign_with_context(&payload, QUARANTINE_SIGNATURE_CONTEXT)?;
            let signed = SignedQuarantineRecord {
                payload,
                public_key: public.as_bytes().to_vec(),
                signature: signature.as_bytes().to_vec(),
            };
            let encoded = minicbor::to_vec(signed)
                .map_err(|error| AgentError::Serialization(error.to_string()))?;
            write_atomic(&directory.join(format!("{name}.manifest.cbor")), &encoded)?;
            Ok(record)
        })();

        match result {
            Ok(record) => match std::fs::remove_file(&staged) {
                Ok(()) => Ok(record),
                Err(error) => {
                    restore_staged_source(&staged, &source);
                    Err(error.into())
                }
            },
            Err(error) => {
                restore_staged_source(&staged, &source);
                Err(error)
            }
        }
    }

    pub fn restore_regular_file(
        &self,
        scope: &ScopeConfig,
        path: &NormalizedPath,
        trusted_key: &MlDsa65PublicKey,
    ) -> Result<()> {
        let manifest = self.load_manifest(&scope.id, trusted_key)?;
        let entry = manifest
            .entries
            .iter()
            .find(|entry| entry.path == path.as_str())
            .ok_or_else(|| {
                AgentError::Quarantine(format!("path is absent from baseline vault: {path}"))
            })?;
        if entry.kind != EntryKind::File {
            return Err(AgentError::UnsafeResponseTarget(format!(
                "active rollback supports regular files only in Phase 2: {path}"
            )));
        }
        let object_name = entry.object_name.as_ref().ok_or_else(|| {
            AgentError::Quarantine(format!("baseline object is absent for {path}"))
        })?;
        let source = self.root.join("objects").join(object_name);
        let destination = scope.root.join(path.as_str());
        if destination.exists() || std::fs::symlink_metadata(&destination).is_ok() {
            return Err(AgentError::Quarantine(format!(
                "rollback destination still exists: {}",
                destination.display()
            )));
        }
        let parent = destination.parent().ok_or_else(|| {
            AgentError::Quarantine(format!("rollback path has no parent: {path}"))
        })?;
        if !parent.is_dir() {
            return Err(AgentError::Quarantine(format!(
                "rollback parent is absent: {}",
                parent.display()
            )));
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| AgentError::Quarantine(error.to_string()))?;
        let temporary = parent.join(format!(
            ".vollcrypt-shield-restore-{}-{}",
            hex::encode(path.key_digest()),
            hex::encode(nonce)
        ));
        let result = (|| -> Result<()> {
            let mut input = File::open(&source)?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            std::io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            let (actual, _) = hash_regular_file(&temporary)?;
            if actual != entry.content_digest {
                return Err(AgentError::Quarantine(
                    "rollback object failed digest verification".to_owned(),
                ));
            }
            entry.metadata.restore(&temporary)?;
            OpenOptions::new()
                .write(true)
                .open(&temporary)?
                .sync_all()?;
            // Creating the destination as a hard link is atomic and fails
            // instead of replacing a path created by a racing process.
            std::fs::hard_link(&temporary, &destination)?;
            std::fs::remove_file(&temporary)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    pub fn verify_quarantine_records(
        &self,
        scope_id: &str,
        trusted_key: &MlDsa65PublicKey,
    ) -> Result<Vec<QuarantineRecord>> {
        let directory = self.root.join("quarantine").join(scope_id);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut manifests = Vec::new();
        for item in std::fs::read_dir(&directory)? {
            let path = item?.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".manifest.cbor"))
            {
                manifests.push(path);
            }
        }
        manifests.sort();

        let mut records = Vec::with_capacity(manifests.len());
        for path in manifests {
            let signed: SignedQuarantineRecord = decode_exact(&std::fs::read(path)?)?;
            let embedded = MlDsa65PublicKey::from_bytes(&signed.public_key)?;
            if embedded.key_id() != trusted_key.key_id() {
                return Err(AgentError::Config(
                    "quarantine signer does not match configured agent key".to_owned(),
                ));
            }
            let signature = MlDsa65Signature::from_bytes(&signed.signature)?;
            trusted_key.verify_with_context(
                &signed.payload,
                QUARANTINE_SIGNATURE_CONTEXT,
                &signature,
            )?;
            let record: QuarantineRecord = decode_exact(&signed.payload)?;
            let object = PathBuf::from(&record.quarantine_object);
            if record.version != FORMAT_VERSION
                || record.scope_id != scope_id
                || !object.starts_with(&directory)
                || !object.is_file()
            {
                return Err(AgentError::Quarantine(
                    "quarantine record version, scope, or object path is invalid".to_owned(),
                ));
            }
            records.push(record);
        }
        Ok(records)
    }

    fn manifest_path(&self, scope_id: &str) -> PathBuf {
        self.root
            .join("manifests")
            .join(format!("{scope_id}.vault.cbor"))
    }
}

fn copy_regular_verified(source: &Path, destination: &Path, expected: &[u8; 32]) -> Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension("tmp");
    {
        let mut input = File::open(source)?;
        let mut output = File::create(&temporary)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
    }
    let (actual, _) = hash_regular_file(&temporary)?;
    if actual != *expected {
        let _ = std::fs::remove_file(&temporary);
        return Err(AgentError::Quarantine(
            "vault object digest does not match baseline".to_owned(),
        ));
    }
    std::fs::rename(&temporary, destination)?;
    Ok(())
}

fn restore_staged_source(staged: &Path, source: &Path) {
    if std::fs::symlink_metadata(staged).is_ok()
        && !source.exists()
        && std::fs::symlink_metadata(source).is_err()
    {
        let _ = std::fs::rename(staged, source);
    }
}

fn hash_regular_file(path: &Path) -> Result<([u8; 32], u64)> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    hasher.update(FILE_DOMAIN);
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok((hasher.finalize().into(), metadata.len()))
}

fn decode_exact<'a, T>(bytes: &'a [u8]) -> Result<T>
where
    T: Decode<'a, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
        .map_err(|error| AgentError::Serialization(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(AgentError::Serialization(
            "trailing bytes after vault record".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::{MetadataPolicy, MlDsa65KeyPair, ResponsePolicy, ScanProfile};

    #[test]
    fn failed_quarantine_restores_atomically_staged_source() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("scope");
        let state = directory.path().join("state");
        std::fs::create_dir(&root).unwrap();
        let source = root.join("app.conf");
        std::fs::write(&source, b"approved").unwrap();
        let scope = ScopeConfig {
            id: "scope".to_owned(),
            root: root.clone(),
            include: vec!["**".to_owned()],
            exclude: Vec::new(),
            metadata: MetadataPolicy::default(),
            full_scan: ScanProfile::full_default(),
            incremental_scan: ScanProfile::incremental_default(),
            full_rescan_interval_secs: 300,
            response: ResponsePolicy::default(),
        };
        let vault = Vault::new(&state).unwrap();
        let pair = MlDsa65KeyPair::generate().unwrap();
        let result = vault.quarantine_regular_file(
            &scope,
            &NormalizedPath::new("app.conf").unwrap(),
            [7; 32],
            None,
            1,
            &pair.secret,
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"approved");
        assert!(std::fs::read_dir(root).unwrap().all(|item| {
            !item
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".vollcrypt-shield-quarantine-")
        }));
    }
}

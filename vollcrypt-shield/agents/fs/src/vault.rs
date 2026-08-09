use std::fs::File;
#[cfg(not(windows))]
use std::fs::OpenOptions;
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
#[cfg(windows)]
const WINDOWS_BACKUP_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-WINDOWS-BACKUP-v1\0";
#[cfg(windows)]
const WINDOWS_VAULT_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Windows Vault v1";
#[cfg(windows)]
const WINDOWS_QUARANTINE_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Windows Quarantine v1";

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

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct WindowsBasicMetadata {
    #[n(0)]
    creation_time: i64,
    #[n(1)]
    last_access_time: i64,
    #[n(2)]
    last_write_time: i64,
    #[n(3)]
    change_time: i64,
    #[n(4)]
    attributes: u32,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct WindowsVaultEntry {
    #[n(0)]
    path: String,
    #[n(1)]
    backup_digest: [u8; 32],
    #[n(2)]
    object_name: String,
    #[n(3)]
    metadata: WindowsBasicMetadata,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct WindowsVaultManifest {
    #[n(0)]
    version: u16,
    #[n(1)]
    scope_id: String,
    #[n(2)]
    snapshot_root: [u8; 32],
    #[n(3)]
    entries: Vec<WindowsVaultEntry>,
    #[n(4)]
    complete: bool,
    #[n(5)]
    failure: Option<String>,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct WindowsQuarantineRecord {
    #[n(0)]
    version: u16,
    #[n(1)]
    scope_id: String,
    #[n(2)]
    original_path: String,
    #[n(3)]
    backup_digest: [u8; 32],
    #[n(4)]
    backup_object: String,
    #[n(5)]
    observed_digest: [u8; 32],
    #[n(6)]
    metadata: WindowsBasicMetadata,
    #[n(7)]
    quarantined_at_unix_ms: u64,
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
        #[cfg(windows)]
        std::fs::create_dir_all(root.join("windows").join("objects"))?;
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
        #[cfg(windows)]
        if let Err(error) = self.capture_windows_baseline(scope, snapshot, secret) {
            self.write_windows_incomplete_baseline(scope, snapshot, secret, &error.to_string())?;
        }
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

    #[cfg(windows)]
    fn capture_windows_baseline(
        &self,
        scope: &ScopeConfig,
        snapshot: &Snapshot,
        secret: &MlDsa65SecretKey,
    ) -> Result<()> {
        let mut entries = Vec::new();
        for entry in snapshot
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
        {
            let source = scope.root.join(entry.path.as_str());
            let (object_name, backup_digest, metadata) = self.capture_windows_backup(&source)?;
            let (current_digest, _) = hash_regular_file(&source)?;
            if current_digest != entry.content_digest {
                return Err(AgentError::Scan(format!(
                    "file changed while capturing Windows baseline: {}",
                    source.display()
                )));
            }
            entries.push(WindowsVaultEntry {
                path: entry.path.to_string(),
                backup_digest,
                object_name,
                metadata: metadata.into(),
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = WindowsVaultManifest {
            version: FORMAT_VERSION,
            scope_id: scope.id.clone(),
            snapshot_root: snapshot.root,
            entries,
            complete: true,
            failure: None,
        };
        let encoded = sign_record(&manifest, secret, WINDOWS_VAULT_SIGNATURE_CONTEXT)?;
        write_atomic(&self.windows_manifest_path(&scope.id), &encoded)
    }

    #[cfg(windows)]
    fn write_windows_incomplete_baseline(
        &self,
        scope: &ScopeConfig,
        snapshot: &Snapshot,
        secret: &MlDsa65SecretKey,
        failure: &str,
    ) -> Result<()> {
        let manifest = WindowsVaultManifest {
            version: FORMAT_VERSION,
            scope_id: scope.id.clone(),
            snapshot_root: snapshot.root,
            entries: Vec::new(),
            complete: false,
            failure: Some(failure.chars().take(1024).collect()),
        };
        write_atomic(
            &self.windows_manifest_path(&scope.id),
            &sign_record(&manifest, secret, WINDOWS_VAULT_SIGNATURE_CONTEXT)?,
        )
    }

    #[cfg(windows)]
    fn load_windows_manifest(
        &self,
        scope_id: &str,
        snapshot_root: [u8; 32],
        trusted_key: &MlDsa65PublicKey,
    ) -> Result<WindowsVaultManifest> {
        let manifest: WindowsVaultManifest = verify_signed_record(
            &std::fs::read(self.windows_manifest_path(scope_id))?,
            trusted_key,
            WINDOWS_VAULT_SIGNATURE_CONTEXT,
        )?;
        if manifest.version != FORMAT_VERSION
            || manifest.scope_id != scope_id
            || manifest.snapshot_root != snapshot_root
        {
            return Err(AgentError::Config(
                "Windows vault manifest version, scope, or root mismatch".to_owned(),
            ));
        }
        Ok(manifest)
    }

    #[cfg(windows)]
    fn capture_windows_backup(
        &self,
        source: &Path,
    ) -> Result<(
        String,
        [u8; 32],
        vollcrypt_shield_windows::FileBasicMetadata,
    )> {
        let directory = self.root.join("windows").join("objects");
        std::fs::create_dir_all(&directory)?;
        let temporary = directory.join(format!(".{}.tmp", random_hex()?));
        let result = (|| {
            let metadata = vollcrypt_shield_windows::capture_file(source, &temporary)?;
            let backup_digest = hash_backup_file(&temporary)?;
            let object_name = format!("{}.backup", hex::encode(backup_digest));
            let destination = directory.join(&object_name);
            if destination.exists() {
                if hash_backup_file(&destination)? != backup_digest {
                    return Err(AgentError::Quarantine(
                        "existing Windows backup object is corrupted".to_owned(),
                    ));
                }
                std::fs::remove_file(&temporary)?;
            } else {
                std::fs::rename(&temporary, &destination)?;
            }
            Ok((object_name, backup_digest, metadata))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    #[cfg(windows)]
    pub fn validate_windows_active_response(
        &self,
        scope: &ScopeConfig,
        trusted_key: &MlDsa65PublicKey,
    ) -> Result<()> {
        if scope.protects_system_path() {
            return Err(AgentError::UnsafeResponseTarget(format!(
                "protected Windows system root remains passive: {}",
                scope.root.display()
            )));
        }
        let windows = self.load_complete_windows_baseline(scope, trusted_key)?;
        for entry in &windows.entries {
            let object = self
                .root
                .join("windows")
                .join("objects")
                .join(&entry.object_name);
            if !object.is_file() || hash_backup_file(&object)? != entry.backup_digest {
                return Err(AgentError::Quarantine(format!(
                    "Windows baseline backup is absent or corrupted: {}",
                    entry.path
                )));
            }
        }
        vollcrypt_shield_windows::validate_active_response_capability(&scope.root)?;
        Ok(())
    }

    #[cfg(windows)]
    pub fn validate_windows_runtime_response(
        &self,
        scope: &ScopeConfig,
        trusted_key: &MlDsa65PublicKey,
    ) -> Result<()> {
        self.load_complete_windows_baseline(scope, trusted_key)?;
        vollcrypt_shield_windows::validate_required_privileges()?;
        Ok(())
    }

    #[cfg(windows)]
    fn load_complete_windows_baseline(
        &self,
        scope: &ScopeConfig,
        trusted_key: &MlDsa65PublicKey,
    ) -> Result<WindowsVaultManifest> {
        let baseline = self.load_manifest(&scope.id, trusted_key)?;
        let windows = self.load_windows_manifest(&scope.id, baseline.snapshot_root, trusted_key)?;
        if !windows.complete {
            return Err(AgentError::Config(format!(
                "Windows active response baseline is incomplete; create a new baseline from a Shield service account with SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege: {}",
                windows
                    .failure
                    .as_deref()
                    .unwrap_or("capability validation did not complete")
            )));
        }
        let expected_files: std::collections::BTreeSet<_> = baseline
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
            .map(|entry| entry.path.as_str())
            .collect();
        let actual_files: std::collections::BTreeSet<_> = windows
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        if actual_files.len() != windows.entries.len()
            || actual_files != expected_files
            || windows
                .entries
                .iter()
                .any(|entry| !is_single_normal_component(Path::new(&entry.object_name)))
        {
            return Err(AgentError::Config(
                "Windows vault coverage or backup object name is invalid".to_owned(),
            ));
        }
        Ok(windows)
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
        let directory = self.root.join("quarantine").join(&scope.id);
        let object = directory.join(format!("{name}.object"));
        let manifest_path = directory.join(format!("{name}.manifest.cbor"));
        #[cfg(windows)]
        let windows_backup = directory.join(format!("{name}.windows.backup"));
        #[cfg(windows)]
        let windows_manifest = directory.join(format!("{name}.windows.cbor"));
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
            std::fs::create_dir_all(&directory)?;
            copy_regular_verified(&staged, &object, &observed_digest)?;

            #[cfg(windows)]
            {
                let windows_metadata =
                    vollcrypt_shield_windows::capture_file(&staged, &windows_backup)?;
                let windows_record = WindowsQuarantineRecord {
                    version: FORMAT_VERSION,
                    scope_id: scope.id.clone(),
                    original_path: path.to_string(),
                    backup_digest: hash_backup_file(&windows_backup)?,
                    backup_object: windows_backup
                        .file_name()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| {
                            AgentError::Quarantine(
                                "Windows quarantine backup name is not UTF-8".to_owned(),
                            )
                        })?
                        .to_owned(),
                    observed_digest,
                    metadata: windows_metadata.into(),
                    quarantined_at_unix_ms: now_unix_ms,
                };
                write_atomic(
                    &windows_manifest,
                    &sign_record(
                        &windows_record,
                        secret,
                        WINDOWS_QUARANTINE_SIGNATURE_CONTEXT,
                    )?,
                )?;
            }

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
            write_atomic(&manifest_path, &encoded)?;
            Ok(record)
        })();

        match result {
            Ok(record) => match std::fs::remove_file(&staged) {
                Ok(()) => Ok(record),
                Err(error) => {
                    restore_staged_source(&staged, &source);
                    cleanup_quarantine_artifacts(&object, &manifest_path);
                    #[cfg(windows)]
                    cleanup_quarantine_artifacts(&windows_backup, &windows_manifest);
                    Err(error.into())
                }
            },
            Err(error) => {
                restore_staged_source(&staged, &source);
                cleanup_quarantine_artifacts(&object, &manifest_path);
                #[cfg(windows)]
                cleanup_quarantine_artifacts(&windows_backup, &windows_manifest);
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
        #[cfg(windows)]
        let windows_entry = {
            let windows =
                self.load_windows_manifest(&scope.id, manifest.snapshot_root, trusted_key)?;
            windows
                .entries
                .into_iter()
                .find(|candidate| candidate.path == path.as_str())
                .ok_or_else(|| {
                    AgentError::Quarantine(format!(
                        "path is absent from Windows baseline vault: {path}"
                    ))
                })?
        };
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
            #[cfg(not(windows))]
            {
                let mut input = File::open(&source)?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                std::io::copy(&mut input, &mut output)?;
                output.sync_all()?;
            }
            #[cfg(windows)]
            {
                let (plain_digest, _) = hash_regular_file(&source)?;
                if plain_digest != entry.content_digest {
                    return Err(AgentError::Quarantine(
                        "baseline content object failed digest verification".to_owned(),
                    ));
                }
                let backup = self
                    .root
                    .join("windows")
                    .join("objects")
                    .join(&windows_entry.object_name);
                if hash_backup_file(&backup)? != windows_entry.backup_digest {
                    return Err(AgentError::Quarantine(
                        "Windows rollback object failed digest verification".to_owned(),
                    ));
                }
                vollcrypt_shield_windows::restore_file(
                    &backup,
                    &temporary,
                    windows_entry.metadata.into(),
                )?;
            }
            #[cfg(not(windows))]
            let actual = hash_regular_file(&temporary)?.0;
            #[cfg(windows)]
            let actual = vollcrypt_shield_windows::hash_default_stream(&temporary, FILE_DOMAIN)?;
            if actual != entry.content_digest {
                return Err(AgentError::Quarantine(
                    "rollback object failed digest verification".to_owned(),
                ));
            }
            #[cfg(not(windows))]
            entry.metadata.restore(&temporary)?;
            #[cfg(not(windows))]
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
            let signed: SignedQuarantineRecord = decode_exact(&std::fs::read(&path)?)?;
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
            #[cfg(windows)]
            {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .and_then(|value| value.strip_suffix(".manifest.cbor"))
                    .ok_or_else(|| {
                        AgentError::Quarantine(
                            "invalid Windows quarantine manifest name".to_owned(),
                        )
                    })?;
                let windows: WindowsQuarantineRecord = verify_signed_record(
                    &std::fs::read(directory.join(format!("{name}.windows.cbor")))?,
                    trusted_key,
                    WINDOWS_QUARANTINE_SIGNATURE_CONTEXT,
                )?;
                let relative = Path::new(&windows.backup_object);
                let backup = directory.join(relative);
                if windows.version != FORMAT_VERSION
                    || windows.scope_id != scope_id
                    || windows.original_path != record.original_path
                    || windows.observed_digest != record.observed_digest
                    || windows.quarantined_at_unix_ms != record.quarantined_at_unix_ms
                    || !is_single_normal_component(relative)
                    || !backup.is_file()
                    || hash_backup_file(&backup)? != windows.backup_digest
                {
                    return Err(AgentError::Quarantine(
                        "Windows quarantine sidecar is invalid or corrupted".to_owned(),
                    ));
                }
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

    #[cfg(windows)]
    fn windows_manifest_path(&self, scope_id: &str) -> PathBuf {
        self.root
            .join("manifests")
            .join(format!("{scope_id}.windows-vault.cbor"))
    }
}

#[cfg(windows)]
fn sign_record<T: Encode<()>>(
    record: &T,
    secret: &MlDsa65SecretKey,
    context: &[u8],
) -> Result<Vec<u8>> {
    let payload =
        minicbor::to_vec(record).map_err(|error| AgentError::Serialization(error.to_string()))?;
    let signed = SignedVaultManifest {
        signature: secret
            .sign_with_context(&payload, context)?
            .as_bytes()
            .to_vec(),
        public_key: secret.public_key()?.as_bytes().to_vec(),
        payload,
    };
    minicbor::to_vec(signed).map_err(|error| AgentError::Serialization(error.to_string()))
}

#[cfg(windows)]
fn verify_signed_record<T>(
    encoded: &[u8],
    trusted_key: &MlDsa65PublicKey,
    context: &[u8],
) -> Result<T>
where
    for<'a> T: Decode<'a, ()>,
{
    let signed: SignedVaultManifest = decode_exact(encoded)?;
    let embedded = MlDsa65PublicKey::from_bytes(&signed.public_key)?;
    if embedded.key_id() != trusted_key.key_id() {
        return Err(AgentError::Config(
            "Windows vault signer does not match configured agent key".to_owned(),
        ));
    }
    trusted_key.verify_with_context(
        &signed.payload,
        context,
        &MlDsa65Signature::from_bytes(&signed.signature)?,
    )?;
    decode_exact(&signed.payload)
}

#[cfg(windows)]
fn hash_backup_file(path: &Path) -> Result<[u8; 32]> {
    let mut input = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    hasher.update(WINDOWS_BACKUP_DOMAIN);
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(windows)]
fn random_hex() -> Result<String> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| AgentError::Quarantine(error.to_string()))?;
    Ok(hex::encode(nonce))
}

#[cfg(windows)]
fn is_single_normal_component(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

#[cfg(windows)]
impl From<vollcrypt_shield_windows::FileBasicMetadata> for WindowsBasicMetadata {
    fn from(value: vollcrypt_shield_windows::FileBasicMetadata) -> Self {
        Self {
            creation_time: value.creation_time,
            last_access_time: value.last_access_time,
            last_write_time: value.last_write_time,
            change_time: value.change_time,
            attributes: value.attributes,
        }
    }
}

#[cfg(windows)]
impl From<WindowsBasicMetadata> for vollcrypt_shield_windows::FileBasicMetadata {
    fn from(value: WindowsBasicMetadata) -> Self {
        Self {
            creation_time: value.creation_time,
            last_access_time: value.last_access_time,
            last_write_time: value.last_write_time,
            change_time: value.change_time,
            attributes: value.attributes,
        }
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

fn cleanup_quarantine_artifacts(object: &Path, manifest: &Path) {
    let _ = std::fs::remove_file(object);
    let _ = std::fs::remove_file(manifest);
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

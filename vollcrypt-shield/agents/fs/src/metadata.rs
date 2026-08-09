use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use filetime::FileTime;
use minicbor::{Decode, Encode};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::MetadataPolicy;

use crate::error::{AgentError, Result};

const METADATA_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-METADATA-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct ExtendedAttribute {
    #[n(0)]
    pub name: Vec<u8>,
    #[n(1)]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct CapturedMetadata {
    #[n(0)]
    pub mode: Option<u32>,
    #[n(1)]
    pub uid: Option<u32>,
    #[n(2)]
    pub gid: Option<u32>,
    #[n(3)]
    pub accessed_unix_ns: Option<u64>,
    #[n(4)]
    pub modified_unix_ns: Option<u64>,
    #[n(5)]
    pub extended_attributes: Vec<ExtendedAttribute>,
}

impl CapturedMetadata {
    pub fn capture(path: &Path, policy: &MetadataPolicy) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;

        #[cfg(unix)]
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (
                policy.permissions.then(|| metadata.mode()),
                policy.ownership.then(|| metadata.uid()),
                policy.ownership.then(|| metadata.gid()),
            )
        };
        #[cfg(not(unix))]
        let (mode, uid, gid) = (None, None, None);

        let (accessed_unix_ns, modified_unix_ns) = if policy.modified_time {
            (
                metadata.accessed().ok().and_then(system_time_ns),
                metadata.modified().ok().and_then(system_time_ns),
            )
        } else {
            (None, None)
        };

        let extended_attributes = if policy.extended_attributes {
            capture_xattrs(path)?
        } else {
            Vec::new()
        };

        Ok(Self {
            mode,
            uid,
            gid,
            accessed_unix_ns,
            modified_unix_ns,
            extended_attributes,
        })
    }

    pub fn capture_complete(path: &Path) -> Result<Self> {
        Self::capture(
            path,
            &MetadataPolicy {
                permissions: true,
                ownership: true,
                modified_time: true,
                extended_attributes: true,
            },
        )
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        // Access time is retained for reversible quarantine, but reading a file
        // can change it. Binding atime into the integrity root would make a
        // verification scan invalidate its own baseline.
        let mut integrity_metadata = self.clone();
        integrity_metadata.accessed_unix_ns = None;
        let encoded = minicbor::to_vec(integrity_metadata)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(METADATA_DOMAIN);
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }

    pub fn restore(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use nix::unistd::{Gid, Uid, chown};
            use std::os::unix::fs::PermissionsExt;

            if let Some(mode) = self.mode {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
            }
            if self.uid.is_some() || self.gid.is_some() {
                chown(
                    path,
                    self.uid.map(Uid::from_raw),
                    self.gid.map(Gid::from_raw),
                )
                .map_err(|error| AgentError::Quarantine(error.to_string()))?;
            }
            restore_xattrs(path, &self.extended_attributes)?;
        }

        if self.accessed_unix_ns.is_some() || self.modified_unix_ns.is_some() {
            let metadata = std::fs::metadata(path)?;
            let accessed = self
                .accessed_unix_ns
                .map(file_time_from_ns)
                .unwrap_or_else(|| FileTime::from_last_access_time(&metadata));
            let modified = self
                .modified_unix_ns
                .map(file_time_from_ns)
                .unwrap_or_else(|| FileTime::from_last_modification_time(&metadata));
            filetime::set_file_times(path, accessed, modified)?;
        }
        Ok(())
    }
}

fn system_time_ns(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
}

fn file_time_from_ns(value: u64) -> FileTime {
    FileTime::from_unix_time(
        (value / 1_000_000_000) as i64,
        (value % 1_000_000_000) as u32,
    )
}

#[cfg(unix)]
fn capture_xattrs(path: &Path) -> Result<Vec<ExtendedAttribute>> {
    use std::os::unix::ffi::OsStrExt;

    let mut attributes = Vec::new();
    for name in xattr::list(path).map_err(|error| AgentError::Quarantine(error.to_string()))? {
        let value = xattr::get(path, &name)
            .map_err(|error| AgentError::Quarantine(error.to_string()))?
            .unwrap_or_default();
        attributes.push(ExtendedAttribute {
            name: name.as_bytes().to_vec(),
            value,
        });
    }
    attributes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(attributes)
}

#[cfg(not(unix))]
fn capture_xattrs(_path: &Path) -> Result<Vec<ExtendedAttribute>> {
    Ok(Vec::new())
}

#[cfg(unix)]
fn restore_xattrs(path: &Path, attributes: &[ExtendedAttribute]) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    for attribute in attributes {
        xattr::set(path, OsStr::from_bytes(&attribute.name), &attribute.value)
            .map_err(|error| AgentError::Quarantine(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn metadata_digest_changes_with_permissions_when_supported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"data")
            .unwrap();
        let policy = MetadataPolicy::default();
        let first = CapturedMetadata::capture(&path, &policy)
            .unwrap()
            .digest()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let second = CapturedMetadata::capture(&path, &policy)
                .unwrap()
                .digest()
                .unwrap();
            assert_ne!(first, second);
        }
        #[cfg(not(unix))]
        assert_ne!(first, [0; 32]);
    }

    #[test]
    fn complete_capture_is_independent_from_integrity_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"data").unwrap();
        let policy = MetadataPolicy {
            permissions: false,
            ownership: false,
            modified_time: false,
            extended_attributes: false,
        };
        let policy_capture = CapturedMetadata::capture(&path, &policy).unwrap();
        let complete = CapturedMetadata::capture_complete(&path).unwrap();
        assert!(policy_capture.modified_unix_ns.is_none());
        assert!(complete.modified_unix_ns.is_some());
        #[cfg(unix)]
        {
            assert!(policy_capture.mode.is_none());
            assert!(complete.mode.is_some());
            assert!(complete.uid.is_some());
            assert!(complete.gid.is_some());
        }
    }
}

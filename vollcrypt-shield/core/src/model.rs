use std::fmt;

use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, ShieldError};

const PATH_KEY_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-PATH-v1\0";
const LEAF_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-LEAF-v1\0";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Encode, Decode,
)]
#[cbor(index_only)]
#[repr(u8)]
pub enum EntryKind {
    #[n(1)]
    File = 1,
    #[n(2)]
    Directory = 2,
    #[n(3)]
    Symlink = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Encode, Decode)]
#[cbor(array)]
pub struct NormalizedPath {
    #[n(0)]
    value: String,
}

impl NormalizedPath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_path(&value)?;
        Ok(Self { value })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn into_string(self) -> String {
        self.value
    }

    pub fn key_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PATH_KEY_DOMAIN);
        hasher.update((self.value.len() as u64).to_be_bytes());
        hasher.update(self.value.as_bytes());
        hasher.finalize().into()
    }
}

impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

fn validate_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\0')
        || value.contains('\\')
    {
        return Err(ShieldError::InvalidPath(value.to_owned()));
    }
    if value.len() >= 2 && value.as_bytes()[1] == b':' {
        return Err(ShieldError::InvalidPath(value.to_owned()));
    }
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ShieldError::InvalidPath(value.to_owned()));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(array)]
pub struct MetadataPolicy {
    #[n(0)]
    pub permissions: bool,
    #[n(1)]
    pub ownership: bool,
    #[n(2)]
    pub modified_time: bool,
    #[n(3)]
    pub extended_attributes: bool,
}

impl Default for MetadataPolicy {
    fn default() -> Self {
        Self {
            permissions: true,
            ownership: true,
            modified_time: false,
            extended_attributes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(array)]
pub struct IntegrityEntry {
    #[n(0)]
    pub path: NormalizedPath,
    #[n(1)]
    pub kind: EntryKind,
    #[n(2)]
    pub content_digest: [u8; 32],
    #[n(3)]
    pub metadata_digest: [u8; 32],
    #[n(4)]
    pub size: u64,
}

impl IntegrityEntry {
    pub fn new(
        path: NormalizedPath,
        kind: EntryKind,
        content_digest: [u8; 32],
        metadata_digest: [u8; 32],
        size: u64,
    ) -> Self {
        Self {
            path,
            kind,
            content_digest,
            metadata_digest,
            size,
        }
    }

    pub fn key_digest(&self) -> [u8; 32] {
        self.path.key_digest()
    }

    pub fn leaf_digest(&self) -> [u8; 32] {
        let path = self.path.as_str().as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(LEAF_DOMAIN);
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path);
        hasher.update([self.kind as u8]);
        hasher.update(self.content_digest);
        hasher.update(self.metadata_digest);
        hasher.update(self.size.to_be_bytes());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_relative_paths() {
        assert_eq!(
            NormalizedPath::new("config/app.toml").unwrap().as_str(),
            "config/app.toml"
        );
    }

    #[test]
    fn rejects_ambiguous_or_escaping_paths() {
        for value in [
            "",
            "/etc/passwd",
            "../secret",
            "a//b",
            "a/./b",
            "C:/temp",
            "a\\b",
        ] {
            assert!(NormalizedPath::new(value).is_err(), "{value}");
        }
    }

    #[test]
    fn path_and_leaf_domains_are_bound() {
        let path = NormalizedPath::new("a").unwrap();
        let entry = IntegrityEntry::new(path.clone(), EntryKind::File, [1; 32], [2; 32], 3);
        assert_ne!(path.key_digest(), entry.leaf_digest());
    }
}

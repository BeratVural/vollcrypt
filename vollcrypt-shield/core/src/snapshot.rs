use std::collections::BTreeSet;

use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::algorithm::{FORMAT_VERSION, HashAlgorithm, SignatureAlgorithm};
use crate::crypto::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
use crate::error::{Result, ShieldError};
use crate::merkle::SparseMerkleTree;
use crate::model::IntegrityEntry;

const SNAPSHOT_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Snapshot v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(array)]
pub struct Snapshot {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub hash_algorithm: HashAlgorithm,
    #[n(2)]
    pub signature_algorithm: SignatureAlgorithm,
    #[n(3)]
    pub scope_id: String,
    #[n(4)]
    pub created_at_unix_ms: u64,
    #[n(5)]
    pub root: [u8; 32],
    #[n(6)]
    pub entries: Vec<IntegrityEntry>,
}

impl Snapshot {
    pub fn new(
        scope_id: impl Into<String>,
        entries: impl IntoIterator<Item = IntegrityEntry>,
        created_at_unix_ms: u64,
    ) -> Result<Self> {
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let mut paths = BTreeSet::new();
        for entry in &entries {
            if !paths.insert(entry.path.clone()) {
                return Err(ShieldError::DuplicatePath(entry.path.to_string()));
            }
        }
        let tree = SparseMerkleTree::from_entries(entries.iter().cloned())?;
        Ok(Self {
            version: FORMAT_VERSION,
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::MlDsa65,
            scope_id: scope_id.into(),
            created_at_unix_ms,
            root: tree.root(),
            entries,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            return Err(ShieldError::UnsupportedVersion(self.version));
        }
        if self.hash_algorithm != HashAlgorithm::Sha256
            || self.signature_algorithm != SignatureAlgorithm::MlDsa65
        {
            return Err(ShieldError::UnsupportedAlgorithm);
        }
        if self.scope_id.is_empty() {
            return Err(ShieldError::InvalidPolicy(
                "snapshot scope_id cannot be empty".to_owned(),
            ));
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(ShieldError::DuplicatePath(
                "entries are not strictly path-sorted".to_owned(),
            ));
        }
        let tree = SparseMerkleTree::from_entries(self.entries.iter().cloned())?;
        if tree.root() != self.root {
            return Err(ShieldError::InvalidMerkleProof);
        }
        Ok(())
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ShieldError::CborEncode(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let value = decoder
            .decode::<Self>()
            .map_err(|error| ShieldError::CborDecode(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(ShieldError::CborDecode(
                "trailing bytes after snapshot".to_owned(),
            ));
        }
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedSnapshot {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

impl SignedSnapshot {
    pub fn sign(snapshot: &Snapshot, secret_key: &MlDsa65SecretKey) -> Result<Self> {
        snapshot.validate()?;
        let payload = snapshot.to_cbor()?;
        let public_key = secret_key.public_key()?;
        let signature = secret_key.sign_with_context(&payload, SNAPSHOT_SIGNATURE_CONTEXT)?;
        Ok(Self {
            payload,
            public_key: public_key.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(&self) -> Result<Snapshot> {
        let public_key = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public_key.verify_with_context(&self.payload, SNAPSHOT_SIGNATURE_CONTEXT, &signature)?;
        Snapshot::from_cbor(&self.payload)
    }

    pub fn public_key(&self) -> Result<MlDsa65PublicKey> {
        MlDsa65PublicKey::from_bytes(&self.public_key)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ShieldError::CborEncode(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let value = decoder
            .decode::<Self>()
            .map_err(|error| ShieldError::CborDecode(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(ShieldError::CborDecode(
                "trailing bytes after signed snapshot".to_owned(),
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MlDsa65KeyPair;
    use crate::model::{EntryKind, NormalizedPath};

    fn entry(path: &str, marker: u8) -> IntegrityEntry {
        IntegrityEntry::new(
            NormalizedPath::new(path).unwrap(),
            EntryKind::File,
            [marker; 32],
            [marker.wrapping_add(1); 32],
            marker as u64,
        )
    }

    #[test]
    fn canonical_snapshot_is_order_independent_and_signed() {
        let first = Snapshot::new("scope", [entry("b", 2), entry("a", 1)], 42).unwrap();
        let second = Snapshot::new("scope", [entry("a", 1), entry("b", 2)], 42).unwrap();
        assert_eq!(first.to_cbor().unwrap(), second.to_cbor().unwrap());

        let pair = MlDsa65KeyPair::generate().unwrap();
        let signed = SignedSnapshot::sign(&first, &pair.secret).unwrap();
        assert_eq!(signed.verify().unwrap(), first);
        assert_eq!(
            SignedSnapshot::from_cbor(&signed.to_cbor().unwrap())
                .unwrap()
                .verify()
                .unwrap(),
            first
        );
    }

    #[test]
    fn tampered_signed_snapshot_is_rejected() {
        let snapshot = Snapshot::new("scope", [entry("a", 1)], 42).unwrap();
        let pair = MlDsa65KeyPair::generate().unwrap();
        let mut signed = SignedSnapshot::sign(&snapshot, &pair.secret).unwrap();
        signed.payload[0] ^= 1;
        assert!(signed.verify().is_err());
    }
}

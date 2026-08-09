use std::path::PathBuf;

use minicbor::{Decode, Encode};
use vollcrypt_shield_core::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
use vollcrypt_shield_protocol::PROTOCOL_VERSION;

use crate::error::{AgentError, Result};
use crate::state::write_atomic;

const REGISTRY_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Witness Registry v1";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct WitnessRegistryEntry {
    #[n(0)]
    pub witness_id: String,
    #[n(1)]
    pub public_key: Vec<u8>,
    #[n(2)]
    pub key_id: [u8; 32],
}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
struct RegistryDocument {
    #[n(0)]
    version: u16,
    #[n(1)]
    entries: Vec<WitnessRegistryEntry>,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
struct SignedRegistry {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

#[derive(Debug)]
pub struct WitnessRegistry {
    path: PathBuf,
    entries: Vec<WitnessRegistryEntry>,
}

impl WitnessRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            entries: Vec::new(),
        }
    }

    pub fn load(path: impl Into<PathBuf>, trusted_key: &MlDsa65PublicKey) -> Result<Self> {
        let path = path.into();
        let signed: SignedRegistry = decode_exact(&std::fs::read(&path)?)?;
        let embedded_key = MlDsa65PublicKey::from_bytes(&signed.public_key)?;
        if embedded_key.key_id() != trusted_key.key_id() {
            return Err(AgentError::Config(
                "witness registry signer does not match configured agent key".to_owned(),
            ));
        }
        let signature = MlDsa65Signature::from_bytes(&signed.signature)?;
        trusted_key.verify_with_context(&signed.payload, REGISTRY_SIGNATURE_CONTEXT, &signature)?;
        let document: RegistryDocument = decode_exact(&signed.payload)?;
        if document.version != PROTOCOL_VERSION {
            return Err(AgentError::Config(
                "unsupported witness registry version".to_owned(),
            ));
        }
        validate_entries(&document.entries)?;
        Ok(Self {
            path,
            entries: document.entries,
        })
    }

    pub fn entries(&self) -> &[WitnessRegistryEntry] {
        &self.entries
    }

    pub fn register(
        &mut self,
        witness_id: &str,
        public_key_bytes: &[u8],
    ) -> Result<WitnessRegistryEntry> {
        validate_witness_id(witness_id)?;
        let public_key = MlDsa65PublicKey::from_bytes(public_key_bytes)?;
        let key_id = public_key.key_id();

        if let Some(existing) = self
            .entries
            .iter()
            .find(|entry| entry.witness_id == witness_id)
        {
            if existing.key_id == key_id && existing.public_key == public_key_bytes {
                return Ok(existing.clone());
            }
            return Err(AgentError::Config(format!(
                "witness id {witness_id} is already pinned to a different key"
            )));
        }
        if self.entries.iter().any(|entry| entry.key_id == key_id) {
            return Err(AgentError::Config(
                "witness public key is already pinned under a different id".to_owned(),
            ));
        }

        let entry = WitnessRegistryEntry {
            witness_id: witness_id.to_owned(),
            public_key: public_key_bytes.to_vec(),
            key_id,
        };
        self.entries.push(entry.clone());
        self.entries
            .sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
        Ok(entry)
    }

    pub fn save(&self, secret: &MlDsa65SecretKey) -> Result<()> {
        validate_entries(&self.entries)?;
        let document = RegistryDocument {
            version: PROTOCOL_VERSION,
            entries: self.entries.clone(),
        };
        let payload = minicbor::to_vec(document)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        let public = secret.public_key()?;
        let signature = secret.sign_with_context(&payload, REGISTRY_SIGNATURE_CONTEXT)?;
        let signed = SignedRegistry {
            payload,
            public_key: public.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        };
        let encoded = minicbor::to_vec(signed)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        write_atomic(&self.path, &encoded)
    }
}

fn validate_entries(entries: &[WitnessRegistryEntry]) -> Result<()> {
    for entry in entries {
        validate_witness_id(&entry.witness_id)?;
        let public_key = MlDsa65PublicKey::from_bytes(&entry.public_key)?;
        if public_key.key_id() != entry.key_id {
            return Err(AgentError::Config(
                "witness registry key id does not match public key".to_owned(),
            ));
        }
    }
    if entries
        .windows(2)
        .any(|pair| pair[0].witness_id >= pair[1].witness_id)
    {
        return Err(AgentError::Config(
            "witness registry ids must be unique and sorted".to_owned(),
        ));
    }
    let mut key_ids: Vec<_> = entries.iter().map(|entry| entry.key_id).collect();
    key_ids.sort();
    if key_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AgentError::Config(
            "witness registry keys must be unique".to_owned(),
        ));
    }
    Ok(())
}

fn validate_witness_id(witness_id: &str) -> Result<()> {
    if witness_id.is_empty()
        || witness_id.len() > 128
        || !witness_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AgentError::Config(
            "witness id must be a 1-128 character ASCII identifier".to_owned(),
        ));
    }
    Ok(())
}

fn decode_exact<'bytes, T>(bytes: &'bytes [u8]) -> Result<T>
where
    T: Decode<'bytes, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
        .map_err(|error| AgentError::Serialization(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(AgentError::Serialization(
            "trailing bytes after witness registry".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::MlDsa65KeyPair;

    #[test]
    fn signed_registry_rejects_tampering_and_identity_rebinding() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("witnesses.cbor");
        let agent = MlDsa65KeyPair::generate().unwrap();
        let witness_a = MlDsa65KeyPair::generate().unwrap();
        let witness_b = MlDsa65KeyPair::generate().unwrap();
        let mut registry = WitnessRegistry::new(&path);
        registry
            .register("witness-a", witness_a.public.as_bytes())
            .unwrap();
        assert!(
            registry
                .register("witness-a", witness_b.public.as_bytes())
                .is_err()
        );
        assert!(
            registry
                .register("witness-b", witness_a.public.as_bytes())
                .is_err()
        );
        registry.save(&agent.secret).unwrap();
        assert_eq!(
            WitnessRegistry::load(&path, &agent.public)
                .unwrap()
                .entries()
                .len(),
            1
        );

        let mut bytes = std::fs::read(&path).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(WitnessRegistry::load(&path, &agent.public).is_err());
    }
}

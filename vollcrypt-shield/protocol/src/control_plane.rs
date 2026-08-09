use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};

use crate::{PROTOCOL_VERSION, ProtocolError, Result};

const ENROLLMENT_CONTEXT: &[u8] = b"Vollcrypt Shield Fleet Enrollment v1";
const SUMMARY_CONTEXT: &[u8] = b"Vollcrypt Shield Fleet Summary v1";
const SUMMARY_HASH_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-FLEET-SUMMARY-HASH-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum DataRetentionMode {
    #[n(1)]
    SignedSummary = 1,
    #[n(2)]
    Raw = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum AgentIntegrityStatus {
    #[n(1)]
    Match = 1,
    #[n(2)]
    Mismatch = 2,
    #[n(3)]
    Contained = 3,
    #[n(4)]
    MonitoringFailure = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct EnrollmentClaim {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub agent_label: String,
    #[n(2)]
    pub retention_mode: DataRetentionMode,
    #[n(3)]
    pub issued_at_unix_ms: u64,
    #[n(4)]
    pub nonce: [u8; 32],
}

impl EnrollmentClaim {
    pub fn new(
        agent_label: impl Into<String>,
        retention_mode: DataRetentionMode,
        issued_at_unix_ms: u64,
    ) -> Result<Self> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| {
            ProtocolError::InvalidControlPlane("nonce generation failed".to_owned())
        })?;
        let claim = Self {
            version: PROTOCOL_VERSION,
            agent_label: agent_label.into(),
            retention_mode,
            issued_at_unix_ms,
            nonce,
        };
        claim.validate()?;
        Ok(claim)
    }

    fn validate(&self) -> Result<()> {
        validate_identifier(&self.agent_label, "agent label")?;
        if self.version != PROTOCOL_VERSION || self.issued_at_unix_ms == 0 || self.nonce == [0; 32]
        {
            return Err(ProtocolError::InvalidControlPlane(
                "invalid enrollment version, timestamp, or nonce".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedEnrollmentRequest {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

impl SignedEnrollmentRequest {
    pub fn sign(claim: &EnrollmentClaim, secret: &MlDsa65SecretKey) -> Result<Self> {
        claim.validate()?;
        let payload = minicbor::to_vec(claim)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        let public_key = secret.public_key()?;
        let signature = secret.sign_with_context(&payload, ENROLLMENT_CONTEXT)?;
        Ok(Self {
            payload,
            public_key: public_key.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(&self) -> Result<(EnrollmentClaim, MlDsa65PublicKey)> {
        let public_key = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public_key.verify_with_context(&self.payload, ENROLLMENT_CONTEXT, &signature)?;
        let claim: EnrollmentClaim = decode_exact(&self.payload, "enrollment claim")?;
        claim.validate()?;
        Ok((claim, public_key))
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ProtocolError::Serialization(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes, "signed enrollment request")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct AgentSummaryClaim {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub agent_key_id: [u8; 32],
    #[n(2)]
    pub scope_id: String,
    #[n(3)]
    pub baseline_root: [u8; 32],
    #[n(4)]
    pub observed_root: [u8; 32],
    #[n(5)]
    pub observed_at_unix_ms: u64,
    #[n(6)]
    pub epoch: u64,
    #[n(7)]
    pub status: AgentIntegrityStatus,
    #[n(8)]
    pub difference_count: u64,
    #[n(9)]
    pub previous_summary_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSummaryInput {
    pub agent_key_id: [u8; 32],
    pub scope_id: String,
    pub baseline_root: [u8; 32],
    pub observed_root: [u8; 32],
    pub observed_at_unix_ms: u64,
    pub epoch: u64,
    pub status: AgentIntegrityStatus,
    pub difference_count: u64,
    pub previous_summary_hash: [u8; 32],
}

impl AgentSummaryClaim {
    pub fn new(input: AgentSummaryInput) -> Result<Self> {
        let claim = Self {
            version: PROTOCOL_VERSION,
            agent_key_id: input.agent_key_id,
            scope_id: input.scope_id,
            baseline_root: input.baseline_root,
            observed_root: input.observed_root,
            observed_at_unix_ms: input.observed_at_unix_ms,
            epoch: input.epoch,
            status: input.status,
            difference_count: input.difference_count,
            previous_summary_hash: input.previous_summary_hash,
        };
        claim.validate()?;
        Ok(claim)
    }

    fn validate(&self) -> Result<()> {
        validate_identifier(&self.scope_id, "scope id")?;
        if self.version != PROTOCOL_VERSION
            || self.agent_key_id == [0; 32]
            || self.observed_at_unix_ms == 0
            || self.epoch == 0
            || (self.status == AgentIntegrityStatus::Match
                && (self.difference_count != 0 || self.baseline_root != self.observed_root))
            || (self.status == AgentIntegrityStatus::Mismatch
                && (self.difference_count == 0 || self.baseline_root == self.observed_root))
        {
            return Err(ProtocolError::InvalidControlPlane(
                "invalid agent summary claim".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedAgentSummary {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    summary_hash: [u8; 32],
    #[n(2)]
    public_key: Vec<u8>,
    #[n(3)]
    signature: Vec<u8>,
}

impl SignedAgentSummary {
    pub fn sign(claim: &AgentSummaryClaim, secret: &MlDsa65SecretKey) -> Result<Self> {
        claim.validate()?;
        let public_key = secret.public_key()?;
        if public_key.key_id() != claim.agent_key_id {
            return Err(ProtocolError::InvalidControlPlane(
                "summary agent key id does not match signer".to_owned(),
            ));
        }
        let payload = minicbor::to_vec(claim)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        let summary_hash = hash_summary(&payload);
        let signature = secret.sign_with_context(&summary_hash, SUMMARY_CONTEXT)?;
        Ok(Self {
            payload,
            summary_hash,
            public_key: public_key.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(&self) -> Result<(AgentSummaryClaim, MlDsa65PublicKey)> {
        if hash_summary(&self.payload) != self.summary_hash {
            return Err(ProtocolError::AuthenticationFailed);
        }
        let public_key = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public_key.verify_with_context(&self.summary_hash, SUMMARY_CONTEXT, &signature)?;
        let claim: AgentSummaryClaim = decode_exact(&self.payload, "agent summary claim")?;
        claim.validate()?;
        if public_key.key_id() != claim.agent_key_id {
            return Err(ProtocolError::InvalidControlPlane(
                "summary signer does not match agent key id".to_owned(),
            ));
        }
        Ok((claim, public_key))
    }

    pub fn summary_hash(&self) -> [u8; 32] {
        self.summary_hash
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ProtocolError::Serialization(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes, "signed agent summary")
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProtocolError::InvalidControlPlane(format!(
            "{label} must be a 1-128 character ASCII identifier"
        )));
    }
    Ok(())
}

fn hash_summary(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SUMMARY_HASH_DOMAIN);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn decode_exact<'bytes, Value>(bytes: &'bytes [u8], label: &str) -> Result<Value>
where
    Value: Decode<'bytes, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<Value>()
        .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::Serialization(format!(
            "trailing bytes after {label}"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::MlDsa65KeyPair;

    #[test]
    fn enrollment_proves_agent_key_possession() {
        let agent = MlDsa65KeyPair::generate().unwrap();
        let claim = EnrollmentClaim::new("node-a", DataRetentionMode::SignedSummary, 100).unwrap();
        let request = SignedEnrollmentRequest::sign(&claim, &agent.secret).unwrap();
        let (verified, public) = SignedEnrollmentRequest::from_cbor(&request.to_cbor().unwrap())
            .unwrap()
            .verify()
            .unwrap();
        assert_eq!(verified, claim);
        assert_eq!(public.key_id(), agent.public.key_id());
    }

    #[test]
    fn summary_is_key_bound_chained_and_rejects_tampering() {
        let agent = MlDsa65KeyPair::generate().unwrap();
        let first_claim = AgentSummaryClaim::new(AgentSummaryInput {
            agent_key_id: agent.public.key_id(),
            scope_id: "app".to_owned(),
            baseline_root: [7; 32],
            observed_root: [7; 32],
            observed_at_unix_ms: 200,
            epoch: 1,
            status: AgentIntegrityStatus::Match,
            difference_count: 0,
            previous_summary_hash: [0; 32],
        })
        .unwrap();
        let first = SignedAgentSummary::sign(&first_claim, &agent.secret).unwrap();
        let second_claim = AgentSummaryClaim::new(AgentSummaryInput {
            agent_key_id: agent.public.key_id(),
            scope_id: "app".to_owned(),
            baseline_root: [7; 32],
            observed_root: [8; 32],
            observed_at_unix_ms: 300,
            epoch: 2,
            status: AgentIntegrityStatus::Mismatch,
            difference_count: 1,
            previous_summary_hash: first.summary_hash(),
        })
        .unwrap();
        let second = SignedAgentSummary::sign(&second_claim, &agent.secret).unwrap();
        assert_eq!(second.verify().unwrap().0, second_claim);

        let mut encoded = second.to_cbor().unwrap();
        let midpoint = encoded.len() / 2;
        encoded[midpoint] ^= 1;
        assert!(
            SignedAgentSummary::from_cbor(&encoded)
                .and_then(|value| value.verify())
                .is_err()
        );
    }
}

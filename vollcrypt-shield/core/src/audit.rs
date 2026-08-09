use minicbor::{Decode, Encode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::algorithm::FORMAT_VERSION;
use crate::crypto::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
use crate::error::{Result, ShieldError};

const AUDIT_HASH_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-AUDIT-v1\0";
const AUDIT_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Audit v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum AuditEventKind {
    #[n(1)]
    AgentStarted = 1,
    #[n(2)]
    BaselineCreated = 2,
    #[n(3)]
    VerificationPassed = 3,
    #[n(4)]
    VerificationFailed = 4,
    #[n(5)]
    DryRunResponse = 5,
    #[n(6)]
    Quarantined = 6,
    #[n(7)]
    RolledBack = 7,
    #[n(8)]
    ScopeContained = 8,
    #[n(9)]
    ContainmentReminder = 9,
    #[n(10)]
    BreakGlassReleased = 10,
    #[n(11)]
    PolicyPromoted = 11,
    #[n(12)]
    AgentStopped = 12,
    #[n(13)]
    MonitoringFailed = 13,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct AuditEvent {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub sequence: u64,
    #[n(2)]
    pub timestamp_unix_ms: u64,
    #[n(3)]
    pub scope_id: String,
    #[n(4)]
    pub kind: AuditEventKind,
    #[n(5)]
    pub path: Option<String>,
    #[n(6)]
    pub detail: String,
    #[n(7)]
    pub previous_hash: [u8; 32],
}

impl AuditEvent {
    pub fn new(
        sequence: u64,
        timestamp_unix_ms: u64,
        scope_id: impl Into<String>,
        kind: AuditEventKind,
        path: Option<String>,
        detail: impl Into<String>,
        previous_hash: [u8; 32],
    ) -> Self {
        Self {
            version: FORMAT_VERSION,
            sequence,
            timestamp_unix_ms,
            scope_id: scope_id.into(),
            kind,
            path,
            detail: detail.into(),
            previous_hash,
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ShieldError::CborEncode(error.to_string()))
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let event = decoder
            .decode::<Self>()
            .map_err(|error| ShieldError::CborDecode(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(ShieldError::CborDecode(
                "trailing bytes after audit event".to_owned(),
            ));
        }
        if event.version != FORMAT_VERSION {
            return Err(ShieldError::UnsupportedVersion(event.version));
        }
        Ok(event)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedAuditRecord {
    #[n(0)]
    event_payload: Vec<u8>,
    #[n(1)]
    event_hash: [u8; 32],
    #[n(2)]
    public_key: Vec<u8>,
    #[n(3)]
    signature: Vec<u8>,
}

impl SignedAuditRecord {
    pub fn sign(event: &AuditEvent, secret_key: &MlDsa65SecretKey) -> Result<Self> {
        let event_payload = event.to_cbor()?;
        let event_hash = hash_event(&event_payload);
        let public_key = secret_key.public_key()?;
        let signature = secret_key.sign_with_context(&event_hash, AUDIT_SIGNATURE_CONTEXT)?;
        Ok(Self {
            event_payload,
            event_hash,
            public_key: public_key.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(&self) -> Result<AuditEvent> {
        let expected_hash = hash_event(&self.event_payload);
        if !bool::from(expected_hash.ct_eq(&self.event_hash)) {
            return Err(ShieldError::InvalidAuditChain(0));
        }
        let public_key = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public_key.verify_with_context(&self.event_hash, AUDIT_SIGNATURE_CONTEXT, &signature)?;
        AuditEvent::from_cbor(&self.event_payload)
    }

    pub fn event_hash(&self) -> [u8; 32] {
        self.event_hash
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
                "trailing bytes after audit record".to_owned(),
            ));
        }
        Ok(value)
    }
}

pub fn verify_audit_chain(records: &[SignedAuditRecord]) -> Result<Vec<AuditEvent>> {
    let mut expected_previous = [0u8; 32];
    let mut expected_key_id = None;
    let mut events = Vec::with_capacity(records.len());

    for (index, record) in records.iter().enumerate() {
        let event = record.verify()?;
        if event.sequence != index as u64 || event.previous_hash != expected_previous {
            return Err(ShieldError::InvalidAuditChain(event.sequence));
        }
        let key_id = record.public_key()?.key_id();
        if let Some(expected) = expected_key_id
            && key_id != expected
        {
            return Err(ShieldError::InvalidAuditChain(event.sequence));
        }
        expected_key_id = Some(key_id);
        expected_previous = record.event_hash();
        events.push(event);
    }
    Ok(events)
}

fn hash_event(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_HASH_DOMAIN);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MlDsa65KeyPair;

    #[test]
    fn chain_rejects_reorder_and_tampering() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let first = SignedAuditRecord::sign(
            &AuditEvent::new(
                0,
                1,
                "scope",
                AuditEventKind::AgentStarted,
                None,
                "started",
                [0; 32],
            ),
            &pair.secret,
        )
        .unwrap();
        let second = SignedAuditRecord::sign(
            &AuditEvent::new(
                1,
                2,
                "scope",
                AuditEventKind::VerificationPassed,
                None,
                "ok",
                first.event_hash(),
            ),
            &pair.secret,
        )
        .unwrap();

        assert_eq!(
            verify_audit_chain(&[first.clone(), second.clone()])
                .unwrap()
                .len(),
            2
        );
        assert!(verify_audit_chain(&[second, first]).is_err());
    }
}

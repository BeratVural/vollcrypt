use std::collections::BTreeMap;

use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};

use crate::{PROTOCOL_VERSION, ProtocolError, Result};

const OFFLINE_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Offline Package v1";
const OFFLINE_HASH_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-OFFLINE-PACKAGE-HASH-v1\0";
pub const MAX_OFFLINE_PAYLOAD_BYTES: usize = 16_777_216;
pub const MAX_OFFLINE_PACKAGE_LIFETIME_MS: u64 = 2_592_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum OfflinePackageKind {
    #[n(1)]
    FleetEnrollmentRequest = 1,
    #[n(2)]
    FleetSummary = 2,
    #[n(3)]
    WitnessAttestationRequest = 3,
    #[n(4)]
    WitnessStatement = 4,
    #[n(5)]
    SnapshotEvidence = 5,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct OfflinePackageManifest {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub package_id: [u8; 16],
    #[n(2)]
    pub kind: OfflinePackageKind,
    #[n(3)]
    pub channel_id: String,
    #[n(4)]
    pub sender_key_id: [u8; 32],
    #[n(5)]
    pub created_at_unix_ms: u64,
    #[n(6)]
    pub expires_at_unix_ms: u64,
    #[n(7)]
    pub sequence: u64,
    #[n(8)]
    pub previous_package_hash: [u8; 32],
    #[n(9)]
    pub payload_hash: [u8; 32],
    #[n(10)]
    pub payload_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePackageInput {
    pub kind: OfflinePackageKind,
    pub channel_id: String,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub sequence: u64,
    pub previous_package_hash: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedOfflinePackage {
    #[n(0)]
    manifest: Vec<u8>,
    #[n(1)]
    payload: Vec<u8>,
    #[n(2)]
    package_hash: [u8; 32],
    #[n(3)]
    public_key: Vec<u8>,
    #[n(4)]
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOfflinePackage {
    pub manifest: OfflinePackageManifest,
    pub payload: Vec<u8>,
    pub sender_public_key: MlDsa65PublicKey,
    pub package_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct OfflineCursorState {
    #[n(0)]
    pub sender_key_id: [u8; 32],
    #[n(1)]
    pub channel_id: String,
    #[n(2)]
    pub last_sequence: u64,
    #[n(3)]
    pub last_package_hash: [u8; 32],
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct OfflineLedgerState {
    #[n(0)]
    pub cursors: Vec<OfflineCursorState>,
}

#[derive(Debug, Clone, Default)]
pub struct OfflineLedger {
    cursors: BTreeMap<([u8; 32], String), OfflineCursorState>,
}

impl SignedOfflinePackage {
    pub fn sign(input: OfflinePackageInput, secret: &MlDsa65SecretKey) -> Result<Self> {
        validate_channel(&input.channel_id)?;
        validate_time_and_sequence(
            input.created_at_unix_ms,
            input.expires_at_unix_ms,
            input.sequence,
            input.previous_package_hash,
        )?;
        if input.payload.len() > MAX_OFFLINE_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidOfflinePackage(format!(
                "payload exceeds {MAX_OFFLINE_PAYLOAD_BYTES} bytes"
            )));
        }
        let mut package_id = [0_u8; 16];
        getrandom::fill(&mut package_id).map_err(|_| {
            ProtocolError::InvalidOfflinePackage("package id generation failed".to_owned())
        })?;
        if package_id == [0; 16] {
            return Err(ProtocolError::InvalidOfflinePackage(
                "generated package id was invalid".to_owned(),
            ));
        }
        let public_key = secret.public_key()?;
        let manifest = OfflinePackageManifest {
            version: PROTOCOL_VERSION,
            package_id,
            kind: input.kind,
            channel_id: input.channel_id,
            sender_key_id: public_key.key_id(),
            created_at_unix_ms: input.created_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
            sequence: input.sequence,
            previous_package_hash: input.previous_package_hash,
            payload_hash: Sha256::digest(&input.payload).into(),
            payload_len: u64::try_from(input.payload.len()).map_err(|_| {
                ProtocolError::InvalidOfflinePackage("payload length exceeds u64".to_owned())
            })?,
        };
        manifest.validate()?;
        let manifest = minicbor::to_vec(&manifest)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        let package_hash = hash_package(&manifest, &input.payload);
        let signature = secret.sign_with_context(&package_hash, OFFLINE_SIGNATURE_CONTEXT)?;
        Ok(Self {
            manifest,
            payload: input.payload,
            package_hash,
            public_key: public_key.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify_at(&self, now_unix_ms: u64) -> Result<VerifiedOfflinePackage> {
        if self.payload.len() > MAX_OFFLINE_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidOfflinePackage(
                "offline payload exceeds its limit".to_owned(),
            ));
        }
        let manifest: OfflinePackageManifest = decode_exact(&self.manifest, "offline manifest")?;
        manifest.validate()?;
        if now_unix_ms > manifest.expires_at_unix_ms
            || manifest.created_at_unix_ms > now_unix_ms.saturating_add(300_000)
        {
            return Err(ProtocolError::InvalidOfflinePackage(
                "offline package is expired or created too far in the future".to_owned(),
            ));
        }
        if manifest.payload_len
            != u64::try_from(self.payload.len()).map_err(|_| {
                ProtocolError::InvalidOfflinePackage("payload length exceeds u64".to_owned())
            })?
            || manifest.payload_hash != <[u8; 32]>::from(Sha256::digest(&self.payload))
            || self.package_hash != hash_package(&self.manifest, &self.payload)
        {
            return Err(ProtocolError::AuthenticationFailed);
        }
        let public_key = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        if public_key.key_id() != manifest.sender_key_id {
            return Err(ProtocolError::AuthenticationFailed);
        }
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public_key.verify_with_context(
            &self.package_hash,
            OFFLINE_SIGNATURE_CONTEXT,
            &signature,
        )?;
        Ok(VerifiedOfflinePackage {
            manifest,
            payload: self.payload.clone(),
            sender_public_key: public_key,
            package_hash: self.package_hash,
        })
    }

    pub fn package_hash(&self) -> [u8; 32] {
        self.package_hash
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ProtocolError::Serialization(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes, "signed offline package")
    }
}

impl OfflinePackageManifest {
    fn validate(&self) -> Result<()> {
        validate_channel(&self.channel_id)?;
        validate_time_and_sequence(
            self.created_at_unix_ms,
            self.expires_at_unix_ms,
            self.sequence,
            self.previous_package_hash,
        )?;
        if self.version != PROTOCOL_VERSION
            || self.package_id == [0; 16]
            || self.sender_key_id == [0; 32]
            || self.payload_hash == [0; 32]
            || self.payload_len > MAX_OFFLINE_PAYLOAD_BYTES as u64
        {
            return Err(ProtocolError::InvalidOfflinePackage(
                "offline manifest contains invalid identifiers or payload bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

impl OfflineLedger {
    pub fn from_state(state: OfflineLedgerState) -> Result<Self> {
        if state.cursors.len() > 100_000 {
            return Err(ProtocolError::InvalidOfflinePackage(
                "offline cursor count exceeds 100000".to_owned(),
            ));
        }
        let mut cursors = BTreeMap::new();
        for cursor in state.cursors {
            validate_channel(&cursor.channel_id)?;
            if cursor.sender_key_id == [0; 32]
                || cursor.last_sequence == 0
                || cursor.last_package_hash == [0; 32]
                || cursors
                    .insert((cursor.sender_key_id, cursor.channel_id.clone()), cursor)
                    .is_some()
            {
                return Err(ProtocolError::InvalidOfflinePackage(
                    "offline ledger contains an invalid or duplicate cursor".to_owned(),
                ));
            }
        }
        Ok(Self { cursors })
    }

    pub fn export_state(&self) -> OfflineLedgerState {
        OfflineLedgerState {
            cursors: self.cursors.values().cloned().collect(),
        }
    }

    pub fn accept(
        &mut self,
        package: &SignedOfflinePackage,
        expected_sender_key_id: [u8; 32],
        now_unix_ms: u64,
    ) -> Result<VerifiedOfflinePackage> {
        let verified = package.verify_at(now_unix_ms)?;
        if verified.manifest.sender_key_id != expected_sender_key_id {
            return Err(ProtocolError::AuthenticationFailed);
        }
        let key = (
            verified.manifest.sender_key_id,
            verified.manifest.channel_id.clone(),
        );
        match self.cursors.get(&key) {
            Some(cursor)
                if verified.manifest.sequence == cursor.last_sequence.saturating_add(1)
                    && verified.manifest.previous_package_hash == cursor.last_package_hash => {}
            None if verified.manifest.sequence == 1
                && verified.manifest.previous_package_hash == [0; 32] => {}
            _ => return Err(ProtocolError::AuthenticationFailed),
        }
        self.cursors.insert(
            key,
            OfflineCursorState {
                sender_key_id: verified.manifest.sender_key_id,
                channel_id: verified.manifest.channel_id.clone(),
                last_sequence: verified.manifest.sequence,
                last_package_hash: verified.package_hash,
            },
        );
        Ok(verified)
    }
}

fn validate_channel(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProtocolError::InvalidOfflinePackage(
            "channel id must be a 1-128 character ASCII identifier".to_owned(),
        ));
    }
    Ok(())
}

fn validate_time_and_sequence(
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    sequence: u64,
    previous_package_hash: [u8; 32],
) -> Result<()> {
    let lifetime = expires_at_unix_ms.checked_sub(created_at_unix_ms);
    if created_at_unix_ms == 0
        || sequence == 0
        || lifetime.is_none_or(|value| value == 0 || value > MAX_OFFLINE_PACKAGE_LIFETIME_MS)
        || (sequence == 1 && previous_package_hash != [0; 32])
        || (sequence > 1 && previous_package_hash == [0; 32])
    {
        return Err(ProtocolError::InvalidOfflinePackage(
            "invalid offline package time, sequence, or previous hash".to_owned(),
        ));
    }
    Ok(())
}

fn hash_package(manifest: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OFFLINE_HASH_DOMAIN);
    hasher.update((manifest.len() as u64).to_be_bytes());
    hasher.update(manifest);
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

    fn package(
        sender: &MlDsa65KeyPair,
        sequence: u64,
        previous_package_hash: [u8; 32],
        marker: u8,
    ) -> SignedOfflinePackage {
        SignedOfflinePackage::sign(
            OfflinePackageInput {
                kind: OfflinePackageKind::FleetSummary,
                channel_id: "fleet-summary".to_owned(),
                created_at_unix_ms: 100,
                expires_at_unix_ms: 10_000,
                sequence,
                previous_package_hash,
                payload: vec![marker; 32],
            },
            &sender.secret,
        )
        .unwrap()
    }

    #[test]
    fn package_binds_manifest_payload_sender_and_expiry() {
        let sender = MlDsa65KeyPair::generate().unwrap();
        let signed = package(&sender, 1, [0; 32], 7);
        let decoded = SignedOfflinePackage::from_cbor(&signed.to_cbor().unwrap()).unwrap();
        let verified = decoded.verify_at(500).unwrap();
        assert_eq!(verified.manifest.sender_key_id, sender.public.key_id());
        assert_eq!(verified.payload, vec![7; 32]);
        assert!(decoded.verify_at(10_001).is_err());

        let mut tampered = decoded;
        tampered.payload[0] ^= 1;
        assert!(tampered.verify_at(500).is_err());
    }

    #[test]
    fn ledger_rejects_replay_wrong_sender_and_broken_chain() {
        let sender = MlDsa65KeyPair::generate().unwrap();
        let other = MlDsa65KeyPair::generate().unwrap();
        let first = package(&sender, 1, [0; 32], 1);
        let second = package(&sender, 2, first.package_hash(), 2);
        let broken = package(&sender, 3, [9; 32], 3);
        let mut ledger = OfflineLedger::default();
        assert!(ledger.accept(&first, other.public.key_id(), 500).is_err());
        ledger.accept(&first, sender.public.key_id(), 500).unwrap();
        assert!(ledger.accept(&first, sender.public.key_id(), 500).is_err());
        ledger.accept(&second, sender.public.key_id(), 500).unwrap();
        assert!(ledger.accept(&broken, sender.public.key_id(), 500).is_err());

        let restored = OfflineLedger::from_state(ledger.export_state()).unwrap();
        assert_eq!(restored.export_state(), ledger.export_state());
    }

    #[test]
    fn oversized_payload_and_invalid_first_sequence_are_rejected() {
        let sender = MlDsa65KeyPair::generate().unwrap();
        let oversized = OfflinePackageInput {
            kind: OfflinePackageKind::SnapshotEvidence,
            channel_id: "snapshot".to_owned(),
            created_at_unix_ms: 100,
            expires_at_unix_ms: 200,
            sequence: 1,
            previous_package_hash: [0; 32],
            payload: vec![0; MAX_OFFLINE_PAYLOAD_BYTES + 1],
        };
        assert!(SignedOfflinePackage::sign(oversized, &sender.secret).is_err());
        assert!(
            SignedOfflinePackage::sign(
                OfflinePackageInput {
                    kind: OfflinePackageKind::SnapshotEvidence,
                    channel_id: "snapshot".to_owned(),
                    created_at_unix_ms: 100,
                    expires_at_unix_ms: 200,
                    sequence: 1,
                    previous_package_hash: [1; 32],
                    payload: vec![1],
                },
                &sender.secret,
            )
            .is_err()
        );
    }
}

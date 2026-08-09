use std::collections::{BTreeMap, BTreeSet};

use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{
    MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignedSnapshot, Snapshot,
};

use crate::{PROTOCOL_VERSION, ProtocolError, Result};

const WITNESS_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Witness v1";
const WITNESS_HASH_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-WITNESS-HASH-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessIdentity {
    pub id: String,
    pub public_key: Vec<u8>,
}

impl WitnessIdentity {
    pub fn key_id(&self) -> Result<[u8; 32]> {
        Ok(MlDsa65PublicKey::from_bytes(&self.public_key)?.key_id())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPolicy {
    pub threshold: usize,
    pub witnesses: Vec<WitnessIdentity>,
}

impl WitnessPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.witnesses.len() < 2 || self.witnesses.len() > 64 {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "witness count must be between 2 and 64".to_owned(),
            ));
        }
        if self.threshold < 2 || self.threshold > self.witnesses.len() {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "threshold must be between 2 and the witness count".to_owned(),
            ));
        }
        let mut ids = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        for witness in &self.witnesses {
            if witness.id.is_empty()
                || witness.id.len() > 128
                || !witness
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(ProtocolError::InvalidWitnessPolicy(
                    "witness id must be a 1-128 character ASCII identifier".to_owned(),
                ));
            }
            if !ids.insert(witness.id.clone()) {
                return Err(ProtocolError::InvalidWitnessPolicy(
                    "duplicate witness id".to_owned(),
                ));
            }
            if !key_ids.insert(witness.key_id()?) {
                return Err(ProtocolError::InvalidWitnessPolicy(
                    "duplicate witness public key".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn identity(&self, id: &str) -> Option<&WitnessIdentity> {
        self.witnesses.iter().find(|witness| witness.id == id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct AttestationRequest {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub epoch: u64,
    #[n(2)]
    pub signed_snapshot: Vec<u8>,
}

impl AttestationRequest {
    pub fn new(epoch: u64, signed_snapshot: &SignedSnapshot) -> Result<Self> {
        if epoch == 0 {
            return Err(ProtocolError::InvalidPairing(
                "witness epoch must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            version: PROTOCOL_VERSION,
            epoch,
            signed_snapshot: signed_snapshot.to_cbor()?,
        })
    }

    pub fn verify(&self, trusted_agent_key_id: [u8; 32]) -> Result<Snapshot> {
        if self.version != PROTOCOL_VERSION || self.epoch == 0 {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "invalid attestation request version or epoch".to_owned(),
            ));
        }
        let signed = SignedSnapshot::from_cbor(&self.signed_snapshot)?;
        if signed.public_key()?.key_id() != trusted_agent_key_id {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "attestation signer does not match paired agent".to_owned(),
            ));
        }
        Ok(signed.verify()?)
    }

    pub fn agent_key_id(&self) -> Result<[u8; 32]> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "invalid attestation request version".to_owned(),
            ));
        }
        Ok(SignedSnapshot::from_cbor(&self.signed_snapshot)?
            .public_key()?
            .key_id())
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ProtocolError::Serialization(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes, "attestation request")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct WitnessClaim {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub witness_id: String,
    #[n(2)]
    pub agent_key_id: [u8; 32],
    #[n(3)]
    pub scope_id: String,
    #[n(4)]
    pub snapshot_root: [u8; 32],
    #[n(5)]
    pub snapshot_created_at_unix_ms: u64,
    #[n(6)]
    pub epoch: u64,
    #[n(7)]
    pub witnessed_at_unix_ms: u64,
    #[n(8)]
    pub previous_statement_hash: [u8; 32],
}

impl WitnessClaim {
    fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION
            || self.witness_id.is_empty()
            || self.scope_id.is_empty()
            || self.epoch == 0
        {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "invalid witness claim".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedWitnessStatement {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    statement_hash: [u8; 32],
    #[n(2)]
    public_key: Vec<u8>,
    #[n(3)]
    signature: Vec<u8>,
}

impl SignedWitnessStatement {
    pub fn sign(claim: &WitnessClaim, secret: &MlDsa65SecretKey) -> Result<Self> {
        claim.validate()?;
        let payload = minicbor::to_vec(claim)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        let statement_hash = hash_statement(&payload);
        let public_key = secret.public_key()?;
        let signature = secret.sign_with_context(&statement_hash, WITNESS_SIGNATURE_CONTEXT)?;
        Ok(Self {
            payload,
            statement_hash,
            public_key: public_key.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(&self) -> Result<WitnessClaim> {
        if hash_statement(&self.payload) != self.statement_hash {
            return Err(ProtocolError::AuthenticationFailed);
        }
        let public_key = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public_key.verify_with_context(
            &self.statement_hash,
            WITNESS_SIGNATURE_CONTEXT,
            &signature,
        )?;
        let claim: WitnessClaim = decode_exact(&self.payload, "witness claim")?;
        claim.validate()?;
        Ok(claim)
    }

    pub fn public_key(&self) -> Result<MlDsa65PublicKey> {
        Ok(MlDsa65PublicKey::from_bytes(&self.public_key)?)
    }

    pub fn statement_hash(&self) -> [u8; 32] {
        self.statement_hash
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ProtocolError::Serialization(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes, "signed witness statement")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumExpectation {
    pub agent_key_id: [u8; 32],
    pub scope_id: String,
    pub snapshot_root: [u8; 32],
    pub snapshot_created_at_unix_ms: u64,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuorumProof {
    pub threshold: usize,
    pub accepted_witness_ids: Vec<String>,
    pub epoch: u64,
    pub snapshot_root: [u8; 32],
}

pub fn verify_witness_quorum(
    policy: &WitnessPolicy,
    expectation: &QuorumExpectation,
    statements: &[SignedWitnessStatement],
) -> Result<QuorumProof> {
    policy.validate()?;
    let mut accepted = BTreeMap::<String, [u8; 32]>::new();
    for statement in statements {
        let Ok(claim) = statement.verify() else {
            continue;
        };
        let Some(identity) = policy.identity(&claim.witness_id) else {
            continue;
        };
        let Ok(statement_key_id) = statement.public_key().map(|key| key.key_id()) else {
            continue;
        };
        let Ok(policy_key_id) = identity.key_id() else {
            continue;
        };
        if statement_key_id != policy_key_id
            || claim.agent_key_id != expectation.agent_key_id
            || claim.scope_id != expectation.scope_id
            || claim.snapshot_root != expectation.snapshot_root
            || claim.snapshot_created_at_unix_ms != expectation.snapshot_created_at_unix_ms
            || claim.epoch != expectation.epoch
        {
            continue;
        }
        accepted
            .entry(claim.witness_id)
            .or_insert(statement.statement_hash());
    }
    if accepted.len() < policy.threshold {
        return Err(ProtocolError::QuorumNotReached {
            accepted: accepted.len(),
            required: policy.threshold,
        });
    }
    Ok(QuorumProof {
        threshold: policy.threshold,
        accepted_witness_ids: accepted.into_keys().collect(),
        epoch: expectation.epoch,
        snapshot_root: expectation.snapshot_root,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct WitnessCursorState {
    #[n(0)]
    pub agent_key_id: [u8; 32],
    #[n(1)]
    pub scope_id: String,
    #[n(2)]
    pub last_epoch: u64,
    #[n(3)]
    pub last_statement_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct WitnessLedgerState {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub cursors: Vec<WitnessCursorState>,
}

#[derive(Debug, Default)]
pub struct WitnessLedger {
    cursors: BTreeMap<([u8; 32], String), WitnessCursorState>,
}

impl WitnessLedger {
    pub fn from_state(state: WitnessLedgerState) -> Result<Self> {
        if state.version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "unsupported witness ledger version".to_owned(),
            ));
        }
        let mut cursors = BTreeMap::new();
        for cursor in state.cursors {
            if cursor.scope_id.is_empty()
                || cursor.last_epoch == 0
                || cursors
                    .insert((cursor.agent_key_id, cursor.scope_id.clone()), cursor)
                    .is_some()
            {
                return Err(ProtocolError::InvalidWitnessPolicy(
                    "invalid or duplicate witness ledger cursor".to_owned(),
                ));
            }
        }
        Ok(Self { cursors })
    }

    pub fn export_state(&self) -> WitnessLedgerState {
        WitnessLedgerState {
            version: PROTOCOL_VERSION,
            cursors: self.cursors.values().cloned().collect(),
        }
    }

    pub fn attest(
        &mut self,
        request: &AttestationRequest,
        trusted_agent_key_id: [u8; 32],
        witness_id: &str,
        witness_secret: &MlDsa65SecretKey,
        now_unix_ms: u64,
    ) -> Result<SignedWitnessStatement> {
        let snapshot = request.verify(trusted_agent_key_id)?;
        let cursor_key = (trusted_agent_key_id, snapshot.scope_id.clone());
        let previous = self.cursors.get(&cursor_key);
        if previous.is_some_and(|cursor| request.epoch <= cursor.last_epoch) {
            return Err(ProtocolError::InvalidWitnessPolicy(
                "witness epoch must increase monotonically".to_owned(),
            ));
        }
        let previous_statement_hash = previous
            .map(|cursor| cursor.last_statement_hash)
            .unwrap_or([0; 32]);
        let claim = WitnessClaim {
            version: PROTOCOL_VERSION,
            witness_id: witness_id.to_owned(),
            agent_key_id: trusted_agent_key_id,
            scope_id: snapshot.scope_id,
            snapshot_root: snapshot.root,
            snapshot_created_at_unix_ms: snapshot.created_at_unix_ms,
            epoch: request.epoch,
            witnessed_at_unix_ms: now_unix_ms,
            previous_statement_hash,
        };
        let statement = SignedWitnessStatement::sign(&claim, witness_secret)?;
        self.cursors.insert(
            cursor_key,
            WitnessCursorState {
                agent_key_id: trusted_agent_key_id,
                scope_id: claim.scope_id.clone(),
                last_epoch: request.epoch,
                last_statement_hash: statement.statement_hash(),
            },
        );
        Ok(statement)
    }
}

fn hash_statement(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WITNESS_HASH_DOMAIN);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn decode_exact<'a, T>(bytes: &'a [u8], label: &str) -> Result<T>
where
    T: Decode<'a, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
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
    use vollcrypt_shield_core::{EntryKind, IntegrityEntry, MlDsa65KeyPair, NormalizedPath};

    fn request(agent: &MlDsa65KeyPair, epoch: u64, marker: u8) -> AttestationRequest {
        let entry = IntegrityEntry::new(
            NormalizedPath::new("app.bin").unwrap(),
            EntryKind::File,
            [marker; 32],
            [0; 32],
            10,
        );
        let snapshot = Snapshot::new("application", [entry], 100).unwrap();
        let signed = SignedSnapshot::sign(&snapshot, &agent.secret).unwrap();
        AttestationRequest::new(epoch, &signed).unwrap()
    }

    fn identity(id: &str, pair: &MlDsa65KeyPair) -> WitnessIdentity {
        WitnessIdentity {
            id: id.to_owned(),
            public_key: pair.public.as_bytes().to_vec(),
        }
    }

    #[test]
    fn two_of_three_quorum_accepts_only_distinct_registered_witnesses() {
        let agent = MlDsa65KeyPair::generate().unwrap();
        let first = MlDsa65KeyPair::generate().unwrap();
        let second = MlDsa65KeyPair::generate().unwrap();
        let third = MlDsa65KeyPair::generate().unwrap();
        let policy = WitnessPolicy {
            threshold: 2,
            witnesses: vec![
                identity("first", &first),
                identity("second", &second),
                identity("third", &third),
            ],
        };
        let request = request(&agent, 1, 7);
        let mut first_ledger = WitnessLedger::default();
        let mut second_ledger = WitnessLedger::default();
        let first_statement = first_ledger
            .attest(&request, agent.public.key_id(), "first", &first.secret, 200)
            .unwrap();
        let second_statement = second_ledger
            .attest(
                &request,
                agent.public.key_id(),
                "second",
                &second.secret,
                201,
            )
            .unwrap();
        let snapshot = request.verify(agent.public.key_id()).unwrap();
        let expectation = QuorumExpectation {
            agent_key_id: agent.public.key_id(),
            scope_id: snapshot.scope_id,
            snapshot_root: snapshot.root,
            snapshot_created_at_unix_ms: snapshot.created_at_unix_ms,
            epoch: 1,
        };
        let proof = verify_witness_quorum(
            &policy,
            &expectation,
            &[first_statement.clone(), second_statement],
        )
        .unwrap();
        assert_eq!(proof.accepted_witness_ids, vec!["first", "second"]);
        assert!(
            verify_witness_quorum(
                &policy,
                &expectation,
                &[first_statement.clone(), first_statement]
            )
            .is_err()
        );
    }

    #[test]
    fn witness_rejects_epoch_rollback_and_unpaired_agent() {
        let agent = MlDsa65KeyPair::generate().unwrap();
        let other = MlDsa65KeyPair::generate().unwrap();
        let witness = MlDsa65KeyPair::generate().unwrap();
        let request = request(&agent, 3, 1);
        let mut ledger = WitnessLedger::default();
        ledger
            .attest(
                &request,
                agent.public.key_id(),
                "witness",
                &witness.secret,
                200,
            )
            .unwrap();
        assert!(
            ledger
                .attest(
                    &request,
                    agent.public.key_id(),
                    "witness",
                    &witness.secret,
                    201
                )
                .is_err()
        );
        assert!(
            WitnessLedger::default()
                .attest(
                    &request,
                    other.public.key_id(),
                    "witness",
                    &witness.secret,
                    200
                )
                .is_err()
        );
    }

    #[test]
    fn policy_requires_at_least_two_witnesses() {
        let witness = MlDsa65KeyPair::generate().unwrap();
        assert!(
            WitnessPolicy {
                threshold: 1,
                witnesses: vec![identity("only", &witness)]
            }
            .validate()
            .is_err()
        );
    }
}

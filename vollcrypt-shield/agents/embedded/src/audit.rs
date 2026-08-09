use crate::{Digest, EmbeddedError, FORMAT_VERSION, hash_parts};

const AUDIT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMBEDDED-AUDIT-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditEventKind {
    MeasurementUpdated = 1,
    MeasurementRemoved = 2,
    BaselineAccepted = 3,
    VerificationPassed = 4,
    VerificationFailed = 5,
    ScopeContained = 6,
    BreakGlassReleased = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub monotonic_counter: u64,
    pub kind: AuditEventKind,
    pub component_id: Digest,
    pub evidence_digest: Digest,
    pub previous_hash: Digest,
    pub record_hash: Digest,
}

impl AuditRecord {
    pub fn verify(&self, expected_sequence: u64, expected_previous: &Digest) -> bool {
        self.sequence == expected_sequence
            && &self.previous_hash == expected_previous
            && self.record_hash
                == record_hash(
                    self.sequence,
                    self.monotonic_counter,
                    self.kind,
                    &self.component_id,
                    &self.evidence_digest,
                    &self.previous_hash,
                )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditChain {
    sequence: u64,
    last_counter: Option<u64>,
    head: Digest,
}

impl AuditChain {
    pub const fn new() -> Self {
        Self {
            sequence: 0,
            last_counter: None,
            head: [0; 32],
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn head(&self) -> Digest {
        self.head
    }

    pub const fn last_counter(&self) -> Option<u64> {
        self.last_counter
    }

    pub fn restore(
        sequence: u64,
        last_counter: Option<u64>,
        head: Digest,
    ) -> Result<Self, EmbeddedError> {
        let empty = sequence == 0 && last_counter.is_none() && head == [0; 32];
        let populated = sequence > 0 && last_counter.is_some() && head != [0; 32];
        if !empty && !populated {
            return Err(EmbeddedError::InvalidPersistedState);
        }
        Ok(Self {
            sequence,
            last_counter,
            head,
        })
    }

    pub fn ensure_fresh_counter(&self, monotonic_counter: u64) -> Result<(), EmbeddedError> {
        if self
            .last_counter
            .is_some_and(|last| monotonic_counter <= last)
        {
            return Err(EmbeddedError::CounterRollback);
        }
        Ok(())
    }

    pub fn ensure_appendable(&self, monotonic_counter: u64) -> Result<(), EmbeddedError> {
        self.ensure_fresh_counter(monotonic_counter)?;
        if self.sequence == u64::MAX {
            return Err(EmbeddedError::SequenceExhausted);
        }
        Ok(())
    }

    pub fn ensure_checkpoint_counter(&self, monotonic_counter: u64) -> Result<(), EmbeddedError> {
        if self
            .last_counter
            .is_some_and(|last| monotonic_counter < last)
        {
            return Err(EmbeddedError::CounterRollback);
        }
        Ok(())
    }

    pub fn append(
        &mut self,
        monotonic_counter: u64,
        kind: AuditEventKind,
        component_id: Digest,
        evidence_digest: Digest,
    ) -> Result<AuditRecord, EmbeddedError> {
        self.ensure_appendable(monotonic_counter)?;
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(EmbeddedError::SequenceExhausted)?;
        let record_hash = record_hash(
            self.sequence,
            monotonic_counter,
            kind,
            &component_id,
            &evidence_digest,
            &self.head,
        );
        let record = AuditRecord {
            sequence: self.sequence,
            monotonic_counter,
            kind,
            component_id,
            evidence_digest,
            previous_hash: self.head,
            record_hash,
        };
        self.sequence = next_sequence;
        self.last_counter = Some(monotonic_counter);
        self.head = record_hash;
        Ok(record)
    }
}

fn record_hash(
    sequence: u64,
    monotonic_counter: u64,
    kind: AuditEventKind,
    component_id: &Digest,
    evidence_digest: &Digest,
    previous_hash: &Digest,
) -> Digest {
    hash_parts(&[
        AUDIT_DOMAIN,
        &FORMAT_VERSION.to_be_bytes(),
        &sequence.to_be_bytes(),
        &monotonic_counter.to_be_bytes(),
        &[kind as u8],
        component_id,
        evidence_digest,
        previous_hash,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_rejects_counter_rollback_and_detects_tampering() {
        let mut chain = AuditChain::new();
        let first = chain
            .append(10, AuditEventKind::MeasurementUpdated, [1; 32], [2; 32])
            .unwrap();
        let second = chain
            .append(11, AuditEventKind::VerificationPassed, [1; 32], [3; 32])
            .unwrap();
        assert!(first.verify(0, &[0; 32]));
        assert!(second.verify(1, &first.record_hash));
        assert_eq!(
            chain.append(11, AuditEventKind::VerificationPassed, [1; 32], [3; 32]),
            Err(EmbeddedError::CounterRollback)
        );

        let mut tampered = second;
        tampered.evidence_digest[0] ^= 1;
        assert!(!tampered.verify(1, &first.record_hash));
    }

    #[test]
    fn restore_rejects_incoherent_persisted_state() {
        assert_eq!(
            AuditChain::restore(0, Some(1), [0; 32]),
            Err(EmbeddedError::InvalidPersistedState)
        );
        assert_eq!(
            AuditChain::restore(1, None, [1; 32]),
            Err(EmbeddedError::InvalidPersistedState)
        );
        let restored = AuditChain::restore(1, Some(7), [8; 32]).unwrap();
        assert_eq!(restored.sequence(), 1);
        assert_eq!(restored.last_counter(), Some(7));
        assert_eq!(restored.head(), [8; 32]);
    }

    #[test]
    fn exhausted_sequence_rejects_append_without_wrapping() {
        let mut chain = AuditChain::restore(u64::MAX, Some(7), [8; 32]).unwrap();
        assert_eq!(
            chain.append(8, AuditEventKind::VerificationPassed, [1; 32], [2; 32]),
            Err(EmbeddedError::SequenceExhausted)
        );
        assert_eq!(chain.sequence(), u64::MAX);
        assert_eq!(chain.head(), [8; 32]);
    }
}

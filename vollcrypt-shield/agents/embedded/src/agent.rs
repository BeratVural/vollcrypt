use crate::{
    AuditChain, AuditEventKind, AuditRecord, Checkpoint, CheckpointSignError, CheckpointSigner,
    Containment, Digest, EmbeddedError, Measurement, MeasurementSet, ReleaseCommand,
    ReleaseVerifier, ScopeState, SignedCheckpoint, sign_checkpoint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedShield<const CAPACITY: usize> {
    device_id: Digest,
    measurements: MeasurementSet<CAPACITY>,
    scope: ScopeState,
    audit: AuditChain,
}

impl<const CAPACITY: usize> EmbeddedShield<CAPACITY> {
    pub const fn new(device_id: Digest, scope_id: Digest) -> Self {
        Self {
            device_id,
            measurements: MeasurementSet::new(),
            scope: ScopeState::new(scope_id),
            audit: AuditChain::new(),
        }
    }

    pub fn restore(
        device_id: Digest,
        measurements: MeasurementSet<CAPACITY>,
        scope: ScopeState,
        audit: AuditChain,
    ) -> Result<Self, EmbeddedError> {
        if scope.baseline_epoch() > 0 && audit.sequence() == 0 {
            return Err(EmbeddedError::InvalidPersistedState);
        }
        if let Some(containment) = scope.containment()
            && audit
                .last_counter()
                .is_none_or(|counter| counter < containment.since_counter)
        {
            return Err(EmbeddedError::InvalidPersistedState);
        }
        Ok(Self {
            device_id,
            measurements,
            scope,
            audit,
        })
    }

    pub const fn scope(&self) -> &ScopeState {
        &self.scope
    }

    pub const fn audit(&self) -> &AuditChain {
        &self.audit
    }

    pub const fn measurements(&self) -> &MeasurementSet<CAPACITY> {
        &self.measurements
    }

    pub fn record_measurement(
        &mut self,
        monotonic_counter: u64,
        measurement: Measurement,
    ) -> Result<AuditRecord, EmbeddedError> {
        self.audit.ensure_appendable(monotonic_counter)?;
        self.measurements.upsert(measurement)?;
        self.audit.append(
            monotonic_counter,
            AuditEventKind::MeasurementUpdated,
            measurement.component_id,
            measurement.leaf_digest(),
        )
    }

    pub fn remove_measurement(
        &mut self,
        monotonic_counter: u64,
        component_id: Digest,
    ) -> Result<AuditRecord, EmbeddedError> {
        self.audit.ensure_appendable(monotonic_counter)?;
        let removed = self.measurements.remove(&component_id)?;
        self.audit.append(
            monotonic_counter,
            AuditEventKind::MeasurementRemoved,
            component_id,
            removed.leaf_digest(),
        )
    }

    pub fn accept_current_baseline(
        &mut self,
        monotonic_counter: u64,
        epoch: u64,
    ) -> Result<AuditRecord, EmbeddedError> {
        self.audit.ensure_appendable(monotonic_counter)?;
        let root = self.measurements.root();
        self.scope.accept_baseline(epoch, root)?;
        self.audit.append(
            monotonic_counter,
            AuditEventKind::BaselineAccepted,
            self.scope.scope_id(),
            root,
        )
    }

    pub fn contain(
        &mut self,
        monotonic_counter: u64,
        reason_digest: Digest,
    ) -> Result<(Containment, AuditRecord), EmbeddedError> {
        self.audit.ensure_appendable(monotonic_counter)?;
        let containment =
            self.scope
                .contain(monotonic_counter, reason_digest, self.audit.head())?;
        let record = self.audit.append(
            monotonic_counter,
            AuditEventKind::ScopeContained,
            self.scope.scope_id(),
            containment.id,
        )?;
        Ok((containment, record))
    }

    pub fn release(
        &mut self,
        monotonic_counter: u64,
        command: &ReleaseCommand,
        signature: &[u8],
        verifier: &impl ReleaseVerifier,
    ) -> Result<AuditRecord, EmbeddedError> {
        self.audit.ensure_appendable(monotonic_counter)?;
        let containment = self
            .scope
            .containment()
            .ok_or(EmbeddedError::NotContained)?;
        self.scope
            .release(command, signature, monotonic_counter, verifier)?;
        self.audit.append(
            monotonic_counter,
            AuditEventKind::BreakGlassReleased,
            self.scope.scope_id(),
            containment.id,
        )
    }

    pub fn checkpoint(
        &self,
        monotonic_counter: u64,
        signer_key_id: Digest,
    ) -> Result<Checkpoint, EmbeddedError> {
        self.audit.ensure_checkpoint_counter(monotonic_counter)?;
        let containment = self.scope.containment();
        Ok(Checkpoint {
            device_id: self.device_id,
            scope_id: self.scope.scope_id(),
            signer_key_id,
            baseline_epoch: self.scope.baseline_epoch(),
            monotonic_counter,
            measurement_count: self.measurements.len() as u64,
            measurement_root: self.measurements.root(),
            audit_sequence: self.audit.sequence(),
            audit_head: self.audit.head(),
            containment_id: containment.map_or([0; 32], |value| value.id),
            contained: containment.is_some(),
        })
    }

    pub fn sign_checkpoint<const SIGNATURE_CAPACITY: usize, S: CheckpointSigner>(
        &self,
        monotonic_counter: u64,
        signer: &mut S,
    ) -> Result<SignedCheckpoint<SIGNATURE_CAPACITY>, CheckpointSignError<S::Error>> {
        let checkpoint = self
            .checkpoint(monotonic_counter, signer.key_id())
            .map_err(CheckpointSignError::State)?;
        sign_checkpoint(checkpoint, signer).map_err(CheckpointSignError::Signing)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{MeasurementKind, RELEASE_COMMAND_LEN};

    fn measurement(id: u8, content: u8) -> Measurement {
        Measurement::new([id; 32], MeasurementKind::Firmware, [content; 32], [9; 32])
    }

    struct TestReleaseVerifier;

    impl ReleaseVerifier for TestReleaseVerifier {
        fn verify_ml_dsa_65(&self, command: &[u8; RELEASE_COMMAND_LEN], signature: &[u8]) -> bool {
            signature == &Sha256::digest(command)[..]
        }
    }

    #[test]
    fn end_to_end_state_is_monotonic_and_scope_local() {
        let mut shield = EmbeddedShield::<2>::new([7; 32], [8; 32]);
        shield.record_measurement(1, measurement(1, 2)).unwrap();
        shield.accept_current_baseline(2, 1).unwrap();
        let (containment, _) = shield.contain(3, [4; 32]).unwrap();
        assert_eq!(
            shield.accept_current_baseline(4, 2),
            Err(EmbeddedError::ScopeContained)
        );

        let command = ReleaseCommand {
            scope_id: [8; 32],
            containment_id: containment.id,
            not_before_counter: 4,
            expires_at_counter: 6,
            nonce: [5; 32],
        };
        let signature = Sha256::digest(command.to_bytes());
        shield
            .release(5, &command, &signature, &TestReleaseVerifier)
            .unwrap();
        shield.accept_current_baseline(6, 2).unwrap();
        assert_eq!(shield.scope().baseline_epoch(), 2);
    }

    #[test]
    fn checkpoint_rejects_counter_rollback() {
        let mut shield = EmbeddedShield::<1>::new([7; 32], [8; 32]);
        shield.record_measurement(9, measurement(1, 2)).unwrap();
        assert_eq!(
            shield.checkpoint(8, [3; 32]),
            Err(EmbeddedError::CounterRollback)
        );
        assert!(shield.checkpoint(9, [3; 32]).is_ok());
    }

    #[test]
    fn audit_exhaustion_cannot_mutate_measurements() {
        let audit = AuditChain::restore(u64::MAX, Some(7), [8; 32]).unwrap();
        let mut shield = EmbeddedShield::<1>::restore(
            [1; 32],
            MeasurementSet::new(),
            ScopeState::new([2; 32]),
            audit,
        )
        .unwrap();
        assert_eq!(
            shield.record_measurement(8, measurement(3, 4)),
            Err(EmbeddedError::SequenceExhausted)
        );
        assert!(shield.measurements().is_empty());
    }
}

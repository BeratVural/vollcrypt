use crate::{Digest, EmbeddedError, hash_parts};

pub const RELEASE_COMMAND_LEN: usize = 120;

const CONTAINMENT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-EMBEDDED-CONTAINMENT-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Containment {
    pub id: Digest,
    pub reason_digest: Digest,
    pub since_counter: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseCommand {
    pub scope_id: Digest,
    pub containment_id: Digest,
    pub not_before_counter: u64,
    pub expires_at_counter: u64,
    pub nonce: Digest,
}

impl ReleaseCommand {
    pub fn to_bytes(&self) -> [u8; RELEASE_COMMAND_LEN] {
        let mut bytes = [0u8; RELEASE_COMMAND_LEN];
        bytes[..4].copy_from_slice(b"VSR1");
        bytes[4..6].copy_from_slice(&crate::FORMAT_VERSION.to_be_bytes());
        bytes[6] = crate::SIGNATURE_ALGORITHM_ML_DSA_65;
        bytes[8..40].copy_from_slice(&self.scope_id);
        bytes[40..72].copy_from_slice(&self.containment_id);
        bytes[72..80].copy_from_slice(&self.not_before_counter.to_be_bytes());
        bytes[80..88].copy_from_slice(&self.expires_at_counter.to_be_bytes());
        bytes[88..120].copy_from_slice(&self.nonce);
        bytes
    }
}

pub trait ReleaseVerifier {
    fn verify_ml_dsa_65(&self, command: &[u8; RELEASE_COMMAND_LEN], signature: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeState {
    scope_id: Digest,
    baseline_epoch: u64,
    baseline_root: Digest,
    containment: Option<Containment>,
}

impl ScopeState {
    pub const fn new(scope_id: Digest) -> Self {
        Self {
            scope_id,
            baseline_epoch: 0,
            baseline_root: [0; 32],
            containment: None,
        }
    }

    pub const fn scope_id(&self) -> Digest {
        self.scope_id
    }

    pub const fn baseline_epoch(&self) -> u64 {
        self.baseline_epoch
    }

    pub const fn baseline_root(&self) -> Digest {
        self.baseline_root
    }

    pub const fn containment(&self) -> Option<Containment> {
        self.containment
    }

    pub const fn allows_approved_change(&self) -> bool {
        self.containment.is_none()
    }

    pub fn restore(
        scope_id: Digest,
        baseline_epoch: u64,
        baseline_root: Digest,
        containment: Option<Containment>,
    ) -> Result<Self, EmbeddedError> {
        if baseline_epoch == 0 && baseline_root != [0; 32] {
            return Err(EmbeddedError::InvalidPersistedState);
        }
        Ok(Self {
            scope_id,
            baseline_epoch,
            baseline_root,
            containment,
        })
    }

    pub fn accept_baseline(&mut self, epoch: u64, root: Digest) -> Result<(), EmbeddedError> {
        if self.containment.is_some() {
            return Err(EmbeddedError::ScopeContained);
        }
        if epoch <= self.baseline_epoch {
            return Err(EmbeddedError::EpochRollback);
        }
        self.baseline_epoch = epoch;
        self.baseline_root = root;
        Ok(())
    }

    pub fn contain(
        &mut self,
        monotonic_counter: u64,
        reason_digest: Digest,
        audit_head: Digest,
    ) -> Result<Containment, EmbeddedError> {
        if self.containment.is_some() {
            return Err(EmbeddedError::AlreadyContained);
        }
        let id = hash_parts(&[
            CONTAINMENT_DOMAIN,
            &self.scope_id,
            &monotonic_counter.to_be_bytes(),
            &reason_digest,
            &audit_head,
        ]);
        let containment = Containment {
            id,
            reason_digest,
            since_counter: monotonic_counter,
        };
        self.containment = Some(containment);
        Ok(containment)
    }

    pub fn release(
        &mut self,
        command: &ReleaseCommand,
        signature: &[u8],
        current_counter: u64,
        verifier: &impl ReleaseVerifier,
    ) -> Result<(), EmbeddedError> {
        let containment = self.containment.ok_or(EmbeddedError::NotContained)?;
        if command.scope_id != self.scope_id {
            return Err(EmbeddedError::WrongScope);
        }
        if command.containment_id != containment.id {
            return Err(EmbeddedError::WrongContainment);
        }
        if current_counter < command.not_before_counter {
            return Err(EmbeddedError::ReleaseNotYetValid);
        }
        if current_counter > command.expires_at_counter {
            return Err(EmbeddedError::ReleaseExpired);
        }
        if !verifier.verify_ml_dsa_65(&command.to_bytes(), signature) {
            return Err(EmbeddedError::InvalidReleaseSignature);
        }
        self.containment = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    struct TestVerifier;

    impl ReleaseVerifier for TestVerifier {
        fn verify_ml_dsa_65(&self, command: &[u8; RELEASE_COMMAND_LEN], signature: &[u8]) -> bool {
            signature == &Sha256::digest(command)[..]
        }
    }

    #[test]
    fn release_is_scope_and_containment_bound() {
        let mut state = ScopeState::new([1; 32]);
        state.accept_baseline(1, [2; 32]).unwrap();
        let containment = state.contain(10, [3; 32], [4; 32]).unwrap();
        assert!(!state.allows_approved_change());
        assert_eq!(
            state.accept_baseline(2, [5; 32]),
            Err(EmbeddedError::ScopeContained)
        );

        let command = ReleaseCommand {
            scope_id: [1; 32],
            containment_id: containment.id,
            not_before_counter: 11,
            expires_at_counter: 12,
            nonce: [6; 32],
        };
        let signature = Sha256::digest(command.to_bytes());
        state
            .release(&command, &signature, 11, &TestVerifier)
            .unwrap();
        assert!(state.allows_approved_change());
    }
}

use crate::{Digest, FORMAT_VERSION, HASH_ALGORITHM_SHA256, SIGNATURE_ALGORITHM_ML_DSA_65};

pub const CHECKPOINT_LEN: usize = 233;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub device_id: Digest,
    pub scope_id: Digest,
    pub signer_key_id: Digest,
    pub baseline_epoch: u64,
    pub monotonic_counter: u64,
    pub measurement_count: u64,
    pub measurement_root: Digest,
    pub audit_sequence: u64,
    pub audit_head: Digest,
    pub containment_id: Digest,
    pub contained: bool,
}

impl Checkpoint {
    pub fn to_bytes(&self) -> [u8; CHECKPOINT_LEN] {
        let mut bytes = [0u8; CHECKPOINT_LEN];
        bytes[..4].copy_from_slice(b"VSE1");
        bytes[4..6].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes[6] = HASH_ALGORITHM_SHA256;
        bytes[7] = SIGNATURE_ALGORITHM_ML_DSA_65;
        bytes[8..40].copy_from_slice(&self.device_id);
        bytes[40..72].copy_from_slice(&self.scope_id);
        bytes[72..104].copy_from_slice(&self.signer_key_id);
        bytes[104..112].copy_from_slice(&self.baseline_epoch.to_be_bytes());
        bytes[112..120].copy_from_slice(&self.monotonic_counter.to_be_bytes());
        bytes[120..128].copy_from_slice(&self.measurement_count.to_be_bytes());
        bytes[128..160].copy_from_slice(&self.measurement_root);
        bytes[160..168].copy_from_slice(&self.audit_sequence.to_be_bytes());
        bytes[168..200].copy_from_slice(&self.audit_head);
        bytes[200..232].copy_from_slice(&self.containment_id);
        bytes[232] = u8::from(self.contained);
        bytes
    }
}

pub trait CheckpointSigner {
    type Error;

    fn key_id(&self) -> Digest;
    fn sign_ml_dsa_65(
        &mut self,
        checkpoint: &[u8; CHECKPOINT_LEN],
        signature: &mut [u8],
    ) -> Result<usize, Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckpointSignError<E> {
    State(crate::EmbeddedError),
    Signing(SigningError<E>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SigningError<E> {
    Signer(E),
    SignatureBufferTooSmall,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint<const SIGNATURE_CAPACITY: usize> {
    pub checkpoint: [u8; CHECKPOINT_LEN],
    signature: [u8; SIGNATURE_CAPACITY],
    signature_len: usize,
}

impl<const SIGNATURE_CAPACITY: usize> SignedCheckpoint<SIGNATURE_CAPACITY> {
    pub fn signature(&self) -> &[u8] {
        &self.signature[..self.signature_len]
    }
}

pub fn sign_checkpoint<const SIGNATURE_CAPACITY: usize, S: CheckpointSigner>(
    checkpoint: Checkpoint,
    signer: &mut S,
) -> Result<SignedCheckpoint<SIGNATURE_CAPACITY>, SigningError<S::Error>> {
    let checkpoint = checkpoint.to_bytes();
    let mut signature = [0u8; SIGNATURE_CAPACITY];
    let signature_len = signer
        .sign_ml_dsa_65(&checkpoint, &mut signature)
        .map_err(SigningError::Signer)?;
    if signature_len > SIGNATURE_CAPACITY {
        return Err(SigningError::SignatureBufferTooSmall);
    }
    Ok(SignedCheckpoint {
        checkpoint,
        signature,
        signature_len,
    })
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    struct TestSigner;

    impl CheckpointSigner for TestSigner {
        type Error = ();

        fn key_id(&self) -> Digest {
            [6; 32]
        }

        fn sign_ml_dsa_65(
            &mut self,
            checkpoint: &[u8; CHECKPOINT_LEN],
            signature: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let digest = Sha256::digest(checkpoint);
            signature[..digest.len()].copy_from_slice(&digest);
            Ok(digest.len())
        }
    }

    #[test]
    fn checkpoint_has_fixed_versioned_encoding_and_external_signer() {
        let checkpoint = Checkpoint {
            device_id: [1; 32],
            scope_id: [2; 32],
            signer_key_id: [6; 32],
            baseline_epoch: 3,
            monotonic_counter: 4,
            measurement_count: 5,
            measurement_root: [7; 32],
            audit_sequence: 8,
            audit_head: [9; 32],
            containment_id: [0; 32],
            contained: false,
        };
        let mut signer = TestSigner;
        let signed = sign_checkpoint::<64, _>(checkpoint, &mut signer).unwrap();
        assert_eq!(&signed.checkpoint[..4], b"VSE1");
        assert_eq!(signed.signature().len(), 32);
        assert_eq!(signed.signature(), &Sha256::digest(signed.checkpoint)[..]);
    }
}

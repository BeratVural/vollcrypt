use getrandom::SysRng;
use ml_dsa::signature::Keypair;
use ml_dsa::{Generate, MlDsa65, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Result, ShieldError};

pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1_952;
pub const ML_DSA_65_SECRET_SEED_SIZE: usize = 32;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3_309;

const KEY_ID_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-KEY-ID-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65PublicKey(Vec<u8>);

impl MlDsa65PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
            return Err(ShieldError::InvalidSignatureMaterial);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn key_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(KEY_ID_DOMAIN);
        hasher.update(&self.0);
        hasher.finalize().into()
    }

    pub fn verify(&self, message: &[u8], signature: &MlDsa65Signature) -> Result<()> {
        self.verify_with_context(message, &[], signature)
    }

    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &MlDsa65Signature,
    ) -> Result<()> {
        let encoded_key = hybrid_array::Array::try_from(self.0.as_slice())
            .map_err(|_| ShieldError::InvalidSignatureMaterial)?;
        let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_key);
        let encoded_signature = hybrid_array::Array::try_from(signature.0.as_slice())
            .map_err(|_| ShieldError::InvalidSignatureMaterial)?;
        let signature = Signature::<MlDsa65>::decode(&encoded_signature)
            .ok_or(ShieldError::InvalidSignatureMaterial)?;
        if verifying_key.verify_with_context(message, context, &signature) {
            Ok(())
        } else {
            Err(ShieldError::SignatureVerification)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65Signature(Vec<u8>);

impl MlDsa65Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(ShieldError::InvalidSignatureMaterial);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone)]
pub struct MlDsa65SecretKey([u8; ML_DSA_65_SECRET_SEED_SIZE]);

impl MlDsa65SecretKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; ML_DSA_65_SECRET_SEED_SIZE] = seed
            .try_into()
            .map_err(|_| ShieldError::InvalidSignatureMaterial)?;
        Ok(Self(seed))
    }

    pub fn expose_seed(&self) -> &[u8; ML_DSA_65_SECRET_SEED_SIZE] {
        &self.0
    }

    pub fn public_key(&self) -> Result<MlDsa65PublicKey> {
        let signing_key = self.signing_key()?;
        Ok(MlDsa65PublicKey(
            signing_key.verifying_key().encode().as_slice().to_vec(),
        ))
    }

    pub fn sign(&self, message: &[u8]) -> Result<MlDsa65Signature> {
        self.sign_with_context(message, &[])
    }

    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<MlDsa65Signature> {
        let signing_key = self.signing_key()?;
        let mut rng = SysRng;
        let signature = signing_key
            .expanded_key()
            .sign_randomized(message, context, &mut rng)
            .map_err(|_| ShieldError::SignatureOperation)?;
        Ok(MlDsa65Signature(signature.encode().as_slice().to_vec()))
    }

    fn signing_key(&self) -> Result<SigningKey<MlDsa65>> {
        let seed = hybrid_array::Array::try_from(self.0.as_slice())
            .map_err(|_| ShieldError::InvalidSignatureMaterial)?;
        Ok(SigningKey::<MlDsa65>::from_seed(&seed))
    }
}

impl Drop for MlDsa65SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct MlDsa65KeyPair {
    pub public: MlDsa65PublicKey,
    pub secret: MlDsa65SecretKey,
}

impl MlDsa65KeyPair {
    pub fn generate() -> Result<Self> {
        let mut rng = SysRng;
        let signing_key = SigningKey::<MlDsa65>::try_generate_from_rng(&mut rng)
            .map_err(|_| ShieldError::SignatureOperation)?;
        let public = MlDsa65PublicKey(signing_key.verifying_key().encode().as_slice().to_vec());
        let mut seed = [0u8; ML_DSA_65_SECRET_SEED_SIZE];
        seed.copy_from_slice(signing_key.to_seed().as_slice());
        Ok(Self {
            public,
            secret: MlDsa65SecretKey(seed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_and_reject_tampering() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let signature = pair.secret.sign(b"baseline").unwrap();
        pair.public.verify(b"baseline", &signature).unwrap();
        assert!(pair.public.verify(b"changed", &signature).is_err());
    }

    #[test]
    fn public_key_round_trip_preserves_key_id() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let decoded = MlDsa65PublicKey::from_bytes(pair.public.as_bytes()).unwrap();
        assert_eq!(pair.public.key_id(), decoded.key_id());
    }

    #[test]
    fn signature_contexts_are_domain_separated() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let signature = pair
            .secret
            .sign_with_context(b"payload", b"Vollcrypt Shield Test A")
            .unwrap();
        pair.public
            .verify_with_context(b"payload", b"Vollcrypt Shield Test A", &signature)
            .unwrap();
        assert!(
            pair.public
                .verify_with_context(b"payload", b"Vollcrypt Shield Test B", &signature)
                .is_err()
        );
        assert!(pair.public.verify(b"payload", &signature).is_err());
    }
}

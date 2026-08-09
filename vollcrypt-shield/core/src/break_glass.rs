use minicbor::{Decode, Encode};
use subtle::ConstantTimeEq;

use crate::algorithm::FORMAT_VERSION;
use crate::crypto::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
use crate::error::{Result, ShieldError};

const BREAK_GLASS_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Break Glass v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum BreakGlassAction {
    #[n(1)]
    ReleaseContainment = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct BreakGlassCommand {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub scope_id: String,
    #[n(2)]
    pub nonce: [u8; 32],
    #[n(3)]
    pub issued_at_unix_ms: u64,
    #[n(4)]
    pub expires_at_unix_ms: u64,
    #[n(5)]
    pub action: BreakGlassAction,
}

impl BreakGlassCommand {
    pub fn release(
        scope_id: impl Into<String>,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self> {
        if expires_at_unix_ms <= issued_at_unix_ms
            || expires_at_unix_ms - issued_at_unix_ms > 86_400_000
        {
            return Err(ShieldError::InvalidPolicy(
                "break-glass validity must be greater than zero and at most 24 hours".to_owned(),
            ));
        }
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ShieldError::SignatureOperation)?;
        Ok(Self {
            version: FORMAT_VERSION,
            scope_id: scope_id.into(),
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            action: BreakGlassAction::ReleaseContainment,
        })
    }

    fn to_cbor(&self) -> Result<Vec<u8>> {
        minicbor::to_vec(self).map_err(|error| ShieldError::CborEncode(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedBreakGlassCommand {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    signer_key_id: [u8; 32],
    #[n(2)]
    signature: Vec<u8>,
}

impl SignedBreakGlassCommand {
    pub fn sign(command: &BreakGlassCommand, secret: &MlDsa65SecretKey) -> Result<Self> {
        if command.version != FORMAT_VERSION {
            return Err(ShieldError::UnsupportedVersion(command.version));
        }
        let payload = command.to_cbor()?;
        let public = secret.public_key()?;
        let signature = secret.sign_with_context(&payload, BREAK_GLASS_SIGNATURE_CONTEXT)?;
        Ok(Self {
            payload,
            signer_key_id: public.key_id(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(
        &self,
        trusted_key: &MlDsa65PublicKey,
        expected_scope: &str,
        now_unix_ms: u64,
    ) -> Result<BreakGlassCommand> {
        if !bool::from(self.signer_key_id.ct_eq(&trusted_key.key_id())) {
            return Err(ShieldError::SignatureVerification);
        }
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        trusted_key.verify_with_context(
            &self.payload,
            BREAK_GLASS_SIGNATURE_CONTEXT,
            &signature,
        )?;
        let mut decoder = minicbor::Decoder::new(&self.payload);
        let command = decoder
            .decode::<BreakGlassCommand>()
            .map_err(|error| ShieldError::CborDecode(error.to_string()))?;
        if decoder.position() != self.payload.len() {
            return Err(ShieldError::CborDecode(
                "trailing bytes after break-glass command".to_owned(),
            ));
        }
        if command.version != FORMAT_VERSION {
            return Err(ShieldError::UnsupportedVersion(command.version));
        }
        if command.scope_id != expected_scope
            || now_unix_ms < command.issued_at_unix_ms
            || now_unix_ms > command.expires_at_unix_ms
        {
            return Err(ShieldError::InvalidPolicy(
                "break-glass scope or validity window is invalid".to_owned(),
            ));
        }
        Ok(command)
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
                "trailing bytes after signed break-glass command".to_owned(),
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MlDsa65KeyPair;

    #[test]
    fn command_is_scope_bound_and_expires() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let command = BreakGlassCommand::release("scope-a", 1_000, 2_000).unwrap();
        let signed = SignedBreakGlassCommand::sign(&command, &pair.secret).unwrap();
        signed.verify(&pair.public, "scope-a", 1_500).unwrap();
        assert!(signed.verify(&pair.public, "scope-b", 1_500).is_err());
        assert!(signed.verify(&pair.public, "scope-a", 2_001).is_err());
    }
}

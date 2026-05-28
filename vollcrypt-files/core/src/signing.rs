use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::error::FileFormatError;

/// Generates a new Ed25519 keypair (public_key, secret_key).
pub fn ed25519_keypair_generate() -> ([u8; 32], [u8; 32]) {
    use rand::RngCore;
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();

    let pk = verifying_key.to_bytes();
    let sk = signing_key.to_bytes();

    let result = (pk, sk);
    // Zeroize the local copy of the secret key to prevent key leakage.
    sk_bytes.zeroize();

    result
}

/// Signs a message using an Ed25519 secret key.
pub fn ed25519_sign(sk: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(sk);
    let signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verifies an Ed25519 signature against a public key and message.
pub fn ed25519_verify(
    pk: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), FileFormatError> {
    let verifying_key =
        VerifyingKey::from_bytes(pk).map_err(|_| FileFormatError::SignatureInvalid)?;
    let sig = Signature::from_bytes(signature);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| FileFormatError::SignatureInvalid)
}

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Generates a new Ed25519 Signing Key (Identity Key) securely.
pub fn generate_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

/// Generates a new X25519 Static Secret (for ECDH Key Exchange).
pub fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let csprng = OsRng;
    let secret = StaticSecret::random_from_rng(csprng);
    let public = X25519PublicKey::from(&secret);

    (secret.to_bytes().to_vec(), public.as_bytes().to_vec())
}

/// Signs a message using an Ed25519 Secret Key (32 bytes).
pub fn sign_message(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, &'static str> {
    if secret_key_bytes.len() != 32 {
        log::error!("sign_message: Invalid secret key length (expected 32, got {})", secret_key_bytes.len());
        return Err("Invalid secret key length");
    }
    
    log::debug!("sign_message: Signing message of length {}", message.len());

    // We expect a 32-byte secret seed to reconstruct the SigningKey
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(secret_key_bytes);

    let signing_key = SigningKey::from_bytes(&sk_bytes);

    let signature = signing_key.sign(message);
    sk_bytes.zeroize();

    Ok(signature.to_bytes().to_vec())
}

/// Verifies an Ed25519 signature given the public key and message.
pub fn verify_signature(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
        log::error!("verify_signature: Invalid key or signature length");
        return false;
    }

    log::debug!("verify_signature: Verifying signature against message of length {}", message.len());

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public_key_bytes);

    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig = match Signature::from_slice(signature_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify_strict(message, &sig).is_ok()
}

/// Performs ECDH Key Exchange using X25519 returning a Shared Secret.
pub fn ecdh_shared_secret(
    our_secret_bytes: &[u8],
    their_public_bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if our_secret_bytes.len() != 32 || their_public_bytes.len() != 32 {
        log::error!("ecdh_shared_secret: Invalid key length");
        return Err("Invalid key length");
    }
    
    log::debug!("ecdh_shared_secret: Computing shared secret");

    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(our_secret_bytes);
    let secret = StaticSecret::from(secret_arr);

    let mut public_arr = [0u8; 32];
    public_arr.copy_from_slice(their_public_bytes);
    let public = X25519PublicKey::from(public_arr);

    let shared_secret = secret.diffie_hellman(&public);

    secret_arr.zeroize();

    // Derived with HKDF immediately as best practice? Or return raw shared secret.
    // Returning raw shared secret here for maximum flexibility. Let the higher layer do KDF.
    Ok(shared_secret.as_bytes().to_vec())
}

/// Performs ECDH Key Exchange and derives a key using HKDF.
pub fn ecdh_derive_key(
    our_secret: &[u8],
    their_public: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut raw_secret = ecdh_shared_secret(our_secret, their_public)?;
    let result = crate::kdf::derive_hkdf(&raw_secret, salt, Some(info), key_len);
    raw_secret.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let (sk, pk) = generate_ed25519_keypair();
        let message = b"Hello VollChat!";

        let signature = sign_message(&sk, message).unwrap();
        assert!(verify_signature(&pk, message, &signature));

        let bad_message = b"Hello Hacker!";
        assert!(!verify_signature(&pk, bad_message, &signature));
    }

    #[test]
    fn test_x25519_ecdh() {
        let (alice_sk, alice_pk) = generate_x25519_keypair();
        let (bob_sk, bob_pk) = generate_x25519_keypair();

        let alice_shared = ecdh_shared_secret(&alice_sk, &bob_pk).unwrap();
        let bob_shared = ecdh_shared_secret(&bob_sk, &alice_pk).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }
}

// Post-Quantum Cryptography (Phase 6)
// FIPS 203: ML-KEM-768 (Module Lattice-based Key Encapsulation Mechanism)
// Hybrid KEM: X25519 + ML-KEM combined via HKDF for quantum-resistant key exchange

use ml_kem::{MlKem768, KemCore, EncodedSizeUser};
use ml_kem::kem::{Encapsulate, Decapsulate};
use rand::rngs::OsRng;
use crate::kdf::derive_hkdf;

// ==================== ML-KEM Primitives ====================

/// Generates an ML-KEM-768 keypair.
/// Returns (decapsulation_key_bytes, encapsulation_key_bytes).
pub fn ml_kem_keygen() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let dk_bytes: Vec<u8> = dk.as_bytes().to_vec();
    let ek_bytes: Vec<u8> = ek.as_bytes().to_vec();
    (dk_bytes, ek_bytes)
}

/// Encapsulates a shared secret using the recipient's encapsulation key.
/// Returns (ciphertext_bytes, shared_secret_32bytes).
pub fn ml_kem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    use ml_kem::EncodedSizeUser;

    type EK = <MlKem768 as KemCore>::EncapsulationKey;
    let ek_encoded = <EK as EncodedSizeUser>::EncodedSize::default();
    let _ = ek_encoded; // just for type inference

    // Try to build the encapsulation key from raw bytes
    let ek_array = ml_kem::array::Array::try_from(ek_bytes)
        .map_err(|_| {
            log::error!("ml_kem_encapsulate: Invalid encapsulation key length");
            "Invalid encapsulation key length"
        })?;
    let ek = <EK as EncodedSizeUser>::from_bytes(&ek_array);

    log::debug!("ml_kem_encapsulate: Encapsulating shared secret");
    let (ct, shared_secret): (ml_kem::Ciphertext<MlKem768>, ml_kem::SharedKey<MlKem768>) = 
        ek.encapsulate(&mut OsRng)
            .map_err(|_| {
                log::error!("ml_kem_encapsulate: ML-KEM encapsulation failed");
                "ML-KEM encapsulation failed"
            })?;

    Ok((ct.as_slice().to_vec(), shared_secret.as_slice().to_vec()))
}

/// Decapsulates a ciphertext using the decapsulation key (private key).
/// Returns the shared_secret (32 bytes).
pub fn ml_kem_decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    use ml_kem::EncodedSizeUser;

    type DK = <MlKem768 as KemCore>::DecapsulationKey;
    type CT = ml_kem::Ciphertext<MlKem768>;

    let dk_array = ml_kem::array::Array::try_from(dk_bytes)
        .map_err(|_| {
            log::error!("ml_kem_decapsulate: Invalid decapsulation key length");
            "Invalid decapsulation key length"
        })?;
    let dk = <DK as EncodedSizeUser>::from_bytes(&dk_array);

    let ct = CT::try_from(ct_bytes)
        .map_err(|_| {
            log::error!("ml_kem_decapsulate: Invalid ciphertext length");
            "Invalid ciphertext length"
        })?;

    log::debug!("ml_kem_decapsulate: Decapsulating ciphertext");
    let shared_secret: ml_kem::SharedKey<MlKem768> = dk.decapsulate(&ct)
        .map_err(|_| {
            log::error!("ml_kem_decapsulate: ML-KEM decapsulation failed");
            "ML-KEM decapsulation failed"
        })?;

    Ok(shared_secret.as_slice().to_vec())
}

// ==================== Hybrid KEM (X25519 + ML-KEM) ====================

/// Hybrid KEM Encapsulation: combines X25519 ECDH and ML-KEM-768
/// to derive a single quantum-resistant shared key.
///
/// Returns: (hybrid_shared_key_32bytes, ml_kem_ciphertext)
pub fn hybrid_kem_encapsulate(
    x25519_our_secret: &[u8],
    x25519_their_public: &[u8],
    ml_kem_ek_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    log::debug!("hybrid_kem_encapsulate: Starting hybrid encapsulation");
    
    // Step 1: X25519 ECDH shared secret
    let x25519_shared = crate::ecdh_shared_secret(x25519_our_secret, x25519_their_public)?;

    // Step 2: ML-KEM encapsulation
    let (ml_kem_ct, ml_kem_shared) = ml_kem_encapsulate(ml_kem_ek_bytes)?;

    // Step 3: Combine both shared secrets via HKDF
    let mut combined_ikm = Vec::with_capacity(x25519_shared.len() + ml_kem_shared.len());
    combined_ikm.extend_from_slice(&x25519_shared);
    combined_ikm.extend_from_slice(&ml_kem_shared);

    let hybrid_key = derive_hkdf(
        &combined_ikm,
        None,
        Some(b"vollchat-hybrid-kem-v1"),
        32,
    )?;

    Ok((hybrid_key, ml_kem_ct))
}

/// Hybrid KEM Decapsulation: reverse of hybrid_kem_encapsulate.
///
/// Returns: hybrid_shared_key_32bytes (must match encapsulator's key)
pub fn hybrid_kem_decapsulate(
    x25519_our_secret: &[u8],
    x25519_their_public: &[u8],
    ml_kem_dk_bytes: &[u8],
    ml_kem_ct_bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    log::debug!("hybrid_kem_decapsulate: Starting hybrid decapsulation");
    
    // Step 1: X25519 ECDH shared secret
    let x25519_shared = crate::ecdh_shared_secret(x25519_our_secret, x25519_their_public)?;

    // Step 2: ML-KEM decapsulation
    let ml_kem_shared = ml_kem_decapsulate(ml_kem_dk_bytes, ml_kem_ct_bytes)?;

    // Step 3: Combine both shared secrets via HKDF
    let mut combined_ikm = Vec::with_capacity(x25519_shared.len() + ml_kem_shared.len());
    combined_ikm.extend_from_slice(&x25519_shared);
    combined_ikm.extend_from_slice(&ml_kem_shared);

    let hybrid_key = derive_hkdf(
        &combined_ikm,
        None,
        Some(b"vollchat-hybrid-kem-v1"),
        32,
    )?;

    Ok(hybrid_key)
}

// ==================== Authenticated Hybrid KEM ====================

/// Authenticated hybrid KEM encapsulation.
///
/// Executes the standard hybrid_kem_encapsulate and signs the resulting
/// ciphertext with the sender's Ed25519 Identity Key. This ensures the
/// recipient can verify the ciphertext originated from the claimed sender
/// and protects against MITM tampering.
///
/// # Returns
/// `(authenticated_ciphertext, shared_secret)`
///
/// `authenticated_ciphertext` format:
/// [2 bytes: kem_ct length (big-endian u16)]
/// [kem_ct_len bytes: KEM ciphertext]
/// [64 bytes: Ed25519 signature over kem_ct]
pub fn authenticated_kem_encapsulate(
    x25519_our_secret: &[u8],
    x25519_their_public: &[u8],
    ml_kem_ek_bytes: &[u8],
    sender_identity_sk: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // 1. hybrid_kem_encapsulate
    let (hybrid_shared_key, kem_ct) = hybrid_kem_encapsulate(
        x25519_our_secret,
        x25519_their_public,
        ml_kem_ek_bytes,
    )?;

    // 2. Compute Ed25519 signature over the ciphertext
    let signature = crate::keys::sign_message(sender_identity_sk, &kem_ct)?;
    if signature.len() != 64 {
        return Err("Signing failed: invalid signature length");
    }

    // 3. Pack the authenticated ciphertext
    let kem_ct_len = kem_ct.len() as u16;
    let mut auth_ct = Vec::with_capacity(2 + kem_ct.len() + 64);
    auth_ct.extend_from_slice(&kem_ct_len.to_be_bytes());
    auth_ct.extend_from_slice(&kem_ct);
    auth_ct.extend_from_slice(&signature);

    Ok((auth_ct, hybrid_shared_key))
}

/// Authenticated hybrid KEM decapsulation.
///
/// First verifies the Ed25519 signature before attempting to decapsulate
/// the KEM ciphertext. Fails fast if the signature is invalid.
pub fn authenticated_kem_decapsulate(
    x25519_our_secret: &[u8],
    x25519_their_public: &[u8],
    ml_kem_dk_bytes: &[u8],
    authenticated_ciphertext: &[u8],
    sender_identity_pk: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if authenticated_ciphertext.len() < 2 + 64 {
        log::error!("authenticated_kem_decapsulate: Invalid ciphertext format (too short)");
        return Err("Invalid authenticated ciphertext format");
    }

    // 1. Parse lengths
    let kem_ct_len = u16::from_be_bytes([authenticated_ciphertext[0], authenticated_ciphertext[1]]) as usize;
    if authenticated_ciphertext.len() != 2 + kem_ct_len + 64 {
        log::error!("authenticated_kem_decapsulate: Invalid ciphertext format (length mismatch)");
        return Err("Invalid authenticated ciphertext format");
    }

    let kem_ct = &authenticated_ciphertext[2..2 + kem_ct_len];
    let signature = &authenticated_ciphertext[2 + kem_ct_len..];

    // 2. Verify signature BEFORE decapsulating
    if !crate::keys::verify_signature(sender_identity_pk, kem_ct, signature) {
        log::error!("authenticated_kem_decapsulate: Authentication failed - signature mismatch");
        return Err("Authentication failed");
    }

    // 3. Decapsulate
    hybrid_kem_decapsulate(
        x25519_our_secret,
        x25519_their_public,
        ml_kem_dk_bytes,
        kem_ct,
    )
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_x25519_keypair;

    #[test]
    fn test_ml_kem_round_trip() {
        let (dk, ek) = ml_kem_keygen();
        let (ct, shared_enc) = ml_kem_encapsulate(&ek).unwrap();
        let shared_dec = ml_kem_decapsulate(&dk, &ct).unwrap();
        assert_eq!(shared_enc, shared_dec);
        assert_eq!(shared_enc.len(), 32);
    }

    #[test]
    fn test_ml_kem_invalid_key() {
        let result = ml_kem_encapsulate(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_kem_round_trip() {
        let (sender_secret, sender_public) = generate_x25519_keypair();
        let (recipient_secret, recipient_public) = generate_x25519_keypair();
        let (ml_kem_dk, ml_kem_ek) = ml_kem_keygen();

        let (shared_enc, ml_kem_ct) = hybrid_kem_encapsulate(
            &sender_secret,
            &recipient_public,
            &ml_kem_ek,
        ).unwrap();

        let shared_dec = hybrid_kem_decapsulate(
            &recipient_secret,
            &sender_public,
            &ml_kem_dk,
            &ml_kem_ct,
        ).unwrap();

        assert_eq!(shared_enc, shared_dec);
        assert_eq!(shared_enc.len(), 32);
    }

    #[test]
    fn test_hybrid_kem_wrong_classical_key() {
        let (sender_secret, sender_public) = generate_x25519_keypair();
        let (_recipient_secret, recipient_public) = generate_x25519_keypair();
        let (ml_kem_dk, ml_kem_ek) = ml_kem_keygen();

        let (shared_enc, ml_kem_ct) = hybrid_kem_encapsulate(
            &sender_secret,
            &recipient_public,
            &ml_kem_ek,
        ).unwrap();

        // Use a wrong X25519 key for decapsulation
        let (wrong_secret, _wrong_public) = generate_x25519_keypair();
        let shared_dec = hybrid_kem_decapsulate(
            &wrong_secret,
            &sender_public,
            &ml_kem_dk,
            &ml_kem_ct,
        ).unwrap();

        // Hybrid key should NOT match when classical key is wrong
        assert_ne!(shared_enc, shared_dec);
    }

    #[test]
    fn test_authenticated_kem_roundtrip() {
        let (alice_identity_sk, alice_identity_pk) = crate::keys::generate_ed25519_keypair();
        
        // Alice sending to Bob
        let (alice_x25519_sk, alice_x25519_pk) = generate_x25519_keypair();
        let (bob_x25519_sk, bob_x25519_pk) = generate_x25519_keypair();
        let (bob_mlkem_dk, bob_mlkem_ek) = ml_kem_keygen();

        // Alice encapsulates and signs
        let (auth_ct, alice_shared) = authenticated_kem_encapsulate(
            &alice_x25519_sk,
            &bob_x25519_pk,
            &bob_mlkem_ek,
            &alice_identity_sk,
        ).unwrap();

        // Bob verifies and decapsulates
        let bob_shared = authenticated_kem_decapsulate(
            &bob_x25519_sk,
            &alice_x25519_pk,
            &bob_mlkem_dk,
            &auth_ct,
            &alice_identity_pk,
        ).unwrap();

        assert_eq!(alice_shared, bob_shared, "Alice and Bob must compute the same shared secret");
    }

    #[test]
    fn test_authenticated_kem_rejects_wrong_identity() {
        let (_alice_identity_sk, alice_identity_pk) = crate::keys::generate_ed25519_keypair();
        let (mallory_identity_sk, _) = crate::keys::generate_ed25519_keypair();

        let (alice_x25519_sk, alice_x25519_pk) = generate_x25519_keypair();
        let (bob_x25519_sk, bob_x25519_pk) = generate_x25519_keypair();
        let (bob_mlkem_dk, bob_mlkem_ek) = ml_kem_keygen();

        // Mallory encrypts and signs using Mallory's identity key, spoofing Alice
        let (auth_ct, _) = authenticated_kem_encapsulate(
            &alice_x25519_sk,
            &bob_x25519_pk,
            &bob_mlkem_ek,
            &mallory_identity_sk,
        ).unwrap();

        // Bob attempts to decapsulate, checking against Alice's identity
        let result = authenticated_kem_decapsulate(
            &bob_x25519_sk,
            &alice_x25519_pk,
            &bob_mlkem_dk,
            &auth_ct,
            &alice_identity_pk,
        );

        assert!(result.is_err(), "Must reject invalid signature");
        assert_eq!(result.unwrap_err(), "Authentication failed");
    }

    #[test]
    fn test_authenticated_kem_rejects_tampered_ciphertext() {
        let (alice_identity_sk, alice_identity_pk) = crate::keys::generate_ed25519_keypair();
        let (alice_x25519_sk, alice_x25519_pk) = generate_x25519_keypair();
        let (bob_x25519_sk, bob_x25519_pk) = generate_x25519_keypair();
        let (bob_mlkem_dk, bob_mlkem_ek) = ml_kem_keygen();

        let (mut auth_ct, _) = authenticated_kem_encapsulate(
            &alice_x25519_sk,
            &bob_x25519_pk,
            &bob_mlkem_ek,
            &alice_identity_sk,
        ).unwrap();

        // Tamper with the ciphertext (e.g., flip a byte in the KEM CT)
        let mid = auth_ct.len() / 2;
        auth_ct[mid] ^= 0xFF;

        let result = authenticated_kem_decapsulate(
            &bob_x25519_sk,
            &alice_x25519_pk,
            &bob_mlkem_dk,
            &auth_ct,
            &alice_identity_pk,
        );

        assert!(result.is_err(), "Must reject tampered ciphertext");
        assert_eq!(result.unwrap_err(), "Authentication failed");
    }

    #[test]
    fn test_authenticated_kem_rejects_truncated_ciphertext() {
        let (alice_identity_sk, alice_identity_pk) = crate::keys::generate_ed25519_keypair();
        let (alice_x25519_sk, alice_x25519_pk) = generate_x25519_keypair();
        let (bob_x25519_sk, bob_x25519_pk) = generate_x25519_keypair();
        let (bob_mlkem_dk, bob_mlkem_ek) = ml_kem_keygen();

        let (auth_ct, _) = authenticated_kem_encapsulate(
            &alice_x25519_sk,
            &bob_x25519_pk,
            &bob_mlkem_ek,
            &alice_identity_sk,
        ).unwrap();

        let truncated = &auth_ct[..auth_ct.len() / 2];

        let result = authenticated_kem_decapsulate(
            &bob_x25519_sk,
            &alice_x25519_pk,
            &bob_mlkem_dk,
            truncated,
            &alice_identity_pk,
        );

        assert!(result.is_err(), "Must reject truncated ciphertext");
        assert_eq!(result.unwrap_err(), "Invalid authenticated ciphertext format");
    }

    #[test]
    fn test_authenticated_ciphertext_format() {
        let (alice_identity_sk, _) = crate::keys::generate_ed25519_keypair();
        let (alice_x25519_sk, _) = generate_x25519_keypair();
        let (_, bob_x25519_pk) = generate_x25519_keypair();
        let (_, bob_mlkem_ek) = ml_kem_keygen();

        let (auth_ct, _) = authenticated_kem_encapsulate(
            &alice_x25519_sk,
            &bob_x25519_pk,
            &bob_mlkem_ek,
            &alice_identity_sk,
        ).unwrap();

        assert!(auth_ct.len() > 66, "Ciphertext is too short");

        // The first 2 bytes must specify the kem_ct length
        let kem_ct_len = u16::from_be_bytes([auth_ct[0], auth_ct[1]]) as usize;
        assert_eq!(auth_ct.len(), 2 + kem_ct_len + 64, "Total length must match 2 + kem_ct_len + 64 byte signature");
    }
}

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
}

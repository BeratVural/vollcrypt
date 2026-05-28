use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Generates a new X25519 keypair.
///
/// Returns `(public_key_bytes, secret_key_bytes)`.
pub fn x25519_keypair_generate() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (public.to_bytes(), secret.to_bytes())
}

/// Performs Diffie-Hellman key agreement using X25519.
///
/// Returns a 32-byte shared secret. Securely zeroizes the local copy of the secret key.
pub fn x25519_diffie_hellman(my_sk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
    let mut my_sk_copy = *my_sk;
    let secret = StaticSecret::from(my_sk_copy);
    my_sk_copy.zeroize();

    let public = X25519PublicKey::from(*their_pk);
    let shared = secret.diffie_hellman(&public);

    shared.to_bytes()
}

/// Generates a new ML-KEM-768 keypair.
///
/// Returns `(encapsulation_key_bytes, decapsulation_key_bytes)`.
pub fn mlkem768_keypair_generate() -> ([u8; 1184], [u8; 2400]) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);

    let mut ek_bytes = [0u8; 1184];
    ek_bytes.copy_from_slice(ek.as_bytes().as_slice());

    let mut dk_bytes = [0u8; 2400];
    dk_bytes.copy_from_slice(dk.as_bytes().as_slice());

    (ek_bytes, dk_bytes)
}

/// Encapsulates a shared secret using the recipient's ML-KEM-768 encapsulation key.
///
/// Returns `(shared_secret, ciphertext)`.
pub fn mlkem768_encapsulate(pk: &[u8; 1184]) -> ([u8; 32], [u8; 1088]) {
    type EK = <MlKem768 as KemCore>::EncapsulationKey;

    let mut shared_secret = [0u8; 32];
    let mut ciphertext = [0u8; 1088];

    // Using try_from to convert input slice into the statically sized array expected by the library
    if let Ok(ek_array) = ml_kem::array::Array::try_from(pk.as_slice()) {
        let ek = <EK as EncodedSizeUser>::from_bytes(&ek_array);
        if let Ok((ct, ss)) = ek.encapsulate(&mut OsRng) {
            shared_secret.copy_from_slice(ss.as_slice());
            ciphertext.copy_from_slice(ct.as_slice());
        }
    }

    (shared_secret, ciphertext)
}

/// Decapsulates an ML-KEM-768 ciphertext using the decapsulation key.
///
/// Returns the 32-byte shared secret.
pub fn mlkem768_decapsulate(sk: &[u8; 2400], ct: &[u8; 1088]) -> [u8; 32] {
    type DK = <MlKem768 as KemCore>::DecapsulationKey;
    type CT = ml_kem::Ciphertext<MlKem768>;

    let mut shared_secret = [0u8; 32];

    if let Ok(dk_array) = ml_kem::array::Array::try_from(sk.as_slice()) {
        let dk = <DK as EncodedSizeUser>::from_bytes(&dk_array);
        if let Ok(ct_obj) = CT::try_from(ct.as_slice()) {
            if let Ok(ss) = dk.decapsulate(&ct_obj) {
                shared_secret.copy_from_slice(ss.as_slice());
            }
        }
    }

    shared_secret
}

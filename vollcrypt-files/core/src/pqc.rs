use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::constants::{
    ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_DECAPSULATION_KEY_SIZE,
    ML_KEM_768_ENCAPSULATION_KEY_SIZE,
};
use crate::error::FileFormatError;

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
pub fn x25519_diffie_hellman(
    my_sk: &[u8; 32],
    their_pk: &[u8; 32],
) -> Result<[u8; 32], FileFormatError> {
    let mut my_sk_copy = *my_sk;
    let secret = StaticSecret::from(my_sk_copy);
    my_sk_copy.zeroize();

    let public = X25519PublicKey::from(*their_pk);
    let shared = secret.diffie_hellman(&public);
    if !shared.was_contributory() {
        return Err(FileFormatError::WrongRecipientKey);
    }

    Ok(shared.to_bytes())
}

/// Generates a new ML-KEM-768 keypair.
///
/// Returns `(encapsulation_key_bytes, decapsulation_key_bytes)`.
pub fn mlkem768_keypair_generate() -> (
    [u8; ML_KEM_768_ENCAPSULATION_KEY_SIZE],
    [u8; ML_KEM_768_DECAPSULATION_KEY_SIZE],
) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);

    let mut ek_bytes = [0u8; ML_KEM_768_ENCAPSULATION_KEY_SIZE];
    ek_bytes.copy_from_slice(ek.as_bytes().as_slice());

    let mut dk_bytes = [0u8; ML_KEM_768_DECAPSULATION_KEY_SIZE];
    dk_bytes.copy_from_slice(dk.as_bytes().as_slice());

    (ek_bytes, dk_bytes)
}

/// Encapsulates a shared secret using the recipient's ML-KEM-768 encapsulation key.
///
/// Returns `(shared_secret, ciphertext)`.
pub fn mlkem768_encapsulate(
    pk: &[u8; ML_KEM_768_ENCAPSULATION_KEY_SIZE],
) -> Result<([u8; 32], [u8; ML_KEM_768_CIPHERTEXT_SIZE]), FileFormatError> {
    type EK = <MlKem768 as KemCore>::EncapsulationKey;

    let mut shared_secret = [0u8; 32];
    let mut ciphertext = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];

    let ek_array = ml_kem::array::Array::try_from(pk.as_slice())
        .map_err(|_| FileFormatError::WrongRecipientKey)?;
    let ek = <EK as EncodedSizeUser>::from_bytes(&ek_array);
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| FileFormatError::WrongRecipientKey)?;

    shared_secret.copy_from_slice(ss.as_slice());
    ciphertext.copy_from_slice(ct.as_slice());

    Ok((shared_secret, ciphertext))
}

/// Decapsulates an ML-KEM-768 ciphertext using the decapsulation key.
///
/// Returns the 32-byte shared secret.
pub fn mlkem768_decapsulate(
    sk: &[u8; ML_KEM_768_DECAPSULATION_KEY_SIZE],
    ct: &[u8; ML_KEM_768_CIPHERTEXT_SIZE],
) -> Result<[u8; 32], FileFormatError> {
    type DK = <MlKem768 as KemCore>::DecapsulationKey;
    type CT = ml_kem::Ciphertext<MlKem768>;

    let mut shared_secret = [0u8; 32];

    let dk_array = ml_kem::array::Array::try_from(sk.as_slice())
        .map_err(|_| FileFormatError::WrongRecipientKey)?;
    let dk = <DK as EncodedSizeUser>::from_bytes(&dk_array);
    let ct_obj = CT::try_from(ct.as_slice()).map_err(|_| FileFormatError::WrongRecipientKey)?;
    let ss = dk
        .decapsulate(&ct_obj)
        .map_err(|_| FileFormatError::WrongRecipientKey)?;

    shared_secret.copy_from_slice(ss.as_slice());

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_key_decapsulate() {
        let sk = [0u8; ML_KEM_768_DECAPSULATION_KEY_SIZE];
        let ct = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
        let res = mlkem768_decapsulate(&sk, &ct);
        println!("Result of zero key decapsulate: {:?}", res);
    }
}

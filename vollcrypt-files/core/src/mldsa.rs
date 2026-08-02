use crate::constants::{
    ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SECRET_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE,
};
use getrandom::SysRng;
use ml_dsa::signature::{Keypair, Verifier};
use ml_dsa::{Generate, MlDsa65, Signature, SigningKey, VerifyingKey};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65PublicKey(pub [u8; ML_DSA_65_PUBLIC_KEY_SIZE]);

#[derive(Clone)]
pub struct MlDsa65SecretKey(pub [u8; ML_DSA_65_SECRET_KEY_SIZE]);

impl Zeroize for MlDsa65SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MlDsa65SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65Signature(pub [u8; ML_DSA_65_SIGNATURE_SIZE]);

pub fn mldsa_keypair_generate() -> (MlDsa65PublicKey, MlDsa65SecretKey) {
    let mut rng = SysRng;
    let sk = SigningKey::<MlDsa65>::try_generate_from_rng(&mut rng)
        .expect("ML-DSA key generation failed");
    let pk = sk.verifying_key();

    let mut pk_bytes = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
    pk_bytes.copy_from_slice(pk.encode().as_slice());

    let mut sk_bytes = [0u8; ML_DSA_65_SECRET_KEY_SIZE];
    sk_bytes.copy_from_slice(sk.to_seed().as_slice());

    (MlDsa65PublicKey(pk_bytes), MlDsa65SecretKey(sk_bytes))
}

pub fn mldsa_sign(sk: &MlDsa65SecretKey, message: &[u8]) -> MlDsa65Signature {
    let seed =
        hybrid_array::Array::try_from(sk.0.as_slice()).expect("Invalid secret key bytes size");
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);

    let mut rng = SysRng;
    let sig = signing_key
        .expanded_key()
        .sign_randomized(message, &[], &mut rng)
        .expect("ML-DSA signature generation failed");

    let mut sig_bytes = [0u8; ML_DSA_65_SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(sig.encode().as_slice());
    MlDsa65Signature(sig_bytes)
}

pub fn mldsa_verify(pk: &MlDsa65PublicKey, message: &[u8], sig: &MlDsa65Signature) -> bool {
    let enc_pk = match hybrid_array::Array::try_from(pk.0.as_slice()) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk_obj = VerifyingKey::<MlDsa65>::decode(&enc_pk);

    let enc_sig = match hybrid_array::Array::try_from(sig.0.as_slice()) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_obj = match Signature::<MlDsa65>::decode(&enc_sig) {
        Some(s) => s,
        None => return false,
    };

    pk_obj.verify(message, &sig_obj).is_ok()
}

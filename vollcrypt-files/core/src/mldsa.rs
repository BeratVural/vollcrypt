use ml_dsa::{MlDsa65, SigningKey, VerifyingKey, Signature, ExpandedSigningKey, Generate};
use ml_dsa::signature::{Verifier, Keypair};
use zeroize::Zeroize;
use getrandom::SysRng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65PublicKey(pub [u8; 1952]);

#[derive(Clone)]
pub struct MlDsa65SecretKey(pub [u8; 4032]);

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
pub struct MlDsa65Signature(pub [u8; 3309]);

pub fn mldsa_keypair_generate() -> (MlDsa65PublicKey, MlDsa65SecretKey) {
    let sk = SigningKey::<MlDsa65>::generate();
    let esk = sk.expanded_key();
    let pk = sk.verifying_key();

    let mut pk_bytes = [0u8; 1952];
    pk_bytes.copy_from_slice(pk.encode().as_slice());

    let mut sk_bytes = [0u8; 4032];
    #[allow(deprecated)]
    sk_bytes.copy_from_slice(esk.to_expanded().as_slice());

    (MlDsa65PublicKey(pk_bytes), MlDsa65SecretKey(sk_bytes))
}

pub fn mldsa_sign(sk: &MlDsa65SecretKey, message: &[u8]) -> MlDsa65Signature {
    let enc_sk = hybrid_array::Array::try_from(sk.0.as_slice()).expect("Invalid secret key bytes size");
    #[allow(deprecated)]
    let esk = ExpandedSigningKey::<MlDsa65>::from_expanded(&enc_sk);
    
    let mut rng = SysRng;
    let sig = esk.sign_randomized(message, &[], &mut rng).expect("ML-DSA signature generation failed");
    
    let mut sig_bytes = [0u8; 3309];
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

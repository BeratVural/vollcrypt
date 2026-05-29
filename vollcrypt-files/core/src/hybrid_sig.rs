use zeroize::Zeroize;
use crate::error::FileFormatError;
use crate::mldsa::{mldsa_keypair_generate, mldsa_sign, mldsa_verify, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
use crate::signing::{ed25519_keypair_generate, ed25519_sign, ed25519_verify};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub ed25519: [u8; 32],
    pub mldsa: [u8; 1952],
}

impl subtle::ConstantTimeEq for HybridPublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.ed25519.as_slice().ct_eq(other.ed25519.as_slice())
            & self.mldsa.as_slice().ct_eq(other.mldsa.as_slice())
    }
}

#[derive(Clone)]
pub struct HybridSecretKey {
    pub ed25519: [u8; 32],
    pub mldsa: [u8; 4032],
}

impl Zeroize for HybridSecretKey {
    fn zeroize(&mut self) {
        self.ed25519.zeroize();
        self.mldsa.zeroize();
    }
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    pub ed25519: [u8; 64],
    pub mldsa: Vec<u8>,
}

pub fn hybrid_keypair_generate() -> (HybridPublicKey, HybridSecretKey) {
    let (ed_pk, ed_sk) = ed25519_keypair_generate();
    let (mldsa_pk, mldsa_sk) = mldsa_keypair_generate();

    let pk = HybridPublicKey {
        ed25519: ed_pk,
        mldsa: mldsa_pk.0,
    };

    let sk = HybridSecretKey {
        ed25519: ed_sk,
        mldsa: mldsa_sk.0,
    };

    (pk, sk)
}

pub fn hybrid_sign(
    sk: &HybridSecretKey,
    pk: &HybridPublicKey,
    domain: &str,
    context: &[u8],
    payload: &[u8],
) -> HybridSignature {
    let mut msg_prime = Vec::new();
    msg_prime.extend_from_slice(domain.as_bytes());
    msg_prime.extend_from_slice(&pk.ed25519);
    msg_prime.extend_from_slice(&pk.mldsa);
    msg_prime.extend_from_slice(&(context.len() as u16).to_be_bytes());
    msg_prime.extend_from_slice(context);
    msg_prime.extend_from_slice(payload);

    let ed_sig = ed25519_sign(&sk.ed25519, &msg_prime);

    let mldsa_sk = MlDsa65SecretKey(sk.mldsa);
    let mldsa_sig = mldsa_sign(&mldsa_sk, &msg_prime);

    HybridSignature {
        ed25519: ed_sig,
        mldsa: mldsa_sig.0.to_vec(),
    }
}

pub fn hybrid_verify(
    pk: &HybridPublicKey,
    domain: &str,
    context: &[u8],
    payload: &[u8],
    sig: &HybridSignature,
) -> bool {
    let mut msg_prime = Vec::new();
    msg_prime.extend_from_slice(domain.as_bytes());
    msg_prime.extend_from_slice(&pk.ed25519);
    msg_prime.extend_from_slice(&pk.mldsa);
    msg_prime.extend_from_slice(&(context.len() as u16).to_be_bytes());
    msg_prime.extend_from_slice(context);
    msg_prime.extend_from_slice(payload);

    let ed_ok = ed25519_verify(&pk.ed25519, &msg_prime, &sig.ed25519).is_ok();

    if sig.mldsa.len() != 3309 {
        return false;
    }
    let mut mldsa_sig_arr = [0u8; 3309];
    mldsa_sig_arr.copy_from_slice(&sig.mldsa);
    let mldsa_sig_wrapped = MlDsa65Signature(mldsa_sig_arr);
    let mldsa_pk_wrapped = MlDsa65PublicKey(pk.mldsa);
    let mldsa_ok = mldsa_verify(&mldsa_pk_wrapped, &msg_prime, &mldsa_sig_wrapped);

    ed_ok && mldsa_ok
}

impl HybridPublicKey {
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1984);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.mldsa);
        out
    }

    pub fn parse(input: &[u8]) -> Result<Self, FileFormatError> {
        if input.len() < 1984 {
            return Err(FileFormatError::TruncatedChunk {
                expected: 1984,
                got: input.len(),
            });
        }
        let mut ed25519 = [0u8; 32];
        ed25519.copy_from_slice(&input[0..32]);
        let mut mldsa = [0u8; 1952];
        mldsa.copy_from_slice(&input[32..1984]);
        Ok(HybridPublicKey { ed25519, mldsa })
    }
}

impl HybridSignature {
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 2 + self.mldsa.len());
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&(self.mldsa.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mldsa);
        out
    }

    pub fn parse(input: &[u8]) -> Result<Self, FileFormatError> {
        if input.len() < 66 {
            return Err(FileFormatError::TruncatedChunk {
                expected: 66,
                got: input.len(),
            });
        }
        let mut ed25519 = [0u8; 64];
        ed25519.copy_from_slice(&input[0..64]);

        let mut mldsa_len_bytes = [0u8; 2];
        mldsa_len_bytes.copy_from_slice(&input[64..66]);
        let mldsa_len = u16::from_be_bytes(mldsa_len_bytes) as usize;

        if input.len() < 66 + mldsa_len {
            return Err(FileFormatError::TruncatedChunk {
                expected: 66 + mldsa_len,
                got: input.len(),
            });
        }

        let mldsa = input[66..66 + mldsa_len].to_vec();
        Ok(HybridSignature { ed25519, mldsa })
    }
}

impl HybridSecretKey {
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4032);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.mldsa);
        out
    }

    pub fn parse(input: &[u8]) -> Result<Self, FileFormatError> {
        if input.len() < 4064 {
            return Err(FileFormatError::TruncatedChunk {
                expected: 4064,
                got: input.len(),
            });
        }
        let mut ed25519 = [0u8; 32];
        ed25519.copy_from_slice(&input[0..32]);
        let mut mldsa = [0u8; 4032];
        mldsa.copy_from_slice(&input[32..4064]);
        Ok(HybridSecretKey { ed25519, mldsa })
    }
}

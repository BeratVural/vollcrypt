use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::FileFormatError;
use crate::pqc::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keypair_generate, x25519_diffie_hellman,
    x25519_keypair_generate,
};
use crate::wrap::WrapEntry;

/// Recipient's public key (X25519 + ML-KEM-768 encapsulation key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPublicKey {
    pub x25519: [u8; 32],
    pub ml_kem: Box<[u8; 1184]>,
}

/// Recipient's secret key (X25519 + ML-KEM-768 decapsulation key).
///
/// Automatically zeroizes on drop to prevent key leakage in memory.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct RecipientSecretKey {
    pub x25519: [u8; 32],
    pub ml_kem: Box<[u8; 2400]>,
}

/// Generates a new recipient keypair.
pub fn generate_recipient_keypair() -> (RecipientPublicKey, RecipientSecretKey) {
    let (x_pk, x_sk) = x25519_keypair_generate();
    let (m_pk, m_sk) = mlkem768_keypair_generate();

    let pk = RecipientPublicKey {
        x25519: x_pk,
        ml_kem: Box::new(m_pk),
    };

    let sk = RecipientSecretKey {
        x25519: x_sk,
        ml_kem: Box::new(m_sk),
    };

    (pk, sk)
}

/// Helper function to derive KEK from classical and post-quantum shared secrets.
///
/// Implements standard X-Wing KEM combiner:
/// combined_key = SHA3-256(XWING_LABEL ‖ ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519)
/// where XWING_LABEL = \.//^\ (5c 2e 2f 2f 5e 5c)
///
/// ML-KEM ephemeral ciphertexts/public keys are intentionally excluded from this combiner,
/// because the ML-KEM Fujisaki-Okamoto (FO) transform already binds the shared secret (ss_pq)
/// to the ciphertext, preventing component substitution attacks.
fn hybrid_kek_derive(
    ss_classical: &[u8; 32],
    ss_pq: &[u8; 32],
    ct_x25519: &[u8; 32],
    pk_x25519: &[u8; 32],
    recipient_id: &[u8; 16],
    gk_version: u32,
) -> [u8; 32] {
    let label = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
    let mut hasher = Sha3_256::new();
    hasher.update(&label);
    hasher.update(ss_pq);          // ss_mlkem
    hasher.update(ss_classical);   // ss_x25519
    hasher.update(ct_x25519);      // ct_x25519
    hasher.update(pk_x25519);      // pk_x25519
    hasher.update(recipient_id);
    hasher.update(&gk_version.to_be_bytes());
    let result = hasher.finalize();
    let mut combined_key = [0u8; 32];
    combined_key.copy_from_slice(&result);
    combined_key
}

/// Encapsulates the Key (DEK or GK) to a recipient's public key.
///
/// Returns a `WrapEntry::HybridKem` containing the recipient metadata and wrapped key.
pub fn wrap_key_to_recipient(
    key: &[u8; 32],
    recipient_id: [u8; 16],
    gk_version: u32,
    recipient_pk: &RecipientPublicKey,
) -> Result<WrapEntry, FileFormatError> {
    let (eph_pk, mut eph_sk) = x25519_keypair_generate();
    let mut ss_classical = x25519_diffie_hellman(&eph_sk, &recipient_pk.x25519);
    let (mut ss_pq, mlkem_ct) = mlkem768_encapsulate(&recipient_pk.ml_kem);

    let mut kek = hybrid_kek_derive(
        &ss_classical,
        &ss_pq,
        &eph_pk,
        &recipient_pk.x25519,
        &recipient_id,
        gk_version,
    );
    let wrapped_dek = crate::keywrap::aes256_kw_wrap(&kek, key);

    // Securely zeroize all intermediate key materials
    eph_sk.zeroize();
    ss_classical.zeroize();
    ss_pq.zeroize();
    kek.zeroize();

    Ok(WrapEntry::HybridKem {
        recipient_id,
        gk_version,
        x25519_ephemeral: eph_pk,
        mlkem_ciphertext: mlkem_ct.to_vec(),
        wrapped_dek,
    })
}

/// Decapsulates and unwraps the Key (DEK or GK) using the recipient's secret key.
pub fn unwrap_key_with_recipient_key(
    wrap: &WrapEntry,
    recipient_sk: &RecipientSecretKey,
) -> Result<[u8; 32], FileFormatError> {
    match wrap {
        WrapEntry::HybridKem {
            recipient_id,
            gk_version,
            x25519_ephemeral,
            mlkem_ciphertext,
            wrapped_dek,
        } => {
            if mlkem_ciphertext.len() != 1088 {
                return Err(FileFormatError::InvalidWrapPayload);
            }

            let mut ss_classical = x25519_diffie_hellman(&recipient_sk.x25519, x25519_ephemeral);

            let mut ct = [0u8; 1088];
            ct.copy_from_slice(mlkem_ciphertext);
            let mut ss_pq = mlkem768_decapsulate(&recipient_sk.ml_kem, &ct);

            // Derive recipient static public key from secret key
            let secret = StaticSecret::from(recipient_sk.x25519);
            let public = X25519PublicKey::from(&secret);
            let pk_x25519 = public.to_bytes();

            let mut kek = hybrid_kek_derive(
                &ss_classical,
                &ss_pq,
                x25519_ephemeral,
                &pk_x25519,
                recipient_id,
                *gk_version,
            );

            // Wrap aes256_kw_unwrap result to map WrongPassword to WrongRecipientKey
            let dek_res = crate::keywrap::aes256_kw_unwrap(&kek, wrapped_dek).map_err(|e| {
                if matches!(e, FileFormatError::WrongPassword) {
                    FileFormatError::WrongRecipientKey
                } else {
                    e
                }
            });

            // Securely zeroize all intermediate key materials
            ss_classical.zeroize();
            ss_pq.zeroize();
            kek.zeroize();

            dek_res
        }
        WrapEntry::PasswordPbkdf2 { .. }
        | WrapEntry::PasswordArgon2id { .. }
        | WrapEntry::GroupWrap { .. }
        | WrapEntry::Threshold { .. } => Err(FileFormatError::WrongWrapType),
    }
}

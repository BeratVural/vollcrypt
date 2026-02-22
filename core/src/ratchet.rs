use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::kdf::derive_hkdf_combined;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub enum CryptoError {
    RatchetKeyGenerationFailed,
    RatchetComputationFailed,
    InvalidRatchetStep,
    InvalidKeyLength,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::RatchetKeyGenerationFailed => write!(f, "Ratchet key generation failed"),
            CryptoError::RatchetComputationFailed => write!(f, "Ratchet computation failed"),
            CryptoError::InvalidRatchetStep => write!(f, "Invalid ratchet step"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
        }
    }
}

/// PCS ratchet adımı için ephemeral anahtar çifti.
/// Kullanım sonrası otomatik zeroize edilir.
#[derive(ZeroizeOnDrop, Zeroize)]
pub struct RatchetKeyPair {
    pub public_key: [u8; 32],   // Karşı tarafa gönderilir
    secret_key: [u8; 32],       // Asla dışarı çıkmaz
}

impl RatchetKeyPair {
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }
}

/// Bir PCS ratchet adımının çıktısı.
#[derive(ZeroizeOnDrop, Zeroize)]
pub struct RatchetOutput {
    pub new_srk: [u8; 32],          // Yeni Session Root Key
}

/// Ratchet tetikleme koşulları.
pub struct RatchetConfig {
    pub messages_per_ratchet: u32,   // Kaç mesajda bir ratchet (varsayılan: 50)
    pub ratchet_on_new_window: bool, // Her yeni WindowKey döneminde ratchet (varsayılan: true)
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            messages_per_ratchet: 50,
            ratchet_on_new_window: true,
        }
    }
}

/// Yeni bir ephemeral X25519 ratchet key pair üretir.
/// Gönderen bu fonksiyonu çağırır, public_key'i karşı tarafa gönderir.
pub fn generate_ratchet_keypair() -> Result<RatchetKeyPair, CryptoError> {
    let mut csprng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut csprng);
    let public = PublicKey::from(&secret);

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&secret.to_bytes());
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(public.as_bytes());

    Ok(RatchetKeyPair {
        public_key: public_bytes,
        secret_key: secret_bytes,
    })
}

/// Gönderen tarafı: Mevcut SRK + kendi ratchet secret + karşının ratchet public → Yeni SRK
pub fn ratchet_srk_sender(
    current_srk: &[u8; 32],
    our_ratchet_secret: &[u8; 32],
    their_ratchet_pub: &[u8; 32],
    _chat_id: &[u8], // maintained for API compatibility based on prompt
    ratchet_step: u64,
) -> Result<[u8; 32], CryptoError> {
    
    // Step 1: ECDH
    let secret = StaticSecret::from(*our_ratchet_secret);
    let public = PublicKey::from(*their_ratchet_pub);
    let ephemeral_shared = secret.diffie_hellman(&public);
    let mut ephemeral_shared_bytes = ephemeral_shared.to_bytes();

    // Step 2-4: input_material = current_srk || ephemeral_shared, then HKDF
    let salt = ratchet_step.to_be_bytes();
    
    let new_srk_vec = derive_hkdf_combined(
        current_srk,
        &ephemeral_shared_bytes,
        Some(&salt),
        Some(b"vollchat-pcs-ratchet-v1"),
        32,
    ).map_err(|_| CryptoError::RatchetComputationFailed)?;

    // Step 5: zeroize intermediate
    ephemeral_shared_bytes.zeroize();

    let mut new_srk = [0u8; 32];
    new_srk.copy_from_slice(&new_srk_vec);

    Ok(new_srk)
}

/// Alıcı tarafı: Mevcut SRK + kendi ratchet secret + karşının ratchet public → Yeni SRK
pub fn ratchet_srk_receiver(
    current_srk: &[u8; 32],
    our_ratchet_secret: &[u8; 32],
    their_ratchet_pub: &[u8; 32],
    chat_id: &[u8],
    ratchet_step: u64,
) -> Result<[u8; 32], CryptoError> {
    // Alıcı ve gönderen aynı matematiği çalıştırır (ECDH özelliği)
    ratchet_srk_sender(current_srk, our_ratchet_secret, their_ratchet_pub, chat_id, ratchet_step)
}

/// Ratchet tetiklenmeli mi? Mesaj sayısı ve pencere durumuna göre karar verir.
pub fn should_ratchet(
    message_count: u32,
    window_changed: bool,
    config: &RatchetConfig,
) -> bool {
    if config.ratchet_on_new_window && window_changed {
        return true;
    }
    
    message_count >= config.messages_per_ratchet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_produces_different_srk() {
        let mut old_srk = [0xAAu8; 32];
        let keypair_a = generate_ratchet_keypair().unwrap();
        let keypair_b = generate_ratchet_keypair().unwrap();

        let new_srk = ratchet_srk_sender(
            &old_srk,
            &keypair_a.secret_key,
            &keypair_b.public_key,
            b"test-chat-id",
            1,
        ).unwrap();

        assert_ne!(old_srk, new_srk, "Ratchet sonrası SRK değişmeli");
        old_srk.zeroize(); // zeroize test cleanup
    }

    #[test]
    fn test_sender_receiver_produce_same_srk() {
        let current_srk = [0xBBu8; 32];
        let chat_id = b"test-chat-42";
        let ratchet_step = 1u64;

        let alice_kp = generate_ratchet_keypair().unwrap();
        let bob_kp = generate_ratchet_keypair().unwrap();

        let alice_new_srk = ratchet_srk_sender(
            &current_srk,
            &alice_kp.secret_key,
            &bob_kp.public_key,
            chat_id,
            ratchet_step,
        ).unwrap();

        let bob_new_srk = ratchet_srk_receiver(
            &current_srk,
            &bob_kp.secret_key,
            &alice_kp.public_key,
            chat_id,
            ratchet_step,
        ).unwrap();

        assert_eq!(alice_new_srk, bob_new_srk, "Alice ve Bob bağımsız olarak aynı SRK'yı üretmeli");
    }

    #[test]
    fn test_different_ratchet_steps_produce_different_srks() {
        let current_srk = [0xCCu8; 32];
        let kp_a = generate_ratchet_keypair().unwrap();
        let kp_b = generate_ratchet_keypair().unwrap();
        let chat_id = b"test-chat";

        let srk_step_1 = ratchet_srk_sender(
            &current_srk, &kp_a.secret_key, &kp_b.public_key, chat_id, 1
        ).unwrap();

        let srk_step_2 = ratchet_srk_sender(
            &current_srk, &kp_a.secret_key, &kp_b.public_key, chat_id, 2
        ).unwrap();

        assert_ne!(srk_step_1, srk_step_2, "Farklı ratchet step'leri farklı SRK üretmeli");
    }

    #[test]
    fn test_ratchet_old_srk_cannot_derive_new() {
        let current_srk = [0xDDu8; 32];
        let kp_a = generate_ratchet_keypair().unwrap();
        let kp_b = generate_ratchet_keypair().unwrap();

        let new_srk = ratchet_srk_sender(
            &current_srk, &kp_a.secret_key, &kp_b.public_key, b"chat", 1
        ).unwrap();

        let kp_c = generate_ratchet_keypair().unwrap();
        let kp_d = generate_ratchet_keypair().unwrap();
        let attempted_srk = ratchet_srk_sender(
            &current_srk, &kp_c.secret_key, &kp_d.public_key, b"chat", 1
        ).unwrap();

        assert_ne!(new_srk, attempted_srk, "Farklı ephemeral key pair ile aynı SRK türetilemez");
    }

    #[test]
    fn test_should_ratchet_by_message_count() {
        let config = RatchetConfig { messages_per_ratchet: 50, ratchet_on_new_window: false };
        assert!(!should_ratchet(49, false, &config));
        assert!(should_ratchet(50, false, &config));
        assert!(should_ratchet(100, false, &config));
    }

    #[test]
    fn test_should_ratchet_on_new_window() {
        let config = RatchetConfig { messages_per_ratchet: 1000, ratchet_on_new_window: true };
        assert!(should_ratchet(1, true, &config), "Yeni pencerede ratchet tetiklenmeli");
        assert!(!should_ratchet(1, false, &config), "Aynı pencerede ratchet tetiklenmemeli");
    }
}

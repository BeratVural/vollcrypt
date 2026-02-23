use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};
use crate::ratchet::CryptoError;
use crate::keys::{sign_message, verify_signature};

/// Genesis kaydının prev_hash alanı için sabit değer.
/// Zincirin başlangıcını işaretler.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Bir key log kaydında gerçekleşen işlem türü.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyAction {
    /// Kullanıcı sisteme ilk kez katıldı veya yeni key yükledi.
    Add,
    /// Mevcut key yeni bir key ile güncellendi (rotation).
    Update,
    /// Key iptal edildi. Bu kullanıcının bu key'i artık geçersiz.
    Revoke,
}

mod array64 {
    use serde::{Deserializer, Serializer, Deserialize};
    pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde::Serialize::serialize(&arr.to_vec(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if vec.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&vec);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom("Expected array of length 64"))
        }
    }
}

/// Tek bir key log kaydı.
///
/// Her kayıt önceki kaydın hash'ini içerir (prev_entry_hash).
/// Bu sayede kayıtlar tek yönlü bağlı bir zincir oluşturur.
/// Herhangi bir kayıt değiştirilirse zincirin geri kalanı geçersizleşir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLogEntry {
    /// Kaydın ait olduğu kullanıcının tanımlayıcısı.
    pub user_id: Vec<u8>,

    /// Yayınlanan veya güncellenen Ed25519 public key (32 byte).
    pub public_key: [u8; 32],

    /// İşlem zaman damgası (UNIX seconds, u64).
    pub timestamp: u64,

    /// Önceki kaydın SHA-256 hash'i.
    /// İlk kayıt (genesis) için GENESIS_HASH ([0u8; 32]) kullanılır.
    pub prev_entry_hash: [u8; 32],

    /// Bu kayıtta gerçekleşen işlem.
    pub action: KeyAction,

    /// Bu kaydın tüm alanlarının (imza hariç) Ed25519 imzası (64 byte).
    /// İmzalanan veri: compute_entry_body() çıktısı.
    #[serde(with = "array64")]
    pub signature: [u8; 64],
}

/// Bir zinciri temsil eden yapı.
/// Doğrulama ve sorgu işlemleri için kullanılır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLog {
    pub entries: Vec<KeyLogEntry>,
}

impl KeyLogEntry {
    /// İmzalanacak kaydın canonical byte temsili.
    /// İmza bu değer üzerinden hesaplanır ve doğrulanır.
    ///
    /// Format (deterministic, big-endian):
    /// [user_id_len: 4B][user_id][public_key: 32B]
    /// [timestamp: 8B][prev_entry_hash: 32B][action: 1B]
    ///
    /// action byte'ları: Add=0x01, Update=0x02, Revoke=0x03
    pub fn compute_entry_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let uid_len = self.user_id.len() as u32;
        body.extend_from_slice(&uid_len.to_be_bytes());
        body.extend_from_slice(&self.user_id);
        body.extend_from_slice(&self.public_key);
        body.extend_from_slice(&self.timestamp.to_be_bytes());
        body.extend_from_slice(&self.prev_entry_hash);
        body.push(match self.action {
            KeyAction::Add    => 0x01,
            KeyAction::Update => 0x02,
            KeyAction::Revoke => 0x03,
        });
        body
    }

    /// Bu kaydın SHA-256 hash'ini hesaplar.
    /// Sonraki kaydın prev_entry_hash alanına bu değer yazılır.
    ///
    /// hash = SHA-256(entry_body || signature)
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.compute_entry_body());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// Bu kaydın imzasını Ed25519 ile doğrular.
    ///
    /// `verifying_key`: İmzayı doğrulamak için kullanılacak Ed25519 public key.
    ///                  Genellikle bu kaydın `public_key` alanının kendisi
    ///                  (Add/Update için) veya önceki geçerli key (Revoke için).
    pub fn verify_signature(&self, verifying_key: &[u8; 32]) -> Result<bool, CryptoError> {
        let is_valid = verify_signature(
            verifying_key,
            &self.compute_entry_body(),
            &self.signature,
        );
        if is_valid {
            Ok(true)
        } else {
            Err(CryptoError::KeyLogInvalidSignature { at_index: 0 }) // Generic error, mapping inside chain validation is better
        }
    }
}

/// Yeni bir key log kaydı oluşturur ve imzalar.
///
/// # Argümanlar
/// * `user_id`          — Kullanıcı tanımlayıcısı
/// * `public_key`       — Yayınlanacak Ed25519 public key (32 byte)
/// * `timestamp`        — İşlem zaman damgası (UNIX seconds)
/// * `prev_entry_hash`  — Önceki kaydın hash'i; ilk kayıt için GENESIS_HASH
/// * `action`           — Gerçekleşen işlem türü
/// * `signing_key`      — İmzalama için Ed25519 private key (32 byte)
///
/// # Güvenlik
/// signing_key bu fonksiyon dışına çıkmaz.
/// Fonksiyon içinde kopyalanırsa zeroize edilir.
pub fn create_entry(
    user_id: &[u8],
    public_key: &[u8; 32],
    timestamp: u64,
    prev_entry_hash: &[u8; 32],
    action: KeyAction,
    signing_key: &[u8; 32],
) -> Result<KeyLogEntry, CryptoError> {
    let mut entry = KeyLogEntry {
        user_id: user_id.to_vec(),
        public_key: *public_key,
        timestamp,
        prev_entry_hash: *prev_entry_hash,
        action,
        signature: [0u8; 64],
    };

    let body = entry.compute_entry_body();
    
    // Copy secret and zeroize it after use
    let mut secret = [0u8; 32];
    secret.copy_from_slice(signing_key);
    let signature = sign_message(&secret, &body).map_err(|_| CryptoError::RatchetComputationFailed)?;
    secret.zeroize();

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature);
    entry.signature = sig_array;
    Ok(entry)
}

impl KeyLog {
    /// Boş log oluşturur.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Zincire yeni kayıt ekler.
    /// Kaydın prev_entry_hash'i mevcut son kaydın hash'i ile eşleşmeli.
    /// Zincir boşsa GENESIS_HASH beklenir.
    pub fn append(&mut self, entry: KeyLogEntry) -> Result<(), CryptoError> {
        let expected_prev_hash = if self.entries.is_empty() {
            GENESIS_HASH
        } else {
            self.entries.last().unwrap().compute_hash()
        };

        if entry.prev_entry_hash != expected_prev_hash {
            return Err(CryptoError::KeyLogHashMismatch);
        }
        
        // Also check if timestamp is monotonic
        if let Some(last_entry) = self.entries.last() {
             if entry.timestamp < last_entry.timestamp {
                 return Err(CryptoError::KeyLogHashMismatch); // For simplicity, we re-use mismatch
             }
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Tüm zinciri baştan sona doğrular.
    pub fn verify_chain(&self) -> Result<(), CryptoError> {
        self.verify_up_to(self.entries.len())
    }

    /// Zincirin belirli bir noktasına kadar olan kısmını doğrular.
    pub fn verify_up_to(&self, limit: usize) -> Result<(), CryptoError> {
        let mut current_hash = GENESIS_HASH;
        
        for (i, entry) in self.entries.iter().take(limit).enumerate() {
            if entry.prev_entry_hash != current_hash {
                return Err(CryptoError::KeyLogChainBroken { at_index: i });
            }

            let verifying_key = if entry.action == KeyAction::Revoke {
                // Find previous valid key for the same user
                let mut prev_key = None;
                for prev_entry in self.entries[..i].iter().rev() {
                    if prev_entry.user_id == entry.user_id {
                        if prev_entry.action != KeyAction::Revoke {
                            prev_key = Some(&prev_entry.public_key);
                            break;
                        }
                    }
                }
                match prev_key {
                    Some(key) => key,
                    None => return Err(CryptoError::KeyLogInvalidSignature { at_index: i }), // Cannot verify revoke without previous key
                }
            } else {
                &entry.public_key
            };

            let is_valid = verify_signature(
                verifying_key,
                &entry.compute_entry_body(),
                &entry.signature,
            );

            if !is_valid {
                return Err(CryptoError::KeyLogInvalidSignature { at_index: i });
            }

            current_hash = entry.compute_hash();
        }

        Ok(())
    }

    /// Belirli bir kullanıcı için o anki geçerli public key'i döndürür.
    pub fn current_key_for(&self, user_id: &[u8]) -> Option<&[u8; 32]> {
        for entry in self.entries.iter().rev() {
            if entry.user_id == user_id {
                return match entry.action {
                    KeyAction::Revoke => None,
                    _ => Some(&entry.public_key),
                };
            }
        }
        None
    }

    /// Belirli bir kullanıcının tüm key değişiklik geçmişini döndürür.
    pub fn history_for(&self, user_id: &[u8]) -> Vec<&KeyLogEntry> {
        self.entries.iter().filter(|e| e.user_id == user_id).collect()
    }

    /// Belirli bir timestamp anında geçerli olan public key'i döndürür.
    pub fn key_at_timestamp(
        &self,
        user_id: &[u8],
        timestamp: u64,
    ) -> Option<&[u8; 32]> {
        let mut current_key = None;
        for entry in &self.entries {
            if entry.user_id == user_id {
                if entry.timestamp > timestamp {
                    break;
                }
                match entry.action {
                    KeyAction::Revoke => current_key = None,
                    _ => current_key = Some(&entry.public_key),
                }
            }
        }
        current_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_ed25519_keypair;

    fn make_entry(
        user_id: &[u8],
        keypair: &(Vec<u8>, Vec<u8>),  // (secret, public)
        prev_hash: &[u8; 32],
        action: KeyAction,
        timestamp: u64,
    ) -> KeyLogEntry {
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 32];
        sk.copy_from_slice(&keypair.0);
        pk.copy_from_slice(&keypair.1);
        create_entry(user_id, &pk, timestamp, prev_hash, action, &sk).unwrap()
    }

    #[test]
    fn test_single_entry_chain_valid() {
        let kp = generate_ed25519_keypair();
        let entry = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
        let mut log = KeyLog::new();
        log.append(entry).unwrap();
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_multi_entry_chain_valid() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        let e1 = make_entry(b"alice", &kp2, &e0_hash, KeyAction::Update, 2000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_tampered_entry_breaks_chain() {
        let kp = generate_ed25519_keypair();
        let mut e0 = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);

        // Timestamp değiştir — imza geçersizleşir
        e0.timestamp = 9999;

        let mut log = KeyLog::new();
        log.append(e0).unwrap();

        let result = log.verify_chain();
        assert!(result.is_err(), "Değiştirilmiş kayıt zinciri kırmalı");
    }

    #[test]
    fn test_wrong_prev_hash_rejected() {
        let kp = generate_ed25519_keypair();
        let e0 = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
        let wrong_prev = [0xFFu8; 32]; // Yanlış prev_hash
        let e1 = make_entry(b"alice", &kp, &wrong_prev, KeyAction::Update, 2000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        let result = log.append(e1);

        assert!(result.is_err(), "Yanlış prev_hash reddedilmeli");
        match result.unwrap_err() {
            CryptoError::KeyLogHashMismatch => {}
            e => panic!("Beklenmeyen hata: {:?}", e),
        }
    }

    #[test]
    fn test_current_key_after_update() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        let e1 = make_entry(b"alice", &kp2, &e0_hash, KeyAction::Update, 2000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();

        let mut expected_pk = [0u8; 32];
        expected_pk.copy_from_slice(&kp2.1);
        let current = log.current_key_for(b"alice").unwrap();
        assert_eq!(current, &expected_pk, "Güncel key en son Update'teki key olmalı");
    }

    #[test]
    fn test_current_key_after_revoke_is_none() {
        let kp = generate_ed25519_keypair();
        let e0 = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        let e1 = make_entry(b"alice", &kp, &e0_hash, KeyAction::Revoke, 2000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();

        assert!(log.current_key_for(b"alice").is_none(),
            "Revoke sonrası current_key None olmalı");
    }

    #[test]
    fn test_key_at_timestamp() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        let e1 = make_entry(b"alice", &kp2, &e0_hash, KeyAction::Update, 3000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();

        let mut expected_pk1 = [0u8; 32];
        expected_pk1.copy_from_slice(&kp1.1);
        
        // timestamp=1500: kp1 geçerliydi
        let key_before = log.key_at_timestamp(b"alice", 1500).unwrap();
        assert_eq!(key_before, &expected_pk1);

        let mut expected_pk2 = [0u8; 32];
        expected_pk2.copy_from_slice(&kp2.1);
        
        // timestamp=4000: kp2 geçerli
        let key_after = log.key_at_timestamp(b"alice", 4000).unwrap();
        assert_eq!(key_after, &expected_pk2);
    }

    #[test]
    fn test_multiple_users_independent() {
        let kp_a = generate_ed25519_keypair();
        let kp_b = generate_ed25519_keypair();

        let e_alice = make_entry(b"alice", &kp_a, &GENESIS_HASH, KeyAction::Add, 1000);
        let e_bob   = make_entry(b"bob",   &kp_b, &GENESIS_HASH, KeyAction::Add, 1000);

        let mut log = KeyLog::new();
        log.append(e_alice).unwrap();
        log.append(e_bob).unwrap();
        assert!(log.verify_chain().is_ok());

        let alice_key = log.current_key_for(b"alice").unwrap();
        let bob_key   = log.current_key_for(b"bob").unwrap();

        let mut expected_pk_a = [0u8; 32];
        expected_pk_a.copy_from_slice(&kp_a.1);
        let mut expected_pk_b = [0u8; 32];
        expected_pk_b.copy_from_slice(&kp_b.1);
        
        assert_eq!(alice_key, &expected_pk_a);
        assert_eq!(bob_key,   &expected_pk_b);
        assert_ne!(alice_key, bob_key);
    }

    #[test]
    fn test_history_for_user() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0h = e0.compute_hash();
        let e1 = make_entry(b"alice", &kp2, &e0h, KeyAction::Update, 2000);
        let e1h = e1.compute_hash();
        let e2 = make_entry(b"alice", &kp2, &e1h, KeyAction::Revoke, 3000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();
        log.append(e2).unwrap();

        let history = log.history_for(b"alice");
        assert_eq!(history.len(), 3, "Alice için 3 kayıt olmalı");
        assert_eq!(history[0].action, KeyAction::Add);
        assert_eq!(history[1].action, KeyAction::Update);
        assert_eq!(history[2].action, KeyAction::Revoke);
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let kp = generate_ed25519_keypair();
        let e = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
        assert_eq!(e.compute_hash(), e.compute_hash(),
            "Entry hash deterministik olmalı");
    }
}

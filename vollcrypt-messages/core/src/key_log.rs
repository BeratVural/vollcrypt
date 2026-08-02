use crate::keys::{sign_message, verify_signature};
use crate::ratchet::CryptoError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Fixed previous-hash value used by the genesis entry.
/// Marks the beginning of the chain.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Operation represented by a key-log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAction {
    /// Registers a user for the first time or publishes a new key.
    Add,
    /// Rotates the current key to a new key.
    Update,
    /// Revokes the key so it can no longer authorize the user.
    Revoke,
}

impl KeyAction {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Add => 0x01,
            Self::Update => 0x02,
            Self::Revoke => 0x03,
        }
    }
}

impl TryFrom<u8> for KeyAction {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Add),
            0x02 => Ok(Self::Update),
            0x03 => Ok(Self::Revoke),
            _ => Err("invalid key action"),
        }
    }
}

mod array64 {
    use serde::{Deserialize, Deserializer, Serializer};
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

/// A single key-log entry.
///
/// Each entry contains the hash of the previous entry in `prev_entry_hash`.
/// This forms a one-way linked chain of entries.
/// Changing any entry invalidates the remaining chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLogEntry {
    /// Identifier of the user that owns the entry.
    pub user_id: Vec<u8>,

    /// Published or updated Ed25519 public key (32 bytes).
    pub public_key: [u8; 32],

    /// Operation timestamp as UNIX seconds.
    pub timestamp: u64,

    /// SHA-256 hash of the previous entry.
    /// The genesis entry uses `GENESIS_HASH` (`[0u8; 32]`).
    pub prev_entry_hash: [u8; 32],

    /// Operation performed by this entry.
    pub action: KeyAction,

    /// Ed25519 signature over every entry field except the signature (64 bytes).
    /// The signed data is returned by `compute_entry_body`.
    #[serde(with = "array64")]
    pub signature: [u8; 64],
}

/// An append-only chain of key-log entries.
/// Supports chain verification and trusted key queries.
/// Mutation requires &mut self; callers sharing a log across threads must
/// serialize access, for example with Arc<Mutex<KeyLog>>.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLog {
    pub entries: Vec<KeyLogEntry>,
}

impl KeyLogEntry {
    /// Canonical byte representation of the entry for signing.
    /// Signatures are computed and verified over this value.
    ///
    /// Format (deterministic, big-endian):
    /// [user_id_len: 4B][user_id][public_key: 32B]
    /// [timestamp: 8B][prev_entry_hash: 32B][action: 1B]
    ///
    /// Action bytes: Add=0x01, Update=0x02, Revoke=0x03.
    pub fn compute_entry_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let uid_len = self.user_id.len() as u32;
        body.extend_from_slice(&uid_len.to_be_bytes());
        body.extend_from_slice(&self.user_id);
        body.extend_from_slice(&self.public_key);
        body.extend_from_slice(&self.timestamp.to_be_bytes());
        body.extend_from_slice(&self.prev_entry_hash);
        body.push(self.action.as_u8());
        body
    }

    /// Computes the SHA-256 hash of this entry.
    /// The next entry stores this value in `prev_entry_hash`.
    ///
    /// hash = SHA-256(entry_body || signature)
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.compute_entry_body());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// Verifies this entry signature with Ed25519.
    ///
    /// `verifying_key` is the Ed25519 public key that authorizes the entry:
    /// the entry key for Add, or the previous valid key for Update/Revoke.
    /// Revoked keys are never accepted for later operations.
    pub fn verify_signature(&self, verifying_key: &[u8; 32]) -> bool {
        verify_signature(verifying_key, &self.compute_entry_body(), &self.signature)
    }
}

/// Creates and signs a new key-log entry.
///
/// # Arguments
/// * `user_id` - User identifier.
/// * `public_key` - Ed25519 public key to publish (32 bytes).
/// * `timestamp` - Operation timestamp as UNIX seconds.
/// * `prev_entry_hash` - Previous entry hash, or `GENESIS_HASH` for genesis.
/// * `action` - Operation represented by the entry.
/// * `signing_key` - Ed25519 secret key used to authorize the entry (32 bytes).
///
/// # Security
/// The signing key is not returned or stored by this function.
/// Any local copy is zeroized after use.
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
    let signature =
        sign_message(&secret, &body).map_err(|_| CryptoError::RatchetComputationFailed)?;
    secret.zeroize();

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature);
    entry.signature = sig_array;
    Ok(entry)
}

impl Default for KeyLog {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyLog {
    /// Creates an empty key log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends an entry to the chain.
    /// The entry previous hash must match the current chain head.
    /// An empty chain requires `GENESIS_HASH`.
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
        if self
            .entries
            .last()
            .is_some_and(|last_entry| entry.timestamp < last_entry.timestamp)
        {
            return Err(CryptoError::KeyLogHashMismatch);
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Verifies the complete chain from genesis to head.
    pub fn verify_chain(&self) -> Result<(), CryptoError> {
        self.verify_up_to(self.entries.len())
    }

    /// Verifies the chain up to the specified entry count.
    pub fn verify_up_to(&self, limit: usize) -> Result<(), CryptoError> {
        let mut current_hash = GENESIS_HASH;

        for (i, entry) in self.entries.iter().take(limit).enumerate() {
            if entry.prev_entry_hash != current_hash {
                return Err(CryptoError::KeyLogChainBroken { at_index: i });
            }

            let verifying_key =
                if entry.action == KeyAction::Revoke || entry.action == KeyAction::Update {
                    // Find previous valid key for the same user
                    let mut prev_key = None;
                    for prev_entry in self.entries[..i].iter().rev() {
                        if prev_entry.user_id == entry.user_id {
                            if prev_entry.action == KeyAction::Revoke {
                                return Err(CryptoError::KeyLogChainBroken { at_index: i });
                            }
                            prev_key = Some(&prev_entry.public_key);
                            break;
                        }
                    }
                    match prev_key {
                        Some(key) => key,
                        None => return Err(CryptoError::KeyLogInvalidSignature { at_index: i }), // Cannot verify update/revoke without previous key
                    }
                } else {
                    // Ensure no prior entry of any kind exists for this user_id in the log history
                    let has_prior = self.entries[..i]
                        .iter()
                        .any(|prev_entry| prev_entry.user_id == entry.user_id);
                    if has_prior {
                        return Err(CryptoError::KeyLogChainBroken { at_index: i });
                    }
                    &entry.public_key
                };

            let is_valid = entry.verify_signature(verifying_key);

            if !is_valid {
                return Err(CryptoError::KeyLogInvalidSignature { at_index: i });
            }

            current_hash = entry.compute_hash();
        }

        Ok(())
    }

    /// Returns the currently valid public key for a user.
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

    /// Returns the complete key-change history for a user.
    pub fn history_for(&self, user_id: &[u8]) -> Vec<&KeyLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.user_id == user_id)
            .collect()
    }

    /// Returns the public key that was valid at a timestamp.
    pub fn key_at_timestamp(&self, user_id: &[u8], timestamp: u64) -> Option<&[u8; 32]> {
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
        keypair: &(Vec<u8>, Vec<u8>), // (secret, public)
        prev_hash: &[u8; 32],
        action: KeyAction,
        timestamp: u64,
    ) -> KeyLogEntry {
        make_entry_with_sig(user_id, keypair, prev_hash, action, timestamp, &keypair.0)
    }

    fn make_entry_with_sig(
        user_id: &[u8],
        keypair: &(Vec<u8>, Vec<u8>),
        prev_hash: &[u8; 32],
        action: KeyAction,
        timestamp: u64,
        sig_sec: &[u8],
    ) -> KeyLogEntry {
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 32];
        sk.copy_from_slice(sig_sec);
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
        let e1 = make_entry_with_sig(b"alice", &kp2, &e0_hash, KeyAction::Update, 2000, &kp1.0);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_tampered_entry_breaks_chain() {
        let kp = generate_ed25519_keypair();
        let mut e0 = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);

        // Changing the timestamp invalidates the signature.
        e0.timestamp = 9999;

        let mut log = KeyLog::new();
        log.append(e0).unwrap();

        let result = log.verify_chain();
        assert!(result.is_err(), "A modified entry must break the chain");
    }

    #[test]
    fn test_wrong_prev_hash_rejected() {
        let kp = generate_ed25519_keypair();
        let e0 = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
        let wrong_prev = [0xFFu8; 32]; // Incorrect previous hash.
        let e1 = make_entry(b"alice", &kp, &wrong_prev, KeyAction::Update, 2000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        let result = log.append(e1);

        assert!(
            result.is_err(),
            "An incorrect previous hash must be rejected"
        );
        match result.unwrap_err() {
            CryptoError::KeyLogHashMismatch => {}
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_current_key_after_update() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        let e1 = make_entry_with_sig(b"alice", &kp2, &e0_hash, KeyAction::Update, 2000, &kp1.0);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();

        let mut expected_pk = [0u8; 32];
        expected_pk.copy_from_slice(&kp2.1);
        let current = log.current_key_for(b"alice").unwrap();
        assert_eq!(
            current, &expected_pk,
            "The current key must be the most recent updated key"
        );
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

        assert!(
            log.current_key_for(b"alice").is_none(),
            "The current key must be absent after revocation"
        );
    }

    #[test]
    fn test_key_at_timestamp() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        let e1 = make_entry_with_sig(b"alice", &kp2, &e0_hash, KeyAction::Update, 3000, &kp1.0);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();

        let mut expected_pk1 = [0u8; 32];
        expected_pk1.copy_from_slice(&kp1.1);

        // At timestamp 1500, kp1 was valid.
        let key_before = log.key_at_timestamp(b"alice", 1500).unwrap();
        assert_eq!(key_before, &expected_pk1);

        let mut expected_pk2 = [0u8; 32];
        expected_pk2.copy_from_slice(&kp2.1);

        // At timestamp 4000, kp2 was valid.
        let key_after = log.key_at_timestamp(b"alice", 4000).unwrap();
        assert_eq!(key_after, &expected_pk2);
    }

    #[test]
    fn test_multiple_users_independent() {
        let kp_a = generate_ed25519_keypair();
        let kp_b = generate_ed25519_keypair();

        let e_alice = make_entry(b"alice", &kp_a, &GENESIS_HASH, KeyAction::Add, 1000);
        let e_alice_hash = e_alice.compute_hash();
        let e_bob = make_entry(b"bob", &kp_b, &e_alice_hash, KeyAction::Add, 1000);

        let mut log = KeyLog::new();
        log.append(e_alice).unwrap();
        log.append(e_bob).unwrap();
        assert!(log.verify_chain().is_ok());

        let alice_key = log.current_key_for(b"alice").unwrap();
        let bob_key = log.current_key_for(b"bob").unwrap();

        let mut expected_pk_a = [0u8; 32];
        expected_pk_a.copy_from_slice(&kp_a.1);
        let mut expected_pk_b = [0u8; 32];
        expected_pk_b.copy_from_slice(&kp_b.1);

        assert_eq!(alice_key, &expected_pk_a);
        assert_eq!(bob_key, &expected_pk_b);
        assert_ne!(alice_key, bob_key);
    }

    #[test]
    fn test_history_for_user() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0h = e0.compute_hash();
        let e1 = make_entry_with_sig(b"alice", &kp2, &e0h, KeyAction::Update, 2000, &kp1.0);
        let e1h = e1.compute_hash();
        let e2 = make_entry(b"alice", &kp2, &e1h, KeyAction::Revoke, 3000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();
        log.append(e2).unwrap();

        let history = log.history_for(b"alice");
        assert_eq!(history.len(), 3, "Alice must have three entries");
        assert_eq!(history[0].action, KeyAction::Add);
        assert_eq!(history[1].action, KeyAction::Update);
        assert_eq!(history[2].action, KeyAction::Revoke);
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let kp = generate_ed25519_keypair();
        let e = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
        assert_eq!(
            e.compute_hash(),
            e.compute_hash(),
            "Entry hashes must be deterministic"
        );
    }

    #[test]
    fn test_duplicate_add_rejected() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        // A duplicate Add action for the same user (alice) but self-signed by kp2
        let e1 = make_entry(b"alice", &kp2, &e0_hash, KeyAction::Add, 2000);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();

        // Verification must fail because of duplicate Add action
        let result = log.verify_chain();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::KeyLogChainBroken { at_index: 1 } => {}
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_revoked_key_cannot_sign_future_update() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();

        let e0 = make_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
        let e0_hash = e0.compute_hash();
        let e1 = make_entry(b"alice", &kp1, &e0_hash, KeyAction::Revoke, 2000);
        let e1_hash = e1.compute_hash();
        let e2 = make_entry_with_sig(b"alice", &kp2, &e1_hash, KeyAction::Update, 3000, &kp1.0);

        let mut log = KeyLog::new();
        log.append(e0).unwrap();
        log.append(e1).unwrap();
        log.append(e2).unwrap();

        let result = log.verify_chain();
        assert!(matches!(
            result,
            Err(CryptoError::KeyLogChainBroken { at_index: 2 })
        ));
    }

    #[test]
    fn externally_synchronized_concurrent_appends_preserve_chain() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let kp = generate_ed25519_keypair();
        let genesis = make_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1_000);
        let mut initial = KeyLog::new();
        initial.append(genesis).unwrap();
        let shared = Arc::new(Mutex::new(initial));

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let shared = Arc::clone(&shared);
                let kp = kp.clone();
                thread::spawn(move || {
                    let mut log = shared.lock().unwrap();
                    let previous = log.entries.last().unwrap().compute_hash();
                    let entry = make_entry(b"alice", &kp, &previous, KeyAction::Update, 1_000);
                    log.append(entry).unwrap();
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let log = shared.lock().unwrap();
        assert_eq!(log.entries.len(), 17);
        assert!(log.verify_chain().is_ok());
    }
}

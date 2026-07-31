use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::keys::{sign_message, verify_signature};

const SIGNED_MESSAGE_DOMAIN: &[u8] = b"vollcrypt-signed-message-v1";
const MAX_MESSAGE_ID_BYTES: usize = 256;
const MAX_SIGNED_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

fn signed_message_digest(
    message_id: &[u8],
    timestamp_ms: u64,
    payload: &[u8],
) -> Result<[u8; 32], &'static str> {
    if message_id.is_empty() || message_id.len() > MAX_MESSAGE_ID_BYTES {
        return Err("message_id must contain between 1 and 256 bytes");
    }
    if payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
        return Err("signed message payload exceeds 16 MiB");
    }

    let mut hasher = Sha256::new();
    hasher.update(SIGNED_MESSAGE_DOMAIN);
    hasher.update((message_id.len() as u32).to_be_bytes());
    hasher.update(message_id);
    hasher.update(timestamp_ms.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

fn replay_key(public_key: &[u8], message_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vollcrypt-replay-key-v1");
    hasher.update(public_key);
    hasher.update((message_id.len() as u32).to_be_bytes());
    hasher.update(message_id);
    hasher.finalize().into()
}

pub fn sign_fresh_message(
    secret_key: &[u8],
    message_id: &[u8],
    timestamp_ms: u64,
    payload: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let digest = signed_message_digest(message_id, timestamp_ms, payload)?;
    sign_message(secret_key, &digest)
}

/// Bounded replay cache for a single trust domain.
///
/// Mutation requires &mut self; callers sharing a store across threads must
/// serialize verify_and_record so duplicate checks and insertion stay atomic.
pub struct ReplayProtectionStore {
    validity_window_ms: u64,
    max_entries: usize,
    accepted: HashMap<[u8; 32], u64>,
}

impl ReplayProtectionStore {
    pub fn new(validity_window_ms: u64, max_entries: usize) -> Result<Self, &'static str> {
        if validity_window_ms == 0 {
            return Err("validity_window_ms must be greater than zero");
        }
        if max_entries == 0 {
            return Err("max_entries must be greater than zero");
        }
        Ok(Self {
            validity_window_ms,
            max_entries,
            accepted: HashMap::new(),
        })
    }

    pub fn verify_and_record(
        &mut self,
        public_key: &[u8],
        message_id: &[u8],
        timestamp_ms: u64,
        now_ms: u64,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), &'static str> {
        if now_ms.abs_diff(timestamp_ms) > self.validity_window_ms {
            return Err("signed message timestamp is outside the validity window");
        }

        let digest = signed_message_digest(message_id, timestamp_ms, payload)?;
        if !verify_signature(public_key, &digest, signature) {
            return Err("signed message signature is invalid");
        }

        self.accepted.retain(|_, expires_at| *expires_at > now_ms);
        let key = replay_key(public_key, message_id);
        if self.accepted.contains_key(&key) {
            return Err("signed message replay detected");
        }
        if self.accepted.len() >= self.max_entries {
            return Err("replay protection store is at capacity");
        }

        self.accepted
            .insert(key, now_ms.saturating_add(self.validity_window_ms));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    pub fn clear(&mut self) {
        self.accepted.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_ed25519_keypair;

    #[test]
    fn accepts_once_and_rejects_replay() {
        let (secret_key, public_key) = generate_ed25519_keypair();
        let timestamp = 1_700_000_000_000;
        let signature =
            sign_fresh_message(&secret_key, b"message-1", timestamp, b"payload").unwrap();
        let mut store = ReplayProtectionStore::new(300_000, 100).unwrap();

        store
            .verify_and_record(
                &public_key,
                b"message-1",
                timestamp,
                timestamp,
                b"payload",
                &signature,
            )
            .unwrap();
        assert_eq!(
            store
                .verify_and_record(
                    &public_key,
                    b"message-1",
                    timestamp,
                    timestamp + 1,
                    b"payload",
                    &signature,
                )
                .unwrap_err(),
            "signed message replay detected"
        );
    }

    #[test]
    fn rejects_stale_and_metadata_tampering() {
        let (secret_key, public_key) = generate_ed25519_keypair();
        let timestamp = 1_700_000_000_000;
        let signature =
            sign_fresh_message(&secret_key, b"message-1", timestamp, b"payload").unwrap();
        let mut store = ReplayProtectionStore::new(1_000, 100).unwrap();

        assert_eq!(
            store
                .verify_and_record(
                    &public_key,
                    b"message-1",
                    timestamp,
                    timestamp + 1_001,
                    b"payload",
                    &signature,
                )
                .unwrap_err(),
            "signed message timestamp is outside the validity window"
        );
        assert_eq!(
            store
                .verify_and_record(
                    &public_key,
                    b"message-2",
                    timestamp,
                    timestamp,
                    b"payload",
                    &signature,
                )
                .unwrap_err(),
            "signed message signature is invalid"
        );
    }

    #[test]
    fn capacity_is_fail_closed_and_expired_entries_are_pruned() {
        let (secret_key, public_key) = generate_ed25519_keypair();
        let mut store = ReplayProtectionStore::new(10, 1).unwrap();

        let first = sign_fresh_message(&secret_key, b"one", 100, b"a").unwrap();
        store
            .verify_and_record(&public_key, b"one", 100, 100, b"a", &first)
            .unwrap();

        let second = sign_fresh_message(&secret_key, b"two", 101, b"b").unwrap();
        assert_eq!(
            store
                .verify_and_record(&public_key, b"two", 101, 101, b"b", &second)
                .unwrap_err(),
            "replay protection store is at capacity"
        );

        let third = sign_fresh_message(&secret_key, b"three", 111, b"c").unwrap();
        store
            .verify_and_record(&public_key, b"three", 111, 111, b"c", &third)
            .unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn externally_synchronized_concurrent_replays_are_accepted_once() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let (secret_key, public_key) = generate_ed25519_keypair();
        let timestamp = 1_700_000_000_000;
        let signature = Arc::new(
            sign_fresh_message(&secret_key, b"concurrent", timestamp, b"payload").unwrap(),
        );
        let public_key = Arc::new(public_key);
        let store = Arc::new(Mutex::new(
            ReplayProtectionStore::new(300_000, 100).unwrap(),
        ));

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let signature = Arc::clone(&signature);
                let public_key = Arc::clone(&public_key);
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    store.lock().unwrap().verify_and_record(
                        &public_key,
                        b"concurrent",
                        timestamp,
                        timestamp,
                        b"payload",
                        &signature,
                    )
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err("signed message replay detected"))
                .count(),
            15
        );
        assert_eq!(store.lock().unwrap().len(), 1);
    }
}

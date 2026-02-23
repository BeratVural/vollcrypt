use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

/// Holds the transcript (chain) state of a conversation.
///
/// `update()` should be called every time a message is sent or received.
/// The caller is responsible for maintaining the chain state - this struct
/// is a stateless calculation component.
#[derive(Clone, ZeroizeOnDrop)]
pub struct TranscriptState {
    chain_hash: [u8; 32],
}

impl TranscriptState {
    /// Initializes a new transcript chain.
    ///
    /// `session_id`: Value that uniquely identifies the conversation.
    /// Typically equals to the chat_id used in SRK derivation.
    /// chain_hash_0 = SHA-256(session_id)
    pub fn new(session_id: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(session_id);
        Self {
            chain_hash: hasher.finalize().into(),
        }
    }

    /// Returns the current chain_hash.
    /// This value must be included in the AAD of the next message.
    pub fn current_hash(&self) -> &[u8; 32] {
        &self.chain_hash
    }

    /// Updates the transcript with a new message.
    ///
    /// `message_hash`: SHA-256 hash of the encrypted message.
    ///                 May correspond to the AAD hash within envelope.rs
    ///                 or can be calculated via `compute_message_hash()`.
    ///
    /// new chain_hash = SHA-256(old_chain_hash || message_hash)
    ///
    /// IMPORTANT: This function must be called in exactly the same order
    /// on both the sender and receiver side for each message to stay synced.
    pub fn update(&mut self, message_hash: &[u8; 32]) {
        let mut hasher = Sha256::new();
        hasher.update(self.chain_hash);
        hasher.update(message_hash);
        self.chain_hash = hasher.finalize().into();
    }

    /// Computes the message hash from the message contents.
    ///
    /// `message_id`: Unique identifier of the message
    /// `sender_id`: Identity of the sender
    /// `timestamp`: Message timestamp (u64, UNIX seconds)
    /// `ciphertext`: Encrypted message payload
    ///
    /// hash = SHA-256(message_id || sender_id || timestamp_bytes || ciphertext)
    pub fn compute_message_hash(
        message_id: &[u8],
        sender_id: &[u8],
        timestamp: u64,
        ciphertext: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message_id);
        hasher.update(sender_id);
        hasher.update(timestamp.to_be_bytes()); // Keep as u64 BE bytes for standard
        hasher.update(ciphertext);
        hasher.finalize().into()
    }

    /// Performs a timing-safe equality check between two transcript state hashes.
    ///
    /// Primarily used to verify if both parties are on the same
    /// chain state at a given point in the conversation.
    pub fn verify_sync(a: &[u8; 32], b: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    /// Serializes the current transcript state for storage.
    /// The caller is responsible for securely storing the returned bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.chain_hash
    }

    /// Restores a transcript from previously saved bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { chain_hash: bytes }
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_hash_depends_on_session_id() {
        let ts_a = TranscriptState::new(b"session-abc");
        let ts_b = TranscriptState::new(b"session-xyz");
        assert_ne!(
            ts_a.current_hash(),
            ts_b.current_hash(),
            "Different session IDs must produce different initial hashes"
        );
    }

    #[test]
    fn test_update_changes_hash() {
        let mut ts = TranscriptState::new(b"session-1");
        let before = *ts.current_hash();
        let msg_hash = [0x42u8; 32];
        ts.update(&msg_hash);
        assert_ne!(
            &before,
            ts.current_hash(),
            "chain_hash must change after calling update()"
        );
    }

    #[test]
    fn test_same_messages_same_order_same_hash() {
        // As long as the sender and receiver process the same messages in the same order,
        // they must reach the exact same chain_hash.
        let session_id = b"shared-session";
        let mut sender_ts = TranscriptState::new(session_id);
        let mut receiver_ts = TranscriptState::new(session_id);

        let messages = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

        for msg_hash in &messages {
            sender_ts.update(msg_hash);
            receiver_ts.update(msg_hash);
        }

        assert_eq!(
            sender_ts.current_hash(),
            receiver_ts.current_hash(),
            "Identical message sequences must produce the same chain_hash"
        );
    }

    #[test]
    fn test_different_order_different_hash() {
        // Processing messages out of order must result in a different chain_hash.
        let session_id = b"shared-session";
        let mut ts_ab = TranscriptState::new(session_id);
        let mut ts_ba = TranscriptState::new(session_id);

        let msg_a = [0xAAu8; 32];
        let msg_b = [0xBBu8; 32];

        ts_ab.update(&msg_a);
        ts_ab.update(&msg_b);

        ts_ba.update(&msg_b); // Reversed order
        ts_ba.update(&msg_a);

        assert_ne!(
            ts_ab.current_hash(),
            ts_ba.current_hash(),
            "Different message orders must produce different chain hashes"
        );
    }

    #[test]
    fn test_missing_message_breaks_chain() {
        // Skipping a message must desync / break the chain_hash.
        let session_id = b"shared-session";
        let mut ts_full = TranscriptState::new(session_id);
        let mut ts_gap = TranscriptState::new(session_id);

        let msg_1 = [0x11u8; 32];
        let msg_2 = [0x22u8; 32]; // Will be skipped in ts_gap
        let msg_3 = [0x33u8; 32];

        ts_full.update(&msg_1);
        ts_full.update(&msg_2);
        ts_full.update(&msg_3);

        ts_gap.update(&msg_1);
        // Skipped msg_2
        ts_gap.update(&msg_3);

        assert_ne!(
            ts_full.current_hash(),
            ts_gap.current_hash(),
            "Missing message must lead to a chain_hash mismatch"
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut ts = TranscriptState::new(b"session-x");
        ts.update(&[0xFFu8; 32]);
        let bytes = ts.to_bytes();
        let ts_restored = TranscriptState::from_bytes(bytes);
        assert_eq!(
            ts.current_hash(),
            ts_restored.current_hash(),
            "Hashes must match after serialize/deserialize roundtrip"
        );
    }

    #[test]
    fn test_verify_sync_timing_safe() {
        let hash_a = [0x01u8; 32];
        let hash_b = [0x01u8; 32];
        let hash_c = [0x02u8; 32];
        assert!(TranscriptState::verify_sync(&hash_a, &hash_b));
        assert!(!TranscriptState::verify_sync(&hash_a, &hash_c));
    }

    #[test]
    fn test_compute_message_hash_deterministic() {
        let h1 = TranscriptState::compute_message_hash(b"msg-001", b"alice", 1700000000, b"ciphertext");
        let h2 = TranscriptState::compute_message_hash(b"msg-001", b"alice", 1700000000, b"ciphertext");
        assert_eq!(h1, h2, "Identical inputs must produce the same hash");
    }

    #[test]
    fn test_compute_message_hash_sensitive_to_inputs() {
        let base = TranscriptState::compute_message_hash(b"msg-001", b"alice", 1700000000, b"ciphertext");
        
        // Changed timestamp
        let diff_time = TranscriptState::compute_message_hash(b"msg-001", b"alice", 1700000001, b"ciphertext");
        
        // Changed sender
        let diff_sender = TranscriptState::compute_message_hash(b"msg-001", b"mallory", 1700000000, b"ciphertext");
        
        assert_ne!(base, diff_time, "Changing timestamp should change the hash");
        assert_ne!(base, diff_sender, "Changing sender should change the hash");
    }
}

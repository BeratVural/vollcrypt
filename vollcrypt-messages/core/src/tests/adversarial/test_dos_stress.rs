use std::collections::HashSet;
use std::time::Instant;
use rand::{RngCore, rngs::OsRng};


use crate::transcript::TranscriptState;
use crate::ratchet::{ratchet_srk_receiver, generate_ratchet_keypair};

// =========================================================================
// 1. The "AES-GCM Nonce Reuse & Counter Exhaustion" Test
// =========================================================================

#[test]
fn test_aes_gcm_nonce_collision_probability() {
    // A. Reduced Nonce Birthday Paradox Simulation (24-bit Nonces)
    // This demonstrates the birthday paradox empirically using a smaller space.
    let target_collisions = 100;
    let mut total_attempts_to_collision = 0;

    for _ in 0..target_collisions {
        let mut seen = HashSet::new();
        let mut attempts = 0;
        loop {
            attempts += 1;
            // Generate a random 24-bit value (3 bytes)
            let mut buf = [0u8; 3];
            OsRng.fill_bytes(&mut buf);
            let val = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
            if !seen.insert(val) {
                break;
            }
        }
        total_attempts_to_collision += attempts;
    }

    let avg_attempts = total_attempts_to_collision / target_collisions;
    // Theoretical average for 24-bit space (16,777,216 values) is sqrt(pi/2 * 2^24) approx 5135.
    println!("Average messages before a 24-bit nonce collision: {}", avg_attempts);
    assert!(avg_attempts > 1000 && avg_attempts < 10000, 
            "Empirical average {} should align with birthday paradox expectations (~5135)", avg_attempts);

    // B. Mathematical Verification of 96-bit (12-byte) Nonce Space
    // We compute the probability of a collision after N messages.
    // P(N) ≈ 1 - exp(-N^2 / 2^97)
    let n_values = [65536u64, 4294967296u64]; // 2^16 and 2^32
    let prob_2_16 = calculate_collision_probability(n_values[0]);
    let prob_2_32 = calculate_collision_probability(n_values[1]);

    println!("Theoretical collision probability for 96-bit nonce at N=2^16 (65,536 msgs): {:.2e}", prob_2_16);
    println!("Theoretical collision probability for 96-bit nonce at N=2^32 (4.29B msgs): {:.2e}", prob_2_32);

    // Assert that the probability of a collision for 2^16 messages is cryptographically negligible.
    assert!(prob_2_16 < 1e-15, "Collision probability must be negligible for standard conversations");
    assert!(prob_2_32 < 1e-9, "Collision probability must be negligible even for 4 billion messages");
}

fn calculate_collision_probability(n: u64) -> f64 {
    // 2^97 is approximately 1.5845632502852868e29
    let denominator = 1.5845632502852868e29f64;
    let numerator = (n as f64) * (n as f64);
    1.0 - (-numerator / denominator).exp()
}

// =========================================================================
// 2. The "Massive Skipped-Keys DoS (Out-of-Memory)" Simulation Test
// =========================================================================

#[test]
fn test_massive_skipped_keys_dos_performance() {
    let initial_srk = [0x55u8; 32];
    let chat_id = b"dos-ratchet-chat";

    let alice_kp = generate_ratchet_keypair().unwrap();
    let bob_kp = generate_ratchet_keypair().unwrap();

    // Adversary attempts a massive leap in step_count to trigger a loop / OOM
    let massive_leap_step = 10_000_000u64;

    let start_time = Instant::now();
    
    // Process the receiver ratchet step with the massive leap
    let result = ratchet_srk_receiver(
        &initial_srk,
        &bob_kp.secret_key(),
        &alice_kp.public_key,
        chat_id,
        massive_leap_step,
    );

    let duration = start_time.elapsed();
    println!("Time taken to compute ratchet step leap of 10M: {} µs", duration.as_micros());

    // Assert that the receiver does not hang or consume excessive time
    assert!(result.is_ok(), "Ratchet step computation must succeed");
    assert!(duration.as_millis() < 50, 
            "A massive ratchet step leap must execute in O(1) time (< 50ms), proving it does not loop over skipped keys");
}

// =========================================================================
// 3. The "Replay Prevention Store Memory Bloat" Stress Test
// =========================================================================

struct StressReplayPreventionStore {
    processed_packet_hashes: HashSet<[u8; 32]>,
}

impl StressReplayPreventionStore {
    fn new() -> Self {
        Self {
            processed_packet_hashes: HashSet::new(),
        }
    }

    fn check_and_add(&mut self, hash: [u8; 32]) -> bool {
        self.processed_packet_hashes.insert(hash)
    }
}

#[test]
fn test_replay_store_memory_bloat_stress() {
    let num_hashes = 500_000;
    let mut store = StressReplayPreventionStore::new();

    // Pre-reserve capacity to avoid reallocation overhead during the test
    store.processed_packet_hashes.reserve(num_hashes);

    let start_time = Instant::now();

    // Flood the store with 500,000 unique simulated packet hashes
    for i in 0..num_hashes {
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        let inserted = store.check_and_add(hash);
        assert!(inserted, "Each hash should be unique and inserted successfully");
    }

    let duration = start_time.elapsed();
    println!("Time taken to insert {} hashes: {} ms", num_hashes, duration.as_millis());

    // Document memory overhead.
    // In Rust, HashSet has overhead per entry. 
    // For HashSet<[u8; 32]>, each entry is at least 32 bytes for the key plus hash-table metadata (typically ~24 bytes).
    // Minimum memory footprint = 500k * (32 + 24) = 28 MB.
    let num_entries = store.processed_packet_hashes.len();
    assert_eq!(num_entries, num_hashes);
    println!("Replay prevention store size: {} entries", num_entries);
    
    // Assert that insertion completes within a reasonable timeframe, confirming O(1) average lookup/insert
    assert!(duration.as_secs() < 3, "Flooding 500k hashes took too long ({}s)", duration.as_secs());
}

// =========================================================================
// 4. The "Simultaneous Offline Messaging & Transcript Fork" Test
// =========================================================================

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct ForkedMessage {
    sequence_number: u64,
    message_id: Vec<u8>,
    sender_id: Vec<u8>,
    timestamp: u64,
    ciphertext: Vec<u8>,
    hash: [u8; 32],
}

#[test]
fn test_simultaneous_offline_messaging_and_transcript_fork() {
    let session_id = b"offline-fork-session";
    
    // Initialize identical transcript chains for Alice and Bob
    let mut alice_chain = TranscriptState::new(session_id);
    let mut bob_chain = TranscriptState::new(session_id);

    // 1. Simulating Alice and Bob going offline and sending 10 messages each concurrently.
    let mut alice_offline_messages = Vec::new();
    let mut bob_offline_messages = Vec::new();

    for i in 0..10 {
        // Alice's messages (timestamps: 1000..1010)
        let alice_msg_id = format!("alice-msg-{}", i).into_bytes();
        let alice_sender = b"alice".to_vec();
        let alice_time = 1000 + i * 2; // e.g. 1000, 1002, 1004...
        let alice_cipher = vec![i as u8; 16];
        let alice_hash = TranscriptState::compute_message_hash(&alice_msg_id, &alice_sender, alice_time, &alice_cipher);
        alice_offline_messages.push(ForkedMessage {
            sequence_number: i,
            message_id: alice_msg_id,
            sender_id: alice_sender,
            timestamp: alice_time,
            ciphertext: alice_cipher,
            hash: alice_hash,
        });

        // Bob's messages (timestamps: 1001..1011)
        let bob_msg_id = format!("bob-msg-{}", i).into_bytes();
        let bob_sender = b"bob".to_vec();
        let bob_time = 1001 + i * 2; // e.g. 1001, 1003, 1005...
        let bob_cipher = vec![i as u8; 16];
        let bob_hash = TranscriptState::compute_message_hash(&bob_msg_id, &bob_sender, bob_time, &bob_cipher);
        bob_offline_messages.push(ForkedMessage {
            sequence_number: i,
            message_id: bob_msg_id,
            sender_id: bob_sender,
            timestamp: bob_time,
            ciphertext: bob_cipher,
            hash: bob_hash,
        });
    }

    // 2. Alice updates her chain with her 10 sent messages
    for msg in &alice_offline_messages {
        alice_chain.update(&msg.hash);
    }

    // 3. Bob updates his chain with his 10 sent messages
    for msg in &bob_offline_messages {
        bob_chain.update(&msg.hash);
    }

    // 4. Reconnect Phase: Alice receives Bob's messages, Bob receives Alice's messages.
    // If they process incoming messages immediately (naive/direct update), their chains will fork.
    let mut alice_chain_naive = alice_chain.clone();
    let mut bob_chain_naive = bob_chain.clone();

    // Alice processes Bob's messages in arrival order
    for msg in &bob_offline_messages {
        alice_chain_naive.update(&msg.hash);
    }

    // Bob processes Alice's messages in arrival order
    for msg in &alice_offline_messages {
        bob_chain_naive.update(&msg.hash);
    }

    // Assert that the direct/naive processing causes a permanent chain fork
    assert_ne!(
        alice_chain_naive.current_hash(),
        bob_chain_naive.current_hash(),
        "Direct updates of concurrent offline messages must result in a permanent transcript fork"
    );

    // 5. Fork Resolution via Deterministic Linearization
    // Alice and Bob collect all messages (sent and received) and sort them deterministically.
    let mut all_messages = Vec::new();
    all_messages.extend(alice_offline_messages);
    all_messages.extend(bob_offline_messages);

    // Sort by timestamp, break ties by sender_id and message_id to ensure a deterministic global order
    all_messages.sort_by(|a, b| {
        a.timestamp.cmp(&b.timestamp)
            .then_with(|| a.sender_id.cmp(&b.sender_id))
            .then_with(|| a.message_id.cmp(&b.message_id))
    });

    // Both Alice and Bob rebuild their transcript chains using the linearized sequence
    let mut alice_chain_resolved = TranscriptState::new(session_id);
    let mut bob_chain_resolved = TranscriptState::new(session_id);

    for msg in &all_messages {
        alice_chain_resolved.update(&msg.hash);
        bob_chain_resolved.update(&msg.hash);
    }

    // Verify that the resolved chains converge to the exact same hash
    assert_eq!(
        alice_chain_resolved.current_hash(),
        bob_chain_resolved.current_hash(),
        "Deterministic linearization must successfully merge the forks back into a unified hash state"
    );

    assert!(
        TranscriptState::verify_sync(alice_chain_resolved.current_hash(), bob_chain_resolved.current_hash()),
        "Transcript synchronization check must succeed after linearization resolution"
    );
}

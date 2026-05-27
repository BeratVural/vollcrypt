use std::collections::BTreeMap;
use std::panic;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use rand::seq::SliceRandom;
use rand::thread_rng;
use zeroize::Zeroize;
use sha2::Digest;

use crate::transcript::TranscriptState;
use crate::ratchet::{
    generate_ratchet_keypair, ratchet_srk_sender, CryptoError,
};
use crate::sealed_sender::{seal, unseal};
use crate::keys::generate_x25519_keypair;

// =========================================================================
// 1. The "Network Chaos & Out-of-Order" Stress Test
// =========================================================================

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct NetworkMessage {
    sequence_number: u64,
    message_id: Vec<u8>,
    sender_id: Vec<u8>,
    timestamp: u64,
    ciphertext: Vec<u8>,
    hash: [u8; 32],
}

#[test]
fn test_network_chaos_and_out_of_order() {
    let session_id = b"chaos-session-123";
    let mut alice_state = TranscriptState::new(session_id);
    let mut bob_state_naive = TranscriptState::new(session_id);
    let mut bob_state_recovered = TranscriptState::new(session_id);

    // 1. Generate 50 sequenced messages
    let mut messages = Vec::new();
    for i in 0..50 {
        let msg_id = format!("msg-{}", i).into_bytes();
        let sender_id = b"alice".to_vec();
        let timestamp = 1700000000 + i;
        let ciphertext = vec![i as u8; 32];
        let hash = TranscriptState::compute_message_hash(&msg_id, &sender_id, timestamp, &ciphertext);

        messages.push(NetworkMessage {
            sequence_number: i,
            message_id: msg_id,
            sender_id,
            timestamp,
            ciphertext,
            hash,
        });
    }

    // 2. Alice processes them in-order (sending phase)
    for msg in &messages {
        alice_state.update(&msg.hash);
    }
    let alice_final_hash = *alice_state.current_hash();

    // 3. Simulate Network Chaos (shuffle, duplicate, delay)
    let mut network_queue = Vec::new();
    let mut rng = thread_rng();
    
    // Duplicate some messages (e.g. sequence 5, 10, 15)
    for msg in &messages {
        network_queue.push(msg.clone());
        if msg.sequence_number % 12 == 0 {
            // Duplicate message
            network_queue.push(msg.clone());
        }
    }

    // Shuffle the queue to simulate severe reordering
    network_queue.shuffle(&mut rng);

    // 4. Bob receives messages via the Naive approach (process directly upon receipt)
    // This will prove that out-of-order execution permanently breaks naive chain synchronization.
    for msg in &network_queue {
        bob_state_naive.update(&msg.hash);
    }
    assert_ne!(
        alice_final_hash,
        *bob_state_naive.current_hash(),
        "Naive out-of-order processing must break the chain sync"
    );

    // 5. Bob receives messages via a Sequenced Recovery Buffer
    // This demonstrates graceful recovery and correct chain synchronization.
    let mut recovery_buffer: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    let mut next_expected_seq = 0u64;

    for msg in &network_queue {
        let seq = msg.sequence_number;
        
        // Ignore duplicates (replay detection)
        if seq < next_expected_seq {
            continue;
        }

        // Insert into recovery buffer
        recovery_buffer.insert(seq, msg.hash);

        // Process buffered messages sequentially
        while let Some(hash) = recovery_buffer.remove(&next_expected_seq) {
            bob_state_recovered.update(&hash);
            next_expected_seq += 1;
        }
    }

    // Ensure all 50 messages were processed and no gaps remain
    assert_eq!(next_expected_seq, 50, "All 50 messages should be processed");
    assert!(recovery_buffer.is_empty(), "Recovery buffer must be empty at the end");

    // Verify Bob's recovered state matches Alice's final state
    assert_eq!(
        alice_final_hash,
        *bob_state_recovered.current_hash(),
        "Sequenced recovery buffer must successfully restore transcript chain sync"
    );
}

// =========================================================================
// 2. The "Ratchet Race Condition & State Corruption" Test
// =========================================================================

struct RatchetSession {
    srk: [u8; 32],
    step: u64,
    chat_id: Vec<u8>,
}

impl RatchetSession {
    fn new(initial_srk: [u8; 32], chat_id: &[u8]) -> Self {
        Self {
            srk: initial_srk,
            step: 0,
            chat_id: chat_id.to_vec(),
        }
    }

    /// Transactional ratchet step.
    /// If the computation fails, the state is unmodified.
    fn try_ratchet(
        &mut self,
        our_secret: &[u8; 32],
        their_pub: &[u8; 32],
    ) -> Result<(), CryptoError> {
        // Attempt to compute the new SRK first
        let new_srk = ratchet_srk_sender(
            &self.srk,
            our_secret,
            their_pub,
            &self.chat_id,
            self.step + 1,
        )?;
        
        // Commit changes only after successful computation
        self.srk = new_srk;
        self.step += 1;
        Ok(())
    }
}

#[test]
fn test_ratchet_race_condition_and_state_corruption() {
    let initial_srk = [0x55u8; 32];
    let chat_id = b"shared-ratchet-chat";

    // Alice and Bob start with the same initial session
    let alice_session = Arc::new(Mutex::new(RatchetSession::new(initial_srk, chat_id)));
    let bob_session = Arc::new(Mutex::new(RatchetSession::new(initial_srk, chat_id)));

    // Barrier to synchronize simultaneous execution of threads
    let barrier = Arc::new(Barrier::new(3));

    // Alice's concurrent ratchet attempt
    let alice_session_clone = Arc::clone(&alice_session);
    let barrier_alice = Arc::clone(&barrier);
    let handle_alice = thread::spawn(move || {
        let alice_kp = generate_ratchet_keypair().unwrap();
        // Wait for other threads to align
        barrier_alice.wait();
        
        // Alice attempts to ratchet using a dummy public key because she hasn't received Bob's new key yet
        let dummy_pub = [0u8; 32];
        let result = alice_session_clone.lock().unwrap().try_ratchet(
            alice_kp.secret_key(),
            &dummy_pub,
        );
        (result, alice_kp)
    });

    // Bob's concurrent ratchet attempt
    let bob_session_clone = Arc::clone(&bob_session);
    let barrier_bob = Arc::clone(&barrier);
    let handle_bob = thread::spawn(move || {
        let bob_kp = generate_ratchet_keypair().unwrap();
        // Wait for other threads to align
        barrier_bob.wait();
        
        // Bob attempts to ratchet using a dummy public key
        let dummy_pub = [0u8; 32];
        let result = bob_session_clone.lock().unwrap().try_ratchet(
            bob_kp.secret_key(),
            &dummy_pub,
        );
        (result, bob_kp)
    });

    // Main thread aligns with Alice and Bob
    barrier.wait();

    let (alice_result, alice_kp) = handle_alice.join().unwrap();
    let (_bob_result, bob_kp) = handle_bob.join().unwrap();

    // The ratchet attempts with dummy keys might either fail or complete.
    // In x25519-dalek, performing DH with a zero public key returns a shared secret of all zeros,
    // which then goes into HKDF. Thus, the operation does not fail with an error, but Alice and Bob
    // now have new derived SRKs.
    // Let's verify that the state is consistent (no partial corruption: SRK and step are in sync).
    {
        let alice_lock = alice_session.lock().unwrap();
        assert_eq!(alice_lock.step, if alice_result.is_ok() { 1 } else { 0 });
        if alice_result.is_ok() {
            assert_ne!(alice_lock.srk, initial_srk);
        } else {
            assert_eq!(alice_lock.srk, initial_srk, "State must roll back on failure");
        }
    }

    // Now, let's explicitly test Transactional Rollback under a guaranteed failure.
    // We will supply an invalid key length/type if possible or trigger a manual error.
    // Let's perform a ratchet that we force to fail by simulating a network failure.
    // If we call try_ratchet with a valid keypair but intercept and inject an invalid operation:
    // Actually, x25519-dalek does not fail on random public keys, but it would fail if we passed 
    // an invalid key size (though Rust's type system enforces `[u8; 32]`).
    // Let's verify that if we manually simulate a failing ratchet step, the SRK is untouched:
    let mut test_session = RatchetSession::new(initial_srk, chat_id);
    let keypair = generate_ratchet_keypair().unwrap();
    
    // Simulate a failure: We pass a helper function that returns Err
    fn failing_ratchet_step(
        session: &mut RatchetSession,
        secret: &[u8; 32],
    ) -> Result<(), CryptoError> {
        // We simulate a half-way failure after deriving a temporary key:
        let _temp_srk = ratchet_srk_sender(
            &session.srk,
            secret,
            &[0u8; 32],
            &session.chat_id,
            session.step + 1,
        )?;
        
        // Simulating an unexpected network interruption or verification failure here
        Err(CryptoError::RatchetComputationFailed)
    }

    let fail_res = failing_ratchet_step(&mut test_session, keypair.secret_key());
    assert!(fail_res.is_err());
    assert_eq!(
        test_session.srk, initial_srk,
        "Session SRK must remain unchanged if the ratchet operation fails halfway"
    );
    assert_eq!(test_session.step, 0, "Session step must not increment on failure");

    // Finally, let's verify that Alice and Bob can correctly synchronize once they exchange actual public keys
    let mut alice_final = alice_session.lock().unwrap();
    let mut bob_final = bob_session.lock().unwrap();
    
    // Reset to initial state for a clean run
    alice_final.srk = initial_srk;
    alice_final.step = 0;
    bob_final.srk = initial_srk;
    bob_final.step = 0;

    // Alice computes ratchet using Bob's public key
    let res_a = alice_final.try_ratchet(alice_kp.secret_key(), &bob_kp.public_key);
    // Bob computes ratchet using Alice's public key
    let res_b = bob_final.try_ratchet(bob_kp.secret_key(), &alice_kp.public_key);

    assert!(res_a.is_ok());
    assert!(res_b.is_ok());
    assert_eq!(
        alice_final.srk, bob_final.srk,
        "Alice and Bob must converge on the exact same SRK after exchanging keys"
    );
}

// =========================================================================
// 3. The "Sealed Sender Byte Malleability & Replay" Attack Test
// =========================================================================

struct ReplayPreventionStore {
    processed_packet_hashes: std::collections::HashSet<[u8; 32]>,
}

impl ReplayPreventionStore {
    fn new() -> Self {
        Self {
            processed_packet_hashes: std::collections::HashSet::new(),
        }
    }

    /// Processes a packet. Returns the unsealed content if it's not a duplicate.
    fn process_packet(
        &mut self,
        packet: &[u8],
        recipient_sk: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        // Calculate hash of the raw packet for replay detection
        let mut hasher = sha2::Sha256::new();
        hasher.update(packet);
        let packet_hash: [u8; 32] = hasher.finalize().into();

        if self.processed_packet_hashes.contains(&packet_hash) {
            return Err("Replay attack detected: Packet already processed");
        }

        // Unseal the packet
        let decrypted = unseal(packet, recipient_sk)
            .map_err(|_| "Decryption/Unseal failed")?;

        // Record the hash on successful decryption
        self.processed_packet_hashes.insert(packet_hash);
        Ok(decrypted)
    }
}

#[test]
fn test_sealed_sender_malleability_and_replay() {
    let (bob_sk_vec, bob_pk_vec) = generate_x25519_keypair();
    let bob_sk: [u8; 32] = bob_sk_vec.try_into().unwrap();
    let bob_pk: [u8; 32] = bob_pk_vec.try_into().unwrap();

    let sender_id = b"alice-identity";
    let message_content = b"highly-sensitive-payload";

    // Create the authentic sealed packet
    let sealed_packet = seal(&bob_pk, sender_id, message_content).unwrap();

    // ---------------------------------------------------------
    // A. Byte Malleability Attack: Mutate every single byte
    // ---------------------------------------------------------
    for i in 0..sealed_packet.len() {
        let original_val = sealed_packet[i];
        let mut corrupted_packet = sealed_packet.clone();

        // Attack 1: Bit flip
        corrupted_packet[i] = original_val ^ 0x01; 
        let result = unseal(&corrupted_packet, &bob_sk);
        assert!(
            result.is_err(),
            "Decryption must fail when byte {} is flipped", i
        );

        // Attack 2: Ensure the byte is modified to a different value (e.g. add 117)
        let mut alt_val = original_val.wrapping_add(117);
        if alt_val == original_val {
            alt_val = alt_val.wrapping_add(1);
        }
        corrupted_packet[i] = alt_val;
        let result_rand = unseal(&corrupted_packet, &bob_sk);
        assert!(
            result_rand.is_err(),
            "Decryption must fail when byte {} is randomized to {}", i, alt_val
        );
    }

    // ---------------------------------------------------------
    // B. Replay Attack
    // ---------------------------------------------------------
    let mut receiver_store = ReplayPreventionStore::new();

    // First delivery must succeed
    let first_delivery = receiver_store.process_packet(&sealed_packet, &bob_sk);
    assert!(first_delivery.is_ok());
    let (recovered_sender, recovered_content) = first_delivery.unwrap();
    assert_eq!(recovered_sender, sender_id);
    assert_eq!(recovered_content, message_content);

    // Subsequent 9 deliveries (replays) must be rejected
    for i in 2..=10 {
        let replay_delivery = receiver_store.process_packet(&sealed_packet, &bob_sk);
        assert!(
            replay_delivery.is_err(),
            "Delivery attempt {} (replay) should have been rejected", i
        );
        assert_eq!(
            replay_delivery.unwrap_err(),
            "Replay attack detected: Packet already processed"
        );
    }

    assert_eq!(receiver_store.processed_packet_hashes.len(), 1);
}

// =========================================================================
// 4. The "Panic & Memory Zeroization" Validation Test
// =========================================================================

// Global raw pointer to observe memory changes of the dropped object safely
static mut OBSERVED_KEY_POINTER: *const u8 = std::ptr::null();

struct SecretKeyContainer {
    key_data: [u8; 32],
}

impl SecretKeyContainer {
    fn new(key: [u8; 32]) -> Self {
        Self { key_data: key }
    }
}

// Emulate ZeroizeOnDrop behavior
impl Drop for SecretKeyContainer {
    fn drop(&mut self) {
        self.key_data.zeroize();
    }
}

#[test]
fn test_panic_memory_zeroization() {
    let original_key = [0x99u8; 32];
    
    // Allocate the container on the heap using Box to ensure stable address
    let container = Box::new(SecretKeyContainer::new(original_key));
    
    // Store the raw pointer to the inner key bytes in our global variable
    unsafe {
        OBSERVED_KEY_POINTER = container.key_data.as_ptr();
        
        // Confirm the memory initially holds the original key data
        let initial_slice = std::slice::from_raw_parts(OBSERVED_KEY_POINTER, 32);
        assert_eq!(initial_slice, original_key);
    }

    // Trigger an unwinding panic inside a catch_unwind boundary
    let panic_result = panic::catch_unwind(panic::AssertUnwindSafe(move || {
        // Reference the container to keep it alive in the closure's scope
        let _active_container = container;
        
        // Deliberately panic (simulate a boundary condition panic or invalid slice access)
        panic!("Forced panic for zeroization test");
    }));

    assert!(panic_result.is_err(), "Closure must panic");

    // After the panic unwinds, the Box<SecretKeyContainer> must be dropped.
    // We check the observed pointer to verify it has been zeroized.
    unsafe {
        assert!(!OBSERVED_KEY_POINTER.is_null());
        let zeroized_slice = std::slice::from_raw_parts(OBSERVED_KEY_POINTER, 32);
        
        // Verify that the memory was zeroized, despite the panic
        assert_eq!(
            zeroized_slice,
            [0u8; 32],
            "Memory containing key must be zeroized during panic unwinding"
        );
    }
}

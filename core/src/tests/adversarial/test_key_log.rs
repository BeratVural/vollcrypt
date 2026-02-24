use std::time::Instant;
use std::convert::TryInto;
use crate::key_log::{KeyLog, KeyLogEntry, KeyAction, create_entry, GENESIS_HASH};
use crate::keys::generate_ed25519_keypair;
use crate::ratchet::CryptoError;

// Helper function to create a valid entry for tests
fn make_helper_entry(
    user_id: &[u8],
    keypair: &(Vec<u8>, Vec<u8>),
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

// ── Chain Manipulation ────────────────────────────────────────────────────

#[test]
fn key_log_modify_timestamp_breaks_chain() {
    let kp = generate_ed25519_keypair();
    let mut e = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    
    // Attack
    e.timestamp += 1;
    
    let mut log = KeyLog::new();
    // It shouldn't let us append without a hash mismatch due to compute_hash relying on tampered body,
    // wait, append() checks if prev_hash matches but e.prev_hash is untouched.
    // The signature however will be broken.
    log.entries.push(e); // force push to test verify_chain directly
    
    let result = log.verify_chain();
    assert!(result.is_err(), "Modified timestamp must break the chain's validity");
    match result.unwrap_err() {
        CryptoError::KeyLogInvalidSignature { at_index: 0 } => {},
        err => panic!("Expected KeyLogInvalidSignature, got {:?}", err),
    }
}

#[test]
fn key_log_modify_public_key_breaks_chain() {
    let kp = generate_ed25519_keypair();
    let mut e = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    
    e.public_key[0] ^= 0xFF;
    
    let mut log = KeyLog::new();
    log.entries.push(e);
    
    let result = log.verify_chain();
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::KeyLogInvalidSignature { .. } => {},
        err => panic!("Expected KeyLogInvalidSignature, got {:?}", err),
    }
}

#[test]
fn key_log_modify_prev_hash_breaks_chain() {
    let kp1 = generate_ed25519_keypair();
    let kp2 = generate_ed25519_keypair();
    
    let e0 = make_helper_entry(b"alice", &kp1, &GENESIS_HASH, KeyAction::Add, 1000);
    let mut e1 = make_helper_entry(b"alice", &kp2, &e0.compute_hash(), KeyAction::Update, 2000);
    
    e1.prev_entry_hash[0] ^= 0xFF; // Modify prev hash (breaks chain link AND invalidates e1's signature)
    
    let mut log = KeyLog::new();
    log.entries.push(e0);
    log.entries.push(e1);
    
    let result = log.verify_chain();
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::KeyLogChainBroken { at_index: 1 } => {},
        err => panic!("Expected KeyLogChainBroken, got {:?}", err),
    }
}

#[test]
fn key_log_delete_middle_entry() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    let e1 = make_helper_entry(b"alice", &kp, &e0.compute_hash(), KeyAction::Update, 2000);
    let e2 = make_helper_entry(b"alice", &kp, &e1.compute_hash(), KeyAction::Update, 3000);
    
    let mut log = KeyLog::new();
    log.entries.push(e0);
    // omitted e1
    log.entries.push(e2);
    
    let result = log.verify_chain();
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::KeyLogChainBroken { at_index: 1 } => {}, // e2 is at index 1 now, its prev_hash expects e1...
        err => panic!("Expected KeyLogChainBroken, got {:?}", err),
    }
}

#[test]
fn key_log_insert_fake_entry() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    let e1 = make_helper_entry(b"alice", &kp, &e0.compute_hash(), KeyAction::Update, 3000);
    
    let mut fake = e1.clone();
    fake.timestamp = 2000;
    // fake's signature is now invalid since timestamp changed
    
    let mut log = KeyLog::new();
    log.entries.push(e0);
    log.entries.push(fake);
    log.entries.push(e1);
    
    let result = log.verify_chain();
    assert!(result.is_err());
}

#[test]
fn key_log_swap_two_entries() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    let e1 = make_helper_entry(b"bob", &kp, &e0.compute_hash(), KeyAction::Add, 2000); // independent user but part of same transparent log
    
    let mut log = KeyLog::new();
    log.entries.push(e1); // Out of order
    log.entries.push(e0);
    
    let result = log.verify_chain();
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::KeyLogChainBroken { at_index: 0 } => {},
        err => panic!("Expected KeyLogChainBroken, got {:?}", err),
    }
}

#[test]
fn key_log_duplicate_entry() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    
    let mut log = KeyLog::new();
    let _ = log.append(e0.clone());
    let result = log.append(e0);
    
    assert!(result.is_err(), "Cannot append duplicate entry (prev_hash mismatch contextually)");
}

// ── Timestamp Attacks ─────────────────────────────────────────────────────

#[test]
fn key_log_timestamp_goes_backward() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 2000);
    let mut e1 = make_helper_entry(b"alice", &kp, &e0.compute_hash(), KeyAction::Update, 1000); // 1000 < 2000
    
    let mut log = KeyLog::new();
    let _ = log.append(e0);
    let result = log.append(e1);
    
    // Expected to fail directly in append if library checks monotonicity
    assert!(result.is_err(), "Append should reject backward timestamps");
}

#[test]
fn key_log_timestamp_zero() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 0); // UNIX epic 0
    
    let mut log = KeyLog::new();
    let result = log.append(e0);
    assert!(result.is_ok(), "Timestamp 0 is acceptable");
}

#[test]
fn key_log_timestamp_max_u64() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, u64::MAX); 
    
    let mut log = KeyLog::new();
    let result = log.append(e0);
    assert!(result.is_ok(), "Timestamp MAX is acceptable, no overflow");
}

// ── Query Attacks ─────────────────────────────────────────────────────────

#[test]
fn key_log_current_key_nonexistent_user() {
    let mut log = KeyLog::new();
    assert!(log.current_key_for(b"bob").is_none(), "Must not panic on unknown user");
}

#[test]
fn key_log_key_at_timestamp_before_first_entry() {
    let kp = generate_ed25519_keypair();
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    let mut log = KeyLog::new();
    log.append(e0).unwrap();
    
    assert!(log.key_at_timestamp(b"alice", 500).is_none(), "Returns None if before first entry");
}

#[test]
fn key_log_empty_log_operations() {
    let log = KeyLog::new();
    // Verify chain of empty log should be Ok(())
    assert!(log.verify_chain().is_ok());
    assert!(log.current_key_for(b"alice").is_none());
    assert_eq!(log.history_for(b"alice").len(), 0);
}

#[test]
fn key_log_1000_entries_performance() {
    let mut log = KeyLog::new();
    let kp = generate_ed25519_keypair();
    
    let start = Instant::now();
    let mut prev_hash = GENESIS_HASH;
    
    for i in 0..1000 {
        let e = make_helper_entry(b"alice", &kp, &prev_hash, KeyAction::Update, 1000 + i);
        prev_hash = e.compute_hash();
        log.append(e).unwrap();
    }
    
    let result = log.verify_chain();
    assert!(result.is_ok());
    
    let duration = start.elapsed();
    assert!(duration.as_secs() < 15, "1000 entries took too long");
}

#[test]
fn key_log_revoke_nonexistent_key() {
    let kp = generate_ed25519_keypair();
    // Directly revoke a key that was never added
    let e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Revoke, 1000);
    
    let mut log = KeyLog::new();
    log.append(e0).unwrap();
    
    let result = log.verify_chain();
    assert!(result.is_err(), "Cannot verify revoke if there is no previous valid key");
}

#[test]
fn key_log_signature_with_wrong_action_byte() {
    // In Rust, an enum naturally avoids an invalid state like `action = 0x99`.
    // However, what if a malicious node crafts an entry explicitly manipulating the signature manually?
    let kp = generate_ed25519_keypair();
    let mut e0 = make_helper_entry(b"alice", &kp, &GENESIS_HASH, KeyAction::Add, 1000);
    
    // We can't set e0.action = 0x99, but we can corrupt the signature to simulate a mismatched action byte.
    // That's what `verify_chain` will protect against.
    e0.signature[0] ^= 0x01;
    
    let mut log = KeyLog::new();
    log.entries.push(e0);
    
    let result = log.verify_chain();
    assert!(result.is_err());
}

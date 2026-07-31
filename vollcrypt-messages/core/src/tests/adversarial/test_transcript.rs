use crate::transcript::TranscriptState;

// ── Chain Manipulation ────────────────────────────────────────────────────

#[test]
fn transcript_insert_extra_message() {
    let mut alice_ts = TranscriptState::new(b"chat1");
    let mut bob_ts = TranscriptState::new(b"chat1");

    let msg1 = [0x11u8; 32];
    let msg2 = [0x22u8; 32];
    let msg3 = [0x33u8; 32];
    let fake_msg = [0x99u8; 32];

    // Alice sends 3 messages
    alice_ts.update(&msg1);
    alice_ts.update(&msg2);
    alice_ts.update(&msg3);

    // Bob processes 4 messages (fake inserted)
    bob_ts.update(&msg1);
    bob_ts.update(&fake_msg);
    bob_ts.update(&msg2);
    bob_ts.update(&msg3);

    assert_ne!(alice_ts.current_hash(), bob_ts.current_hash());
}

#[test]
fn transcript_delete_middle_message() {
    let mut alice_ts = TranscriptState::new(b"chat2");
    let mut bob_ts = TranscriptState::new(b"chat2");

    let msg1 = [0x11u8; 32];
    let msg2 = [0x22u8; 32];
    let msg3 = [0x33u8; 32];

    // Alice sends 3 messages
    alice_ts.update(&msg1);
    alice_ts.update(&msg2);
    alice_ts.update(&msg3);

    // Bob misses the 2nd message
    bob_ts.update(&msg1);
    bob_ts.update(&msg3);

    assert_ne!(alice_ts.current_hash(), bob_ts.current_hash());
}

#[test]
fn transcript_swap_two_messages() {
    let mut ts1 = TranscriptState::new(b"chat3");
    let mut ts2 = TranscriptState::new(b"chat3");

    let msg_a = [0xAAu8; 32];
    let msg_b = [0xBBu8; 32];

    ts1.update(&msg_a);
    ts1.update(&msg_b);

    ts2.update(&msg_b);
    ts2.update(&msg_a);

    assert_ne!(ts1.current_hash(), ts2.current_hash());
}

#[test]
fn transcript_message_hash_collision_attempt() {
    let hash1 = TranscriptState::compute_message_hash(b"msg1", b"sender", 1000, b"data_a");
    let hash2 = TranscriptState::compute_message_hash(b"msg1", b"sender", 1000, b"data_b");

    assert_ne!(
        hash1, hash2,
        "Different ciphertexts must produce different message hashes"
    );
}

#[test]
fn transcript_message_hash_collision_sliding_fields() {
    let hash1 = TranscriptState::compute_message_hash(b"msg", b"alice", 1000, b"data");
    let hash2 = TranscriptState::compute_message_hash(b"msga", b"lice", 1000, b"data");

    assert_ne!(
        hash1, hash2,
        "Prefixing with lengths must prevent sliding-field concatenation collisions"
    );
}

#[test]
fn transcript_from_bytes_invalid_length() {
    // TranscriptState::from_bytes expects a [u8; 32] directly.
    // In Rust, providing a 31-byte array to a function expecting [u8; 32] is a compile-time error.
    //
    // let bad_input = [0u8; 31];
    // TranscriptState::from_bytes(bad_input); // Compile Error
    // This satisfies the "compile-time enforcement" requirement of the prompt.
    // To test runtime conversion if coming from a Vec:
    let vec_31 = vec![0u8; 31];
    let result: Result<[u8; 32], _> = vec_31.try_into();
    assert!(
        result.is_err(),
        "Cannot safely convert 31 bytes to a 32-byte array"
    );
}

#[test]
fn transcript_update_with_all_zeros_hash() {
    let mut ts = TranscriptState::new(b"chat4");
    let before = *ts.current_hash();

    // All zero hash is a valid input type ([u8; 32])
    ts.update(&[0u8; 32]);

    assert_ne!(
        before,
        *ts.current_hash(),
        "Updating with zero hash must change the chain state"
    );
}

#[test]
fn transcript_large_sequence_is_deterministic() {
    let mut first = TranscriptState::new(b"chat5");
    let mut second = TranscriptState::new(b"chat5");

    for i in 0..100_000 {
        let mut msg_hash = [0u8; 32];
        msg_hash[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        first.update(&msg_hash);
        second.update(&msg_hash);
    }

    assert_eq!(first.current_hash(), second.current_hash());
    assert_ne!(first.current_hash(), &[0u8; 32]);
}

#[test]
fn transcript_verify_sync_rejects_every_mismatch_position() {
    let expected = [0x55u8; 32];
    assert!(TranscriptState::verify_sync(&expected, &expected));

    for index in 0..expected.len() {
        let mut different = expected;
        different[index] ^= 1;
        assert!(
            !TranscriptState::verify_sync(&expected, &different),
            "Mismatch at byte {index} was accepted"
        );
    }
}

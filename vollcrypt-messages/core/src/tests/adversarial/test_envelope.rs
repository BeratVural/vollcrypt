use crate::envelope::{pack_envelope, unpack_envelope};
use crate::symmetric::{encrypt_aes256gcm, decrypt_aes256gcm};
use crate::transcript::TranscriptState;
use crate::kdf::derive_window_key;

// ── Format Attacks ────────────────────────────────────────────────────────

#[test]
fn envelope_too_short_for_header() {
    let envelope = [0u8; 3];
    let result = unpack_envelope(&envelope);
    assert!(result.is_err(), "Too short envelope should fail");
}

#[test]
fn envelope_exactly_minimum_size_no_ciphertext() {
    // Minimum size: 4 (window) + 12 (iv) + 32 (aad) + 16 (tag) = 64
    let envelope = [0u8; 64];
    let result = unpack_envelope(&envelope);
    assert!(result.is_ok(), "Unpack might succeed, but the ciphertext is empty (0 bytes before tag)");

    // But AES-GCM needs the ciphertext part to be processed
    if let Ok((_, aad, blob)) = result {
        let key = [0u8; 32];
        let dec = decrypt_aes256gcm(&key, &blob, Some(&aad));
        // Decryption will fail because auth tag is all zeros and won't match
        assert!(dec.is_err());
    }
}

#[test]
fn envelope_window_index_overflow() {
    let window_index = u32::MAX;
    let aad_hash = [0x55u8; 32];
    let mut encrypted_blob = vec![0x00u8; 12]; // IV
    encrypted_blob.extend_from_slice(b"ciphertext_body!"); // Cipher + Tag (16)
    
    let envelope = pack_envelope(window_index, &aad_hash, &encrypted_blob).expect("Pack failed");

    let (unpacked_window, _, _) = unpack_envelope(&envelope).expect("Unpack failed");
    assert_eq!(unpacked_window, window_index, "Window index must handle u32::MAX without overflow");
}

#[test]
fn envelope_corrupted_aad_hash() {
    let key = [0u8; 32];
    let aad_hash = [0xAAu8; 32];
    
    // Encrypt with correct AAD
    let encrypted_blob = encrypt_aes256gcm(&key, b"message", Some(&aad_hash)).unwrap();
    
    // Pack
    let mut envelope = pack_envelope(1, &aad_hash, &encrypted_blob).unwrap();
    
    // Corrupt AAD in the envelope (bytes 16..48)
    envelope[20] ^= 0x01;
    
    let (_, broken_aad, broken_blob) = unpack_envelope(&envelope).unwrap();
    
    // Attempt to decrypt with the corrupted AAD
    let result = decrypt_aes256gcm(&key, &broken_blob, Some(&broken_aad));
    assert!(result.is_err(), "Authentication must fail due to corrupted AAD hash");
}

#[test]
fn envelope_wrong_window_index_on_decrypt() {
    let srk = [0u8; 32];
    let window_index_correct = 5;
    let window_index_wrong = 6;
    
    let key_correct = derive_window_key(&srk, window_index_correct as u64).unwrap();
    let key_wrong = derive_window_key(&srk, window_index_wrong as u64).unwrap();
    
    let aad_hash = [0xAAu8; 32];
    let encrypted_blob = encrypt_aes256gcm(&key_correct, b"message", Some(&aad_hash)).unwrap();
    
    let envelope = pack_envelope(window_index_correct, &aad_hash, &encrypted_blob).unwrap();
    
    let (unpacked_window, unpacked_aad, unpacked_blob) = unpack_envelope(&envelope).unwrap();
    assert_eq!(unpacked_window, window_index_correct);
    
    // Attempt decrypt with wrong key derived from wrong window
    let result = decrypt_aes256gcm(&key_wrong, &unpacked_blob, Some(&unpacked_aad));
    assert!(result.is_err(), "Decryption with wrong window key must fail");
}

#[test]
fn envelope_all_zeros() {
    let envelope = vec![0u8; 1024];
    let result = unpack_envelope(&envelope);
    // Unpack succeeds because it's just stripping lengths
    assert!(result.is_ok());

    let (_, aad, blob) = result.unwrap();
    
    let key = [0u8; 32];
    let dec = decrypt_aes256gcm(&key, &blob, Some(&aad));
    assert!(dec.is_err(), "Decrypting all-zeros must fail safely without panic");
}

#[test]
fn envelope_random_bytes_1mb() {
    // Not actually random to avoid adding heavy dependencies, but filler bytes
    let envelope = vec![0x42u8; 1024 * 1024];
    let result = unpack_envelope(&envelope);
    assert!(result.is_ok());

    let (_, aad, blob) = result.unwrap();
    
    let key = [0u8; 32];
    let dec = decrypt_aes256gcm(&key, &blob, Some(&aad));
    assert!(dec.is_err(), "Decrypting 1MB random payload must fail safely without crash");
}

// ── Replay Attacks ────────────────────────────────────────────────────────

#[test]
fn envelope_replay_detection_via_transcript() {
    // A replay attack works by re-submitting the same envelope.
    // The transcript chain hash must diverge.
    
    let mut transcript1 = TranscriptState::new(b"session1");
    let mut transcript2 = TranscriptState::new(b"session1");
    
    let sender_id = b"alice@example";
    let message_id = b"msg-001";
    let timestamp = 1600000000;
    let envelope_ct = b"some encrypted envelope bytes from step 1";
    
    // Both apply msg1
    let hash1 = TranscriptState::compute_message_hash(message_id, sender_id, timestamp, envelope_ct);
    transcript1.update(&hash1);
    transcript2.update(&hash1);
    
    // Normal flow applies msg2
    let hash2 = TranscriptState::compute_message_hash(b"msg-002", sender_id, timestamp + 1, b"ct2");
    transcript1.update(&hash2);
    
    // Replay attack applies msg1 again
    transcript2.update(&hash1);
    
    assert_ne!(
        transcript1.current_hash(), 
        transcript2.current_hash(),
        "Replay must cause transcript divergence"
    );
}

#[test]
fn envelope_message_swap() {
    // msg_a and msg_b are encrypted, but envelope of msg_b is used with msg_a's context
    let key = [0u8; 32];
    
    let aad_a = [0xAAu8; 32];
    let aad_b = [0xBBu8; 32];
    
    let _blob_a = encrypt_aes256gcm(&key, b"Message A", Some(&aad_a)).unwrap();
    let blob_b = encrypt_aes256gcm(&key, b"Message B", Some(&aad_b)).unwrap();
    
    // Mallory swaps the envelope of B into A's context
    let envelope_b = pack_envelope(1, &aad_b, &blob_b).unwrap();
    let (_, _unpacked_aad_b, unpacked_blob_b) = unpack_envelope(&envelope_b).unwrap();
    
    // Try to decrypt B's blob using A's AAD (simulate AAD check)
    let dec = decrypt_aes256gcm(&key, &unpacked_blob_b, Some(&aad_a));
    
    assert!(dec.is_err(), "Message swap must be rejected due to AAD mismatch");
}

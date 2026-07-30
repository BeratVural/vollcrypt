use crate::key_log::{GENESIS_HASH, KeyAction, create_entry};
use crate::keys::{generate_ed25519_keypair, generate_x25519_keypair};
use crate::ratchet::CryptoError;
use crate::sealed_sender::{seal, unseal};

fn setup_test_context(sender_id: &[u8]) -> ([u8; 32], [u8; 32], String) {
    let (alice_sk, alice_pk) = generate_ed25519_keypair();
    let mut alice_pk_arr = [0u8; 32];
    alice_pk_arr.copy_from_slice(&alice_pk);
    let mut alice_sk_arr = [0u8; 32];
    alice_sk_arr.copy_from_slice(&alice_sk);

    let entry = create_entry(
        sender_id,
        &alice_pk_arr,
        1000,
        &GENESIS_HASH,
        KeyAction::Add,
        &alice_sk_arr,
    )
    .unwrap();
    let entries = vec![entry];
    let entries_json = serde_json::to_string(&entries).unwrap();

    (alice_sk_arr, alice_pk_arr, entries_json)
}

// ── Identity Confidentiality ───────────────────────────────────────────────

#[test]
fn sealed_sender_identity_not_in_packet_substring() {
    let (_, bob_pk) = generate_x25519_keypair();
    let sender_id = b"alice@example.com";
    let (alice_sk, _, _) = setup_test_context(sender_id);

    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sealed = seal(&pk_array, sender_id, b"message", &alice_sk).unwrap();

    let alice = b"alice";
    let example = b"example";

    let windows: Vec<&[u8]> = sealed.windows(alice.len()).collect();
    assert!(
        !windows.contains(&alice.as_ref()),
        "The string 'alice' must not appear in the packet"
    );

    let windows_ex: Vec<&[u8]> = sealed.windows(example.len()).collect();
    assert!(
        !windows_ex.contains(&example.as_ref()),
        "The string 'example' must not appear in the packet"
    );
}

#[test]
fn sealed_sender_identity_not_in_packet_any_substring_8_chars() {
    let (_, bob_pk) = generate_x25519_keypair();
    let sender_id = b"secureuser";
    let (alice_sk, _, _) = setup_test_context(sender_id);

    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sealed = seal(&pk_array, sender_id, b"message", &alice_sk).unwrap();

    if sender_id.len() >= 8 {
        for i in 0..=(sender_id.len() - 8) {
            let sub = &sender_id[i..i + 8];
            let windows: Vec<&[u8]> = sealed.windows(8).collect();
            assert!(
                !windows.contains(&sub),
                "8-character substring of identity leaked"
            );
        }
    }
}

#[test]
fn sealed_sender_two_messages_unlinkable() {
    let (_, bob_pk) = generate_x25519_keypair();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sender_id = b"alice";
    let (alice_sk, _, _) = setup_test_context(sender_id);

    let sealed1 = seal(&pk_array, sender_id, b"message 1", &alice_sk).unwrap();
    let sealed2 = seal(&pk_array, sender_id, b"message 2", &alice_sk).unwrap();

    let eph_pk1 = &sealed1[0..32];
    let eph_pk2 = &sealed2[0..32];

    assert_ne!(
        eph_pk1, eph_pk2,
        "Ephemeral public keys must differ to prevent unlinkability"
    );
}

// ── Packet Manipulation ───────────────────────────────────────────────────

#[test]
fn sealed_sender_flip_every_byte() {
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let sk_array: [u8; 32] = bob_sk.try_into().unwrap();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sender_id = b"alice";
    let (alice_sk, alice_pk, entries_json) = setup_test_context(sender_id);

    let sealed = seal(&pk_array, sender_id, b"payload", &alice_sk).unwrap();

    for i in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[i] ^= 0xFF;

        let result = unseal(&tampered, &sk_array, Some(&entries_json), Some(&alice_pk));
        assert!(
            result.is_err(),
            "Unseal must fail when byte {} is tampered with",
            i
        );
    }
}

#[test]
fn sealed_sender_truncate_to_each_length() {
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let sk_array: [u8; 32] = bob_sk.try_into().unwrap();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sender_id = b"alice";
    let (alice_sk, alice_pk, entries_json) = setup_test_context(sender_id);

    let sealed = seal(&pk_array, sender_id, b"payload", &alice_sk).unwrap();

    for i in 0..sealed.len() {
        let truncated = &sealed[..i];
        let result = unseal(truncated, &sk_array, Some(&entries_json), Some(&alice_pk));
        assert!(result.is_err(), "Truncated packet length {} must fail", i);
    }
}

#[test]
fn sealed_sender_extend_with_random_bytes() {
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let sk_array: [u8; 32] = bob_sk.try_into().unwrap();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sender_id = b"alice";
    let (alice_sk, alice_pk, entries_json) = setup_test_context(sender_id);

    let sealed = seal(&pk_array, sender_id, b"payload", &alice_sk).unwrap();

    for ext_len in [1, 10, 100, 1000] {
        let mut extended = sealed.clone();
        extended.extend(vec![0x42; ext_len]);

        let result = unseal(&extended, &sk_array, Some(&entries_json), Some(&alice_pk));
        assert!(
            result.is_err(),
            "Extended packet with +{} bytes must fail",
            ext_len
        );
    }
}

#[test]
fn sealed_sender_wrong_recipient_multiple_attempts() {
    let (_, bob_pk) = generate_x25519_keypair();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sender_id = b"alice";
    let (alice_sk, alice_pk, entries_json) = setup_test_context(sender_id);

    let sealed = seal(&pk_array, sender_id, b"payload", &alice_sk).unwrap();

    for _ in 0..10 {
        let (wrong_sk, _) = generate_x25519_keypair();
        let wrong_sk_array: [u8; 32] = wrong_sk.try_into().unwrap();

        let result = unseal(
            &sealed,
            &wrong_sk_array,
            Some(&entries_json),
            Some(&alice_pk),
        );
        assert!(
            result.is_err(),
            "Unseal with entirely wrong recipient private key must fail"
        );
    }
}

#[test]
fn sealed_sender_empty_sender_id() {
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let sk_array: [u8; 32] = bob_sk.try_into().unwrap();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sender_id = b"";
    let (alice_sk, alice_pk, entries_json) = setup_test_context(sender_id);

    let sealed = seal(&pk_array, sender_id, b"payload", &alice_sk).unwrap();
    let (recovered_id, _) =
        unseal(&sealed, &sk_array, Some(&entries_json), Some(&alice_pk)).unwrap();

    assert_eq!(
        recovered_id, b"",
        "Empty sender_id must roundtrip successfully"
    );
}

#[test]
fn sealed_sender_very_long_sender_id() {
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let sk_array: [u8; 32] = bob_sk.try_into().unwrap();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let long_id = vec![b'a'; 65000];
    let (alice_sk, alice_pk, entries_json) = setup_test_context(&long_id);

    let sealed = seal(&pk_array, &long_id, b"payload", &alice_sk).unwrap();
    let (recovered_id, recovered_content) =
        unseal(&sealed, &sk_array, Some(&entries_json), Some(&alice_pk)).unwrap();

    assert_eq!(recovered_id.len(), 65000_usize);
    assert_eq!(recovered_content, b"payload");
}

#[test]
fn sealed_sender_sender_id_length_overflow_attempt() {
    let (bob_sk, bob_pk) = generate_x25519_keypair();
    let sk_array: [u8; 32] = bob_sk.try_into().unwrap();
    let pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let sender_id = b"alice";
    let (_, alice_pk, entries_json) = setup_test_context(sender_id);

    use crate::kdf::derive_hkdf;
    use crate::symmetric::encrypt_aes256gcm_padded;
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);
    let recipient_pk = PublicKey::from(pk_array);
    let shared_secret = ephemeral_sk.diffie_hellman(&recipient_pk).to_bytes();

    let encryption_key = derive_hkdf(
        &shared_secret,
        Some(ephemeral_pk.as_bytes()),
        Some(b"vollchat-sealed-sender-v1"),
        32,
    )
    .unwrap();

    let mut inner_plaintext = Vec::new();
    let spoof_len: u16 = 65000;
    inner_plaintext.extend_from_slice(&spoof_len.to_be_bytes());
    inner_plaintext.extend_from_slice(b"1234567890"); // Only 10 bytes remaining

    let encrypted_inner =
        encrypt_aes256gcm_padded(&encryption_key, &inner_plaintext, None).unwrap();

    let mut sealed_packet = Vec::new();
    sealed_packet.extend_from_slice(ephemeral_pk.as_bytes());
    sealed_packet.extend_from_slice(&encrypted_inner);

    let result = unseal(
        &sealed_packet,
        &sk_array,
        Some(&entries_json),
        Some(&alice_pk),
    );

    assert!(
        result.is_err(),
        "Overflow attempt parsed without panicking but must fail"
    );
    match result.unwrap_err() {
        CryptoError::InvalidSealedPacketFormat => {}
        e => panic!("Expected InvalidSealedPacketFormat error, got {:?}", e),
    }
}

#[test]
fn sealed_sender_seal_fails_on_low_order_recipient_key() {
    let low_order_pk = [0u8; 32];
    let (alice_sk, _, _) = setup_test_context(b"alice");
    let result = seal(&low_order_pk, b"alice", b"payload", &alice_sk);
    assert!(
        result.is_err(),
        "Sealing with a low-order recipient key must fail"
    );
}

#[test]
fn sealed_sender_unseal_fails_on_low_order_ephemeral_key() {
    let (bob_sk, _) = generate_x25519_keypair();
    let sk_array: [u8; 32] = bob_sk.try_into().unwrap();

    let sealed_packet = vec![0u8; 100];

    let result = unseal(&sealed_packet, &sk_array, None, None);
    assert!(
        result.is_err(),
        "Unsealing a packet with a low-order ephemeral key must fail"
    );
}

#[test]
fn sealed_sender_seal_fails_on_huge_sender_id() {
    let (_, bob_pk) = generate_x25519_keypair();
    let bob_pk_array: [u8; 32] = bob_pk.try_into().unwrap();
    let huge_sender_id = vec![0u8; 65536];
    let (alice_sk, _, _) = setup_test_context(b"alice");
    let result = seal(&bob_pk_array, &huge_sender_id, b"payload", &alice_sk);
    assert!(
        result.is_err(),
        "Sealing with a huge sender_id must fail due to u16 overflow prevention"
    );
}

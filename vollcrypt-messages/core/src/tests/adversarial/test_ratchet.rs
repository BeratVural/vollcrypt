use crate::kdf::derive_window_key;
use crate::ratchet::{
    RatchetConfig, generate_ratchet_keypair, ratchet_srk_receiver, ratchet_srk_sender,
    should_ratchet,
};
use crate::symmetric::{decrypt_aes256gcm_padded, encrypt_aes256gcm_padded};

// ── Ratchet Security ──────────────────────────────────────────────────────

#[test]
fn ratchet_step_replay() {
    let current_srk = [0x11u8; 32];
    let kp_sender = generate_ratchet_keypair().unwrap();
    let kp_receiver = generate_ratchet_keypair().unwrap();

    let srk1 = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat",
        1,
    )
    .unwrap();

    // Replay exact same step and keys
    let srk2 = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat",
        1,
    )
    .unwrap();

    assert_eq!(
        srk1, srk2,
        "Deterministic: Same inputs must yield same SRK. Caller prevents replay."
    );
}

#[test]
fn ratchet_step_zero() {
    let current_srk = [0x11u8; 32];
    let kp_sender = generate_ratchet_keypair().unwrap();
    let kp_receiver = generate_ratchet_keypair().unwrap();

    let srk = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat",
        0,
    )
    .unwrap();

    assert_eq!(srk.len(), 32);
}

#[test]
fn ratchet_step_max_u64() {
    let current_srk = [0x11u8; 32];
    let kp_sender = generate_ratchet_keypair().unwrap();
    let kp_receiver = generate_ratchet_keypair().unwrap();

    let srk = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat",
        u64::MAX,
    )
    .unwrap();

    assert_eq!(srk.len(), 32);
}

#[test]
fn ratchet_with_zero_srk() {
    let current_srk = [0x00u8; 32]; // Zero SRK
    let kp_sender = generate_ratchet_keypair().unwrap();
    let kp_receiver = generate_ratchet_keypair().unwrap();

    let srk = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat",
        1,
    )
    .unwrap();

    assert_eq!(srk.len(), 32);
    assert_ne!(srk, [0u8; 32], "HKDF expands zero IKM into non-zero OKM");
}

#[test]
fn ratchet_isolation_between_conversations() {
    let current_srk = [0x11u8; 32];
    let kp_sender = generate_ratchet_keypair().unwrap();
    let kp_receiver = generate_ratchet_keypair().unwrap();

    let srk_a = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat-A",
        1,
    )
    .unwrap();

    let srk_b = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat-B",
        1,
    )
    .unwrap();

    assert_ne!(
        srk_a, srk_b,
        "Conversations with different chat IDs must derive distinct SRK values"
    );
}

#[test]
fn ratchet_forward_secrecy_simulation() {
    // Without the ephemeral private key, the attacker cannot reverse HKDF to find the old SRK.
    // We simulate by doing a ratchet and ensuring new SRK != old SRK,
    // and documenting that HKDF is a one-way function.
    let current_srk = [0x55u8; 32];
    let kp_sender = generate_ratchet_keypair().unwrap();
    let kp_receiver = generate_ratchet_keypair().unwrap();

    let new_srk = ratchet_srk_sender(
        &current_srk,
        kp_sender.secret_key(),
        &kp_receiver.public_key,
        b"chat",
        1,
    )
    .unwrap();

    assert_ne!(current_srk, new_srk);
    // Since HKDF relies on SHA-256 which is pre-image resistant, it's impossible to go from new_srk back to current_srk.
}

#[test]
fn ratchet_should_trigger_boundary() {
    let config = RatchetConfig {
        messages_per_ratchet: 50,
        ratchet_on_new_window: true,
    };

    assert!(!should_ratchet(49, false, &config));
    assert!(should_ratchet(50, false, &config));
    assert!(should_ratchet(51, false, &config));
    assert!(should_ratchet(0, true, &config));
    assert!(!should_ratchet(1, false, &config));
}

#[test]
fn ratchet_post_compromise_message_cannot_be_decrypted_with_leaked_old_srk() {
    let leaked_old_srk = [0x55u8; 32];
    let alice_kp = generate_ratchet_keypair().unwrap();
    let bob_kp = generate_ratchet_keypair().unwrap();
    let chat_id = b"pcs-e2e-chat";
    let ratchet_step = 42;

    let alice_new_srk = ratchet_srk_sender(
        &leaked_old_srk,
        alice_kp.secret_key(),
        &bob_kp.public_key,
        chat_id,
        ratchet_step,
    )
    .unwrap();
    let bob_new_srk = ratchet_srk_receiver(
        &leaked_old_srk,
        bob_kp.secret_key(),
        &alice_kp.public_key,
        chat_id,
        ratchet_step,
    )
    .unwrap();
    assert_eq!(alice_new_srk, bob_new_srk);

    let post_heal_key = derive_window_key(&alice_new_srk, 0).unwrap();
    let old_window_key = derive_window_key(&leaked_old_srk, 0).unwrap();
    let ciphertext =
        encrypt_aes256gcm_padded(&post_heal_key, b"post-heal message", Some(chat_id)).unwrap();

    assert!(
        decrypt_aes256gcm_padded(&old_window_key, &ciphertext, Some(chat_id)).is_err(),
        "A leaked pre-ratchet SRK must not decrypt post-ratchet messages"
    );
    let plaintext = decrypt_aes256gcm_padded(&post_heal_key, &ciphertext, Some(chat_id)).unwrap();
    assert_eq!(plaintext, b"post-heal message");
}

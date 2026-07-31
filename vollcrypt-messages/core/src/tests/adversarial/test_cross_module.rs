use crate::envelope::{pack_envelope, unpack_envelope};
use crate::kdf::{derive_srk, derive_window_key};
use crate::ratchet::{generate_ratchet_keypair, ratchet_srk_receiver, ratchet_srk_sender};
use crate::symmetric::{
    decrypt_aes256gcm, decrypt_aes256gcm_padded, encrypt_aes256gcm, encrypt_aes256gcm_padded,
};

#[test]
fn cross_use_srk_as_window_key() {
    let srk = [0x55u8; 32];
    let window_index = 1;
    let window_key = derive_window_key(&srk, window_index).unwrap();

    // SRK and Window Key should be distinct
    assert_ne!(
        &srk[..],
        window_key.as_slice(),
        "SRK and derived window key must not be exactly the same"
    );

    let plaintext = b"secret message";
    let encrypted_with_window = encrypt_aes256gcm(&window_key, plaintext, None).unwrap();

    // Try decrypting with SRK instead of window key
    let decrypt_attempt = decrypt_aes256gcm(&srk, &encrypted_with_window, None);
    assert!(
        decrypt_attempt.is_err(),
        "Must fail to decrypt if the raw SRK is mistakenly used instead of the derived Window Key"
    );
}

#[test]
fn full_ratchet_envelope_round_trip() {
    let chat_id = b"cross-module-chat";
    let dek = [0x42u8; 32];
    let initial_srk_vec = derive_srk(&dek, chat_id).unwrap();
    let initial_srk: [u8; 32] = initial_srk_vec.try_into().unwrap();

    let alice_ratchet = generate_ratchet_keypair().unwrap();
    let bob_ratchet = generate_ratchet_keypair().unwrap();
    let alice_srk = ratchet_srk_sender(
        &initial_srk,
        alice_ratchet.secret_key(),
        &bob_ratchet.public_key,
        chat_id,
        1,
    )
    .unwrap();
    let bob_srk = ratchet_srk_receiver(
        &initial_srk,
        bob_ratchet.secret_key(),
        &alice_ratchet.public_key,
        chat_id,
        1,
    )
    .unwrap();
    assert_eq!(alice_srk, bob_srk);

    let window_index = 7u32;
    let alice_window = derive_window_key(&alice_srk, u64::from(window_index)).unwrap();
    let bob_window = derive_window_key(&bob_srk, u64::from(window_index)).unwrap();
    let aad_hash = [0x24u8; 32];
    let plaintext = b"authenticated cross-module message";

    let encrypted = encrypt_aes256gcm_padded(&alice_window, plaintext, Some(&aad_hash)).unwrap();
    let envelope = pack_envelope(window_index, &aad_hash, &encrypted).unwrap();
    let (received_window, received_aad, received_blob) = unpack_envelope(&envelope).unwrap();

    assert_eq!(received_window, window_index);
    assert_eq!(received_aad, aad_hash);
    let decrypted =
        decrypt_aes256gcm_padded(&bob_window, &received_blob, Some(&received_aad)).unwrap();
    assert_eq!(decrypted, plaintext);
}

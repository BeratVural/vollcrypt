use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::kdf::derive_hkdf;
use crate::ratchet::CryptoError;
use crate::symmetric::{decrypt_aes256gcm_padded, encrypt_aes256gcm_padded};

/// Creates a sealed sender packet.
///
/// Hides the sender identity inside an encrypted inner envelope.
/// The outer envelope only contains the ephemeral public key and the ciphertext.
///
/// # Arguments
/// * `recipient_x25519_pub` - Recipient's X25519 static public key (32 bytes)
/// * `sender_id` - Identity of the sender (max 65535 bytes)
/// * `content` - The actual message payload to encrypt
///
/// # Returns
/// A scaled sender packet structured as:
/// [32 bytes] ephemeral_public_key
/// [12 bytes] iv
/// [N bytes]  ciphertext (containing inner plaintext: [2B sender_id_len | sender_id | content])
/// [16 bytes] auth_tag
///
/// # Security
/// Ephemeral X25519 key pair is generated per call using OsRng.
/// Ephemeral private key and shared secret are zeroized after usage.
pub fn seal(
    recipient_x25519_pub: &[u8; 32],
    sender_id: &[u8],
    content: &[u8],
    sender_signing_key: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    // 1. Generate ephemeral X25519 key pair
    let mut ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    // 2. ECDH to compute shared secret
    let recipient_pk = PublicKey::from(*recipient_x25519_pub);
    let dh = ephemeral_sk.diffie_hellman(&recipient_pk);
    if !dh.was_contributory() {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut shared_secret = dh.to_bytes();

    // 3. Derive encryption key using HKDF-SHA256
    let mut encryption_key = derive_hkdf(
        &shared_secret,
        Some(ephemeral_pk.as_bytes()),
        Some(b"vollchat-sealed-sender-v1"),
        32,
    )
    .map_err(|_| CryptoError::InvalidKeyLength)?;

    // Ensure shared_secret is zeroized immediately after key derivation
    shared_secret.zeroize();

    // Compute Ed25519 signature over sender_id and content
    let mut sig_payload = Vec::with_capacity(sender_id.len() + content.len());
    sig_payload.extend_from_slice(sender_id);
    sig_payload.extend_from_slice(content);

    let mut sk_copy = [0u8; 32];
    sk_copy.copy_from_slice(sender_signing_key);
    let signature = crate::keys::sign_message(&sk_copy, &sig_payload)
        .map_err(|_| CryptoError::RatchetComputationFailed)?;
    sk_copy.zeroize();

    // 4. Pack inner plaintext: [2 bytes sender_id_len | sender_id | 64 bytes signature | content]
    let sender_id_len =
        u16::try_from(sender_id.len()).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut inner_plaintext = Vec::with_capacity(2 + sender_id.len() + 64 + content.len());
    inner_plaintext.extend_from_slice(&sender_id_len.to_be_bytes());
    inner_plaintext.extend_from_slice(sender_id);
    inner_plaintext.extend_from_slice(&signature);
    inner_plaintext.extend_from_slice(content);

    // 5. Encrypt with AES-256-GCM (returns [12B IV][ciphertext][16B tag])
    let encrypted_inner = encrypt_aes256gcm_padded(&encryption_key, &inner_plaintext, None)
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    // Zeroize intermediate encryption key and plaintext
    encryption_key.zeroize();
    inner_plaintext.zeroize();

    // 6. Pack final sealed packet: [32B ephemeral_pk][encrypted_inner]
    let mut sealed_packet = Vec::with_capacity(32 + encrypted_inner.len());
    sealed_packet.extend_from_slice(ephemeral_pk.as_bytes());
    sealed_packet.extend_from_slice(&encrypted_inner);

    ephemeral_sk.zeroize();

    Ok(sealed_packet)
}

/// Unseals a sealed sender packet and verifies the sender's signature against the log chain.
///
/// # Arguments
/// * `sealed_packet` - The output from `seal()`
/// * `our_x25519_sk` - The recipient's X25519 static secret key (32 bytes)
/// * `entries_json` - Key log chain entries JSON to fetch the sender's active public key
///
/// # Returns
/// `(sender_id, content)`
pub fn unseal(
    sealed_packet: &[u8],
    our_x25519_sk: &[u8; 32],
    entries_json: Option<&str>,
    trusted_sender_public_key: Option<&[u8; 32]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // 1. Check minimum length (32 bytes ephemeral_pk + 12 bytes IV + 16 bytes tag)
    if sealed_packet.len() < 32 + 12 + 16 {
        return Err(CryptoError::InvalidSealedPacketFormat);
    }

    // 2. Parse packet
    let ephemeral_pk_bytes: [u8; 32] = sealed_packet[0..32].try_into().unwrap();
    let encrypted_inner = &sealed_packet[32..];

    // 3. ECDH to compute shared secret
    let ephemeral_pk = PublicKey::from(ephemeral_pk_bytes);
    let secret = StaticSecret::from(*our_x25519_sk);
    let dh = secret.diffie_hellman(&ephemeral_pk);
    if !dh.was_contributory() {
        return Err(CryptoError::InvalidSealedPacketFormat);
    }
    let mut shared_secret = dh.to_bytes();

    // 4. Derive encryption key using HKDF-SHA256
    let mut encryption_key = derive_hkdf(
        &shared_secret,
        Some(&ephemeral_pk_bytes),
        Some(b"vollchat-sealed-sender-v1"),
        32,
    )
    .map_err(|_| CryptoError::InvalidKeyLength)?;
    shared_secret.zeroize();

    // 5. Decrypt AES-256-GCM
    let mut inner_plaintext = match decrypt_aes256gcm_padded(&encryption_key, encrypted_inner, None)
    {
        Ok(pt) => pt,
        Err(_) => {
            encryption_key.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
    };
    encryption_key.zeroize();

    // 6. Parse inner plaintext
    if inner_plaintext.len() < 2 + 64 {
        inner_plaintext.zeroize();
        return Err(CryptoError::InvalidSealedPacketFormat);
    }

    let sender_id_len = u16::from_be_bytes([inner_plaintext[0], inner_plaintext[1]]) as usize;

    if inner_plaintext.len() < 2 + sender_id_len + 64 {
        inner_plaintext.zeroize();
        return Err(CryptoError::InvalidSealedPacketFormat);
    }

    let sender_id = inner_plaintext[2..2 + sender_id_len].to_vec();
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&inner_plaintext[2 + sender_id_len..2 + sender_id_len + 64]);
    let content = inner_plaintext[2 + sender_id_len + 64..].to_vec();

    inner_plaintext.zeroize();

    // 7. Verify the sender's signature using the log chain
    match entries_json {
        Some(json_str) => {
            let entries: Vec<crate::key_log::KeyLogEntry> = serde_json::from_str(json_str)
                .map_err(|_| CryptoError::InvalidSealedPacketFormat)?;
            let log = crate::key_log::KeyLog { entries };

            // Verify the integrity of the key log chain first
            log.verify_chain()?;

            // Find the current active public key for this sender_id.
            // The caller must pin the expected sender public key out-of-band; a self-signed
            // key-log JSON alone is not a trust root.
            let active_pk = log
                .current_key_for(&sender_id)
                .ok_or(CryptoError::KeyLogInvalidSignature { at_index: 0 })?;
            let trusted_pk = trusted_sender_public_key
                .ok_or(CryptoError::KeyLogInvalidSignature { at_index: 0 })?;
            if active_pk != trusted_pk {
                return Err(CryptoError::KeyLogInvalidSignature { at_index: 0 });
            }

            let mut sig_payload = Vec::with_capacity(sender_id.len() + content.len());
            sig_payload.extend_from_slice(&sender_id);
            sig_payload.extend_from_slice(&content);

            let is_sig_valid = crate::keys::verify_signature(active_pk, &sig_payload, &signature);
            if !is_sig_valid {
                return Err(CryptoError::KeyLogInvalidSignature { at_index: 0 });
            }
        }
        None => {
            return Err(CryptoError::KeyLogInvalidSignature { at_index: 0 });
        }
    }

    Ok((sender_id, content))
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_log::{GENESIS_HASH, KeyAction, create_entry};
    use crate::keys::{generate_ed25519_keypair, generate_x25519_keypair};

    fn setup_test_keys() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], String) {
        let bob_kp = generate_x25519_keypair();
        let bob_sk: [u8; 32] = bob_kp.0.try_into().unwrap();
        let bob_pk: [u8; 32] = bob_kp.1.try_into().unwrap();

        let (alice_sk, alice_pk) = generate_ed25519_keypair();
        let mut alice_pk_arr = [0u8; 32];
        alice_pk_arr.copy_from_slice(&alice_pk);
        let mut alice_sk_arr = [0u8; 32];
        alice_sk_arr.copy_from_slice(&alice_sk);

        let entry = create_entry(
            b"alice",
            &alice_pk_arr,
            1000,
            &GENESIS_HASH,
            KeyAction::Add,
            &alice_sk_arr,
        )
        .unwrap();
        let entries = vec![entry];
        let entries_json = serde_json::to_string(&entries).unwrap();

        (bob_sk, bob_pk, alice_sk_arr, alice_pk_arr, entries_json)
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let (bob_sk, bob_pk, alice_sk, alice_pk, entries_json) = setup_test_keys();
        let sender_id = b"alice";
        let content = b"Secret message content";

        let sealed = seal(&bob_pk, sender_id, content, &alice_sk).unwrap();
        let (recovered_sender, recovered_content) =
            unseal(&sealed, &bob_sk, Some(&entries_json), Some(&alice_pk)).unwrap();

        assert_eq!(recovered_sender, sender_id);
        assert_eq!(recovered_content, content);
    }

    #[test]
    fn sealed_sender_rejects_untrusted_self_signed_keylog() {
        let bob_kp = generate_x25519_keypair();
        let bob_sk: [u8; 32] = bob_kp.0.try_into().unwrap();
        let bob_pk: [u8; 32] = bob_kp.1.try_into().unwrap();

        let (trusted_alice_sk, trusted_alice_pk) = generate_ed25519_keypair();
        let mut trusted_alice_pk_arr = [0u8; 32];
        trusted_alice_pk_arr.copy_from_slice(&trusted_alice_pk);
        let mut trusted_alice_sk_arr = [0u8; 32];
        trusted_alice_sk_arr.copy_from_slice(&trusted_alice_sk);

        let (attacker_sk, attacker_pk) = generate_ed25519_keypair();
        let mut attacker_pk_arr = [0u8; 32];
        attacker_pk_arr.copy_from_slice(&attacker_pk);
        let mut attacker_sk_arr = [0u8; 32];
        attacker_sk_arr.copy_from_slice(&attacker_sk);

        let forged_entry = create_entry(
            b"alice",
            &attacker_pk_arr,
            1000,
            &GENESIS_HASH,
            KeyAction::Add,
            &attacker_sk_arr,
        )
        .unwrap();
        let forged_entries_json = serde_json::to_string(&vec![forged_entry]).unwrap();
        let forged = seal(&bob_pk, b"alice", b"forged content", &attacker_sk_arr).unwrap();

        let result = unseal(
            &forged,
            &bob_sk,
            Some(&forged_entries_json),
            Some(&trusted_alice_pk_arr),
        );
        assert!(
            result.is_err(),
            "A self-signed attacker key-log must not be accepted without matching the pinned sender key"
        );

        trusted_alice_sk_arr.zeroize();
    }

    #[test]
    fn test_each_seal_produces_different_packet() {
        let (_, bob_pk, alice_sk, _, _) = setup_test_keys();
        let sender_id = b"alice";
        let content = b"same content";

        let sealed_1 = seal(&bob_pk, sender_id, content, &alice_sk).unwrap();
        let sealed_2 = seal(&bob_pk, sender_id, content, &alice_sk).unwrap();

        assert_ne!(
            sealed_1, sealed_2,
            "Each seal call must produce a different packet"
        );
    }

    #[test]
    fn test_sender_identity_hidden_in_packet() {
        let (_, bob_pk, alice_sk, _, _) = setup_test_keys();
        let sender_id = b"alice";
        let content = b"content";

        let sealed = seal(&bob_pk, sender_id, content, &alice_sk).unwrap();

        let alice_str = b"alice";
        let windows: Vec<&[u8]> = sealed.windows(alice_str.len()).collect();
        assert!(
            !windows.contains(&alice_str.as_ref()),
            "sender_id must not appear as plaintext in the packet"
        );
    }

    #[test]
    fn test_wrong_recipient_key_fails() {
        let (_, bob_pk, alice_sk, alice_pk, entries_json) = setup_test_keys();

        let mallory_kp = generate_x25519_keypair();
        let mallory_sk: [u8; 32] = mallory_kp.0.try_into().unwrap();

        let sealed = seal(&bob_pk, b"alice", b"content", &alice_sk).unwrap();

        // Mallory tries to open Bob's packet
        let result = unseal(&sealed, &mallory_sk, Some(&entries_json), Some(&alice_pk));

        assert!(result.is_err(), "Unsealing with wrong key must fail");
        match result.unwrap_err() {
            CryptoError::DecryptionFailed => {}
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_tampered_packet_fails() {
        let (bob_sk, bob_pk, alice_sk, alice_pk, entries_json) = setup_test_keys();

        let mut sealed = seal(&bob_pk, b"alice", b"content", &alice_sk).unwrap();

        // Tamper with one byte in the ciphertext part
        let tamper_pos = 40;
        sealed[tamper_pos] ^= 0xFF;

        let result = unseal(&sealed, &bob_sk, Some(&entries_json), Some(&alice_pk));
        assert!(result.is_err(), "Tampered packet must be rejected");
    }

    #[test]
    fn test_truncated_packet_fails() {
        let (bob_sk, bob_pk, alice_sk, alice_pk, entries_json) = setup_test_keys();

        let sealed = seal(&bob_pk, b"alice", b"content", &alice_sk).unwrap();

        let truncated = &sealed[..30];
        let result = unseal(truncated, &bob_sk, Some(&entries_json), Some(&alice_pk));

        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::InvalidSealedPacketFormat => {}
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_empty_content_supported() {
        let (bob_sk, bob_pk, alice_sk, alice_pk, entries_json) = setup_test_keys();

        let sealed = seal(&bob_pk, b"alice", b"", &alice_sk).unwrap();
        let (sender, content) =
            unseal(&sealed, &bob_sk, Some(&entries_json), Some(&alice_pk)).unwrap();
        assert_eq!(sender, b"alice");
        assert_eq!(content, b"");
    }

    #[test]
    fn test_large_content_supported() {
        let (bob_sk, bob_pk, alice_sk, alice_pk, entries_json) = setup_test_keys();

        let large_content = vec![0x42u8; 1024 * 1024];
        let sealed = seal(&bob_pk, b"alice", &large_content, &alice_sk).unwrap();
        let (_, recovered) =
            unseal(&sealed, &bob_sk, Some(&entries_json), Some(&alice_pk)).unwrap();
        assert_eq!(recovered, large_content);
    }

    #[test]
    fn test_revoked_sender_fails() {
        let (bob_sk, bob_pk, alice_sk, alice_pk, _) = setup_test_keys();

        // Register then revoke alice key
        let entry_add = create_entry(
            b"alice",
            &alice_pk,
            1000,
            &GENESIS_HASH,
            KeyAction::Add,
            &alice_sk,
        )
        .unwrap();
        let hash_add = entry_add.compute_hash();
        let entry_revoke = create_entry(
            b"alice",
            &alice_pk,
            2000,
            &hash_add,
            KeyAction::Revoke,
            &alice_sk,
        )
        .unwrap();
        let entries = vec![entry_add, entry_revoke];
        let entries_json = serde_json::to_string(&entries).unwrap();

        let sealed = seal(&bob_pk, b"alice", b"Secret", &alice_sk).unwrap();
        let result = unseal(&sealed, &bob_sk, Some(&entries_json), Some(&alice_pk));

        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::KeyLogInvalidSignature { at_index: 0 } => {}
            e => panic!("Unexpected error: {:?}", e),
        }
    }
}

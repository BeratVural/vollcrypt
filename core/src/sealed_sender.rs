use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::kdf::derive_hkdf;
use crate::symmetric::{decrypt_aes256gcm_padded, encrypt_aes256gcm_padded};
use crate::ratchet::CryptoError;

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
) -> Result<Vec<u8>, CryptoError> {
    // 1. Generate ephemeral X25519 key pair
    let mut ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    // 2. ECDH to compute shared secret
    let recipient_pk = PublicKey::from(*recipient_x25519_pub);
    let mut shared_secret = ephemeral_sk.diffie_hellman(&recipient_pk).to_bytes();

    // 3. Derive encryption key using HKDF-SHA256
    let mut encryption_key = derive_hkdf(
        &shared_secret,
        Some(ephemeral_pk.as_bytes()),
        Some(b"vollchat-sealed-sender-v1"),
        32,
    ).map_err(|_| CryptoError::InvalidKeyLength)?;

    // Ensure shared_secret is zeroized immediately after key derivation
    shared_secret.zeroize();

    // 4. Pack inner plaintext: [2 bytes sender_id_len | sender_id | content]
    let sender_id_len = sender_id.len() as u16;
    let mut inner_plaintext = Vec::with_capacity(2 + sender_id.len() + content.len());
    inner_plaintext.extend_from_slice(&sender_id_len.to_be_bytes());
    inner_plaintext.extend_from_slice(sender_id);
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

    // 7. Ephemeral Secret Key automatically zeroizes on drop (StaticSecret implements ZeroizeOnDrop natively in later versions, but we manually zeroize if possible, or it handles itself)
    // Actually, x25519_dalek::StaticSecret zeroizes on drop.
    ephemeral_sk.zeroize();

    Ok(sealed_packet)
}

/// Unseals a sealed sender packet.
///
/// # Arguments
/// * `sealed_packet` - The output from `seal()`
/// * `our_x25519_sk` - The recipient's X25519 static secret key (32 bytes)
///
/// # Returns
/// `(sender_id, content)`
pub fn unseal(
    sealed_packet: &[u8],
    our_x25519_sk: &[u8; 32],
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
    let mut shared_secret = secret.diffie_hellman(&ephemeral_pk).to_bytes();

    // 4. Derive encryption key using HKDF-SHA256
    let mut encryption_key = derive_hkdf(
        &shared_secret,
        Some(&ephemeral_pk_bytes),
        Some(b"vollchat-sealed-sender-v1"),
        32,
    ).map_err(|_| CryptoError::InvalidKeyLength)?;
    shared_secret.zeroize();

    // 5. Decrypt AES-256-GCM
    let mut inner_plaintext = match decrypt_aes256gcm_padded(&encryption_key, encrypted_inner, None) {
        Ok(pt) => pt,
        Err(_) => {
            encryption_key.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
    };
    encryption_key.zeroize();

    // 6. Parse inner plaintext
    if inner_plaintext.len() < 2 {
        inner_plaintext.zeroize();
        return Err(CryptoError::InvalidSealedPacketFormat);
    }

    let sender_id_len = u16::from_be_bytes([inner_plaintext[0], inner_plaintext[1]]) as usize;
    
    if inner_plaintext.len() < 2 + sender_id_len {
        inner_plaintext.zeroize();
        return Err(CryptoError::InvalidSealedPacketFormat);
    }

    let sender_id = inner_plaintext[2..2 + sender_id_len].to_vec();
    let content = inner_plaintext[2 + sender_id_len..].to_vec();

    inner_plaintext.zeroize();

    Ok((sender_id, content))
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_x25519_keypair;

    #[test]
    fn test_seal_unseal_roundtrip() {
        let bob_kp = generate_x25519_keypair();
        // bob_kp.0 = secret(32B), bob_kp.1 = public(32B)
        let bob_sk: [u8; 32] = bob_kp.0.clone().try_into().unwrap();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();

        let sender_id = b"alice@vollsign.com";
        let content = b"Secret message content";

        let sealed = seal(&bob_pk, sender_id, content).unwrap();
        let (recovered_sender, recovered_content) = unseal(&sealed, &bob_sk).unwrap();

        assert_eq!(recovered_sender, sender_id);
        assert_eq!(recovered_content, content);
    }

    #[test]
    fn test_each_seal_produces_different_packet() {
        // Every seal call should generate a different ephemeral key, thus a different packet
        let bob_kp = generate_x25519_keypair();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();
        
        let sender_id = b"alice";
        let content = b"same content";

        let sealed_1 = seal(&bob_pk, sender_id, content).unwrap();
        let sealed_2 = seal(&bob_pk, sender_id, content).unwrap();

        assert_ne!(
            sealed_1, sealed_2,
            "Each seal call must produce a different packet"
        );
    }

    #[test]
    fn test_sender_identity_hidden_in_packet() {
        // The sender_id must not appear as plaintext inside the packet
        let bob_kp = generate_x25519_keypair();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();

        let sender_id = b"alice@vollsign.com";
        let content = b"content";

        let sealed = seal(&bob_pk, sender_id, content).unwrap();

        let alice_str = b"alice";
        let windows: Vec<&[u8]> = sealed.windows(alice_str.len()).collect();
        assert!(
            !windows.contains(&alice_str.as_ref()),
            "sender_id must not appear as plaintext in the packet"
        );
    }

    #[test]
    fn test_wrong_recipient_key_fails() {
        // Unsealing with a different recipient's key must fail
        let bob_kp = generate_x25519_keypair();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();

        let mallory_kp = generate_x25519_keypair();
        let mallory_sk: [u8; 32] = mallory_kp.0.clone().try_into().unwrap();

        let sealed = seal(&bob_pk, b"alice", b"content").unwrap();

        // Mallory tries to open Bob's packet
        let result = unseal(&sealed, &mallory_sk);

        assert!(result.is_err(), "Unsealing with wrong key must fail");
        match result.unwrap_err() {
            CryptoError::DecryptionFailed => {}
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_tampered_packet_fails() {
        // If the packet is altered, auth tag verification must fail
        let bob_kp = generate_x25519_keypair();
        let bob_sk: [u8; 32] = bob_kp.0.clone().try_into().unwrap();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();

        let mut sealed = seal(&bob_pk, b"alice", b"content").unwrap();

        // Tamper with one byte in the ciphertext part (after 32B ephemeral key + 8B into IV/Ciphertext space)
        let tamper_pos = 40;
        sealed[tamper_pos] ^= 0xFF;

        let result = unseal(&sealed, &bob_sk);
        assert!(result.is_err(), "Tampered packet must be rejected");
    }

    #[test]
    fn test_truncated_packet_fails() {
        let bob_kp = generate_x25519_keypair();
        let bob_sk: [u8; 32] = bob_kp.0.clone().try_into().unwrap();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();

        let sealed = seal(&bob_pk, b"alice", b"content").unwrap();

        // Under minimum length 32 + 12 + 16 = 60
        let truncated = &sealed[..30];
        let result = unseal(truncated, &bob_sk);

        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::InvalidSealedPacketFormat => {}
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_empty_content_supported() {
        // Empty payload must be supported (for notifications/sync markers)
        let bob_kp = generate_x25519_keypair();
        let bob_sk: [u8; 32] = bob_kp.0.clone().try_into().unwrap();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();

        let sealed = seal(&bob_pk, b"alice", b"").unwrap();
        let (sender, content) = unseal(&sealed, &bob_sk).unwrap();
        assert_eq!(sender, b"alice");
        assert_eq!(content, b"");
    }

    #[test]
    fn test_large_content_supported() {
        // 1 MB content
        let bob_kp = generate_x25519_keypair();
        let bob_sk: [u8; 32] = bob_kp.0.clone().try_into().unwrap();
        let bob_pk: [u8; 32] = bob_kp.1.clone().try_into().unwrap();

        let large_content = vec![0x42u8; 1024 * 1024];
        let sealed = seal(&bob_pk, b"alice", &large_content).unwrap();
        let (_, recovered) = unseal(&sealed, &bob_sk).unwrap();
        assert_eq!(recovered, large_content);
    }
}

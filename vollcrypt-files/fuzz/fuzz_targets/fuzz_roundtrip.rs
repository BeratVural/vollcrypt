#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use vollcrypt_files_core::*;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    // Construct a valid Header using Unstructured
    let version = if u.ratio(1, 2).unwrap_or(true) { 1 } else { 2 };
    
    let mode_choice = u.int_in_range(0..=2).unwrap_or(0);
    let mode = match mode_choice {
        0 => Mode::Password,
        1 => Mode::Recipient,
        _ => Mode::Group,
    };
    
    let cipher_id = CipherId::Aes256Gcm;
    
    let mut file_id = [0u8; 16];
    if u.fill_buffer(&mut file_id).is_err() { return; }
    
    let chunk_size = u.arbitrary::<u32>().unwrap_or(65536);
    let plaintext_size = u.arbitrary::<u64>().unwrap_or(0);
    
    let mut merkle_root = [0u8; 32];
    if u.fill_buffer(&mut merkle_root).is_err() { return; }
    
    // Construct some wraps
    let num_wraps = u.int_in_range(0..=5).unwrap_or(0);
    let mut wraps = Vec::new();
    for _ in 0..num_wraps {
        let wrap_choice = u.int_in_range(0..=3).unwrap_or(0);
        let wrap = match wrap_choice {
            0 => {
                let iters = u.arbitrary::<u32>().unwrap_or(1000);
                let mut salt = [0u8; 16];
                if u.fill_buffer(&mut salt).is_err() { return; }
                let mut wrapped_dek = [0u8; 40];
                if u.fill_buffer(&mut wrapped_dek).is_err() { return; }
                WrapEntry::PasswordPbkdf2 { iterations: iters, salt, wrapped_dek }
            }
            1 => {
                let m = u.arbitrary::<u32>().unwrap_or(4096);
                let t = u.arbitrary::<u32>().unwrap_or(3);
                let p = u.arbitrary::<u32>().unwrap_or(1);
                let mut salt = [0u8; 16];
                if u.fill_buffer(&mut salt).is_err() { return; }
                let mut wrapped_dek = [0u8; 40];
                if u.fill_buffer(&mut wrapped_dek).is_err() { return; }
                WrapEntry::PasswordArgon2id { m_cost: m, t_cost: t, p_cost: p, salt, wrapped_dek }
            }
            2 => {
                let mut recipient_id = [0u8; 16];
                if u.fill_buffer(&mut recipient_id).is_err() { return; }
                let gk_version = u.arbitrary::<u32>().unwrap_or(1);
                let mut x25519_ephemeral = [0u8; 32];
                if u.fill_buffer(&mut x25519_ephemeral).is_err() { return; }
                let mut mlkem_ciphertext = vec![0u8; 1088];
                if u.fill_buffer(&mut mlkem_ciphertext).is_err() { return; }
                let mut wrapped_dek = [0u8; 40];
                if u.fill_buffer(&mut wrapped_dek).is_err() { return; }
                WrapEntry::HybridKem {
                    recipient_id,
                    gk_version,
                    x25519_ephemeral,
                    mlkem_ciphertext,
                    wrapped_dek,
                }
            }
            _ => {
                let mut group_id = [0u8; 16];
                if u.fill_buffer(&mut group_id).is_err() { return; }
                let gk_version = u.arbitrary::<u32>().unwrap_or(1);
                let mut wrapped_dek = [0u8; 40];
                if u.fill_buffer(&mut wrapped_dek).is_err() { return; }
                WrapEntry::GroupWrap { group_id, gk_version, wrapped_dek }
            }
        };
        wraps.push(wrap);
    }
    
    let mut signed_metadata = None;
    let mut signature = None;
    if version == 2 {
        let is_plain = u.ratio(1, 2).unwrap_or(true);
        let timestamp = u.arbitrary::<u64>().unwrap_or(0);
        if is_plain {
            let mut signer_pubkey = [0u8; 32];
            if u.fill_buffer(&mut signer_pubkey).is_err() { return; }
            let mut key_log_id = [0u8; 32];
            if u.fill_buffer(&mut key_log_id).is_err() { return; }
            signed_metadata = Some(SignedMetadata::Plain {
                signer_pubkey,
                timestamp,
                key_log_id,
            });
        } else {
            let mut sealed_group_id = [0u8; 16];
            if u.fill_buffer(&mut sealed_group_id).is_err() { return; }
            let sealed_gk_version = u.arbitrary::<u32>().unwrap_or(1);
            let mut iv = [0u8; 12];
            if u.fill_buffer(&mut iv).is_err() { return; }
            let payload_len = u.int_in_range(0..=100).unwrap_or(0);
            let mut sealed_payload = vec![0u8; payload_len];
            if u.fill_buffer(&mut sealed_payload).is_err() { return; }
            let mut sealed_tag = [0u8; 16];
            if u.fill_buffer(&mut sealed_tag).is_err() { return; }
            signed_metadata = Some(SignedMetadata::Sealed {
                sealed_group_id,
                sealed_gk_version,
                iv,
                sealed_payload,
                sealed_tag,
                timestamp,
            });
        }
        let mut sig = [0u8; 64];
        if u.fill_buffer(&mut sig).is_err() { return; }
        signature = Some(sig);
    }

    let header = Header {
        version,
        mode,
        cipher_id,
        file_id,
        chunk_size,
        plaintext_size,
        merkle_root,
        wraps,
        signed_metadata,
        signature,
    };

    // Roundtrip verification: write -> parse -> compare serialized representations
    let serialized1 = header.write();
    if let Ok((parsed, _)) = Header::parse(&serialized1) {
        let serialized2 = parsed.write();
        assert_eq!(serialized1, serialized2, "Serialization mismatch in roundtrip!");
    }
});

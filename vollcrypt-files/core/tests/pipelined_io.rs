use std::io::Cursor;
use vollcrypt_files_core::{
    encrypt_file_pipelined, decrypt_file_pipelined, generate_dek, generate_file_id,
    wrap_dek_with_password, unwrap_dek_with_password, KdfChoice, Mode, PipelinedSignInfo,
    FileFormatError, ed25519_keypair_generate, verify_header_signature_plain,
};

#[test]
fn test_pipelined_roundtrip_small() {
    let plaintext = b"Hello from the parallel pipelined world! This is a simple verification test.".to_vec();
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 16; // Very small chunk size to trigger multiple chunks

    let password = b"pipeline-password";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let mut dest = Cursor::new(Vec::new());
    
    // Encrypt
    let encrypt_res = encrypt_file_pipelined(
        Cursor::new(plaintext.clone()),
        &mut dest,
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        3, // 3 worker threads
        None,
    );
    assert!(encrypt_res.is_ok());

    // Decrypt
    let mut decrypted = Cursor::new(Vec::new());
    dest.set_position(0);

    let decrypt_res = decrypt_file_pipelined(
        dest,
        &mut decrypted,
        &dek,
        3, // 3 worker threads
    );
    assert!(decrypt_res.is_ok());
    assert_eq!(decrypted.into_inner(), plaintext);
}

#[test]
fn test_pipelined_roundtrip_large() {
    let plaintext = vec![0x42u8; 3 * 1024 * 1024 + 50]; // ~3 MB
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 256 * 1024; // 256 KB chunks

    let password = b"pipeline-password-large";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let mut dest = Cursor::new(Vec::new());
    
    // Encrypt
    let encrypt_res = encrypt_file_pipelined(
        Cursor::new(plaintext.clone()),
        &mut dest,
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        4, // 4 worker threads
        None,
    );
    assert!(encrypt_res.is_ok());

    // Decrypt
    let mut decrypted = Cursor::new(Vec::new());
    dest.set_position(0);

    let decrypt_res = decrypt_file_pipelined(
        dest,
        &mut decrypted,
        &dek,
        4, // 4 worker threads
    );
    assert!(decrypt_res.is_ok());
    assert_eq!(decrypted.into_inner(), plaintext);
}

#[test]
fn test_pipelined_signed_header_plain() {
    let plaintext = b"Signed metadata test payload.".to_vec();
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 100;

    let password = b"password";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let (signer_pk, signer_sk) = ed25519_keypair_generate();
    let sign_info = PipelinedSignInfo::Plain {
        signer_ed25519_pk: signer_pk,
        signer_ed25519_sk: signer_sk,
        key_log_id: [0x55; 32],
        timestamp: 9876543210,
    };

    let mut dest = Cursor::new(Vec::new());
    
    // Encrypt with signing info
    let header = encrypt_file_pipelined(
        Cursor::new(plaintext.clone()),
        &mut dest,
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        2,
        Some(sign_info),
    ).unwrap();

    // Verify signature passes
    assert!(verify_header_signature_plain(&header).is_ok());

    // Decrypt and verify roundtrip
    let mut decrypted = Cursor::new(Vec::new());
    dest.set_position(0);

    let decrypt_res = decrypt_file_pipelined(
        dest,
        &mut decrypted,
        &dek,
        2,
    );
    assert!(decrypt_res.is_ok());
    assert_eq!(decrypted.into_inner(), plaintext);
}

#[test]
fn test_pipelined_tampered_chunk_rejected() {
    let plaintext = vec![0xAA; 1024];
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 128;

    let password = b"tamper-pass";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let mut dest = Cursor::new(Vec::new());
    encrypt_file_pipelined(
        Cursor::new(plaintext),
        &mut dest,
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        2,
        None,
    ).unwrap();

    // Tamper one byte of the ciphertext in the output buffer.
    // Chunk envelopes start after header. Let's find header length.
    let bytes = dest.into_inner();
    let mut tampered_bytes = bytes.clone();
    
    // Tamper the very last byte of the stream
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 0xFF;

    let tampered_source = Cursor::new(tampered_bytes);
    let mut decrypted = Cursor::new(Vec::new());

    let decrypt_res = decrypt_file_pipelined(
        tampered_source,
        &mut decrypted,
        &dek,
        2,
    );
    
    // Decrypt should fail due to AEAD tag verification failure
    assert!(decrypt_res.is_err());
    assert!(matches!(decrypt_res.unwrap_err(), FileFormatError::AesGcmDecryptFailed));
}

#[test]
fn test_pipelined_wrong_password_fails() {
    let plaintext = b"Secret data".to_vec();
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 50;

    let correct_password = b"correct-password";
    let wrong_password = b"wrong-password";
    let wrap = wrap_dek_with_password(&dek, correct_password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let mut dest = Cursor::new(Vec::new());
    let header = encrypt_file_pipelined(
        Cursor::new(plaintext),
        &mut dest,
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        2,
        None,
    ).unwrap();

    // Try to unwrap the DEK using the parsed header wraps with the wrong password
    let recovered_dek_result = unwrap_dek_with_password(&header.wraps[0], wrong_password);
    assert!(matches!(recovered_dek_result, Err(FileFormatError::WrongPassword)));
}

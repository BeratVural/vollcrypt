use std::io::{Cursor, Read, Seek, SeekFrom};
use vollcrypt_files_core::{
    decrypt_file_pipelined, hybrid_keypair_generate, encrypt_file_pipelined, generate_dek,
    generate_file_id, unwrap_dek_with_password, verify_header_signature_plain,
    wrap_dek_with_password, FileFormatError, KdfChoice, Mode, PipelinedSignInfo,
};

#[test]
fn test_pipelined_roundtrip_small() {
    let plaintext =
        b"Hello from the parallel pipelined world! This is a simple verification test.".to_vec();
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 16; // Very small chunk size to trigger multiple chunks

    let password = b"pipeline-password";
    let wrap =
        wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let dest = tempfile::tempfile().unwrap();

    // Encrypt
    let encrypt_res = encrypt_file_pipelined(
        Cursor::new(plaintext.clone()),
        dest.try_clone().unwrap(),
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        3, // 3 worker threads
        None,
        None,
    );
    assert!(encrypt_res.is_ok());

    // Decrypt
    let mut decrypted = Vec::new();
    let mut read_dest = dest;
    read_dest.seek(SeekFrom::Start(0)).unwrap();

    let decrypt_res = decrypt_file_pipelined(
        read_dest,
        &mut decrypted,
        &dek,
        3, // 3 worker threads
    );
    if let Err(ref e) = decrypt_res {
        eprintln!("Decrypt error small: {:?}", e);
    }
    assert!(decrypt_res.is_ok());
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_pipelined_roundtrip_large() {
    let plaintext = vec![0x42u8; 3 * 1024 * 1024 + 50]; // ~3 MB
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 256 * 1024; // 256 KB chunks

    let password = b"pipeline-password-large";
    let wrap =
        wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let dest = tempfile::tempfile().unwrap();

    // Encrypt
    let encrypt_res = encrypt_file_pipelined(
        Cursor::new(plaintext.clone()),
        dest.try_clone().unwrap(),
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        4, // 4 worker threads
        None,
        None,
    );
    assert!(encrypt_res.is_ok());

    // Decrypt
    let mut decrypted = Vec::new();
    let mut read_dest = dest;
    read_dest.seek(SeekFrom::Start(0)).unwrap();

    let decrypt_res = decrypt_file_pipelined(
        read_dest,
        &mut decrypted,
        &dek,
        4, // 4 worker threads
    );
    assert!(decrypt_res.is_ok());
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_pipelined_signed_header_plain() {
    let plaintext = b"Signed metadata test payload.".to_vec();
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 100;

    let password = b"password";
    let wrap =
        wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let (signer_pk, signer_sk) = hybrid_keypair_generate();
    let sign_info = PipelinedSignInfo::Plain {
        signer_pk,
        signer_sk,
        key_log_id: [0x55; 32],
        timestamp: 9876543210,
    };

    let dest = tempfile::tempfile().unwrap();

    // Encrypt with signing info
    let header = encrypt_file_pipelined(
        Cursor::new(plaintext.clone()),
        dest.try_clone().unwrap(),
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        2,
        Some(sign_info),
        None,
    )
    .unwrap();

    // Verify signature passes
    assert!(verify_header_signature_plain(&header, vollcrypt_files_core::VerificationPolicy::RequireSigned).is_ok());

    // Decrypt and verify roundtrip
    let mut decrypted = Vec::new();
    let mut read_dest = dest;
    read_dest.seek(SeekFrom::Start(0)).unwrap();

    let decrypt_res = decrypt_file_pipelined(read_dest, &mut decrypted, &dek, 2);
    assert!(decrypt_res.is_ok());
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_pipelined_tampered_chunk_rejected() {
    let plaintext = vec![0xAA; 1024];
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 128;

    let password = b"tamper-pass";
    let wrap =
        wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let mut dest = tempfile::tempfile().unwrap();
    encrypt_file_pipelined(
        Cursor::new(plaintext),
        dest.try_clone().unwrap(),
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        2,
        None,
        None,
    )
    .unwrap();

    // Tamper one byte of the ciphertext in the output buffer.
    let mut bytes = Vec::new();
    dest.seek(SeekFrom::Start(0)).unwrap();
    dest.read_to_end(&mut bytes).unwrap();

    let mut tampered_bytes = bytes.clone();

    // Tamper the very last byte of the stream
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 0xFF;

    let tampered_source = Cursor::new(tampered_bytes);
    let mut decrypted = Vec::new();

    let decrypt_res = decrypt_file_pipelined(tampered_source, &mut decrypted, &dek, 2);

    // Decrypt should fail due to AEAD tag verification failure
    assert!(decrypt_res.is_err());
    assert!(matches!(
        decrypt_res.unwrap_err(),
        FileFormatError::AesGcmDecryptFailed
    ));
}

#[test]
fn test_pipelined_wrong_password_fails() {
    let plaintext = b"Secret data".to_vec();
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 50;

    let correct_password = b"correct-password";
    let wrong_password = b"wrong-password";
    let wrap = wrap_dek_with_password(
        &dek,
        correct_password,
        KdfChoice::Pbkdf2 { iterations: 1000 },
    )
    .unwrap();

    let dest = tempfile::tempfile().unwrap();
    let header = encrypt_file_pipelined(
        Cursor::new(plaintext),
        dest,
        &dek,
        &file_id,
        chunk_size,
        vec![wrap],
        Mode::Password,
        2,
        None,
        None,
    )
    .unwrap();

    // Try to unwrap the DEK using the parsed header wraps with the wrong password
    let recovered_dek_result = unwrap_dek_with_password(&header.wraps[0], wrong_password);
    assert!(matches!(
        recovered_dek_result,
        Err(FileFormatError::WrongPassword)
    ));
}

#[test]
fn test_pipelined_write_modes_equivalence() {
    use std::io::Write as _;
    let plaintext = vec![0xABu8; 100 * 1024]; // 100 KB
    let dek = generate_dek();
    let file_id = generate_file_id();
    let chunk_size = 4096; // 4 KB chunks

    let password = b"equivalence-password";
    let wrap =
        wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let mut src_file = tempfile::tempfile().unwrap();
    src_file.write_all(&plaintext).unwrap();

    // 1. Sequential Mode
    let mut file_seq = tempfile::tempfile().unwrap();
    src_file.seek(SeekFrom::Start(0)).unwrap();
    let header_seq = encrypt_file_pipelined(
        src_file.try_clone().unwrap(),
        file_seq.try_clone().unwrap(),
        &dek,
        &file_id,
        chunk_size,
        vec![wrap.clone()],
        Mode::Password,
        4,
        None,
        Some(vollcrypt_files_core::IoWriteMode::Sequential),
    )
    .unwrap();

    let mut data_seq = Vec::new();
    file_seq.seek(SeekFrom::Start(0)).unwrap();
    file_seq.read_to_end(&mut data_seq).unwrap();

    // 2. Batched Mode
    let mut file_batch = tempfile::tempfile().unwrap();
    src_file.seek(SeekFrom::Start(0)).unwrap();
    let header_batch = encrypt_file_pipelined(
        src_file.try_clone().unwrap(),
        file_batch.try_clone().unwrap(),
        &dek,
        &file_id,
        chunk_size,
        vec![wrap.clone()],
        Mode::Password,
        4,
        None,
        Some(vollcrypt_files_core::IoWriteMode::Batched { batch_size: 4 }),
    )
    .unwrap();

    let mut data_batch = Vec::new();
    file_batch.seek(SeekFrom::Start(0)).unwrap();
    file_batch.read_to_end(&mut data_batch).unwrap();

    // 3. Direct Offset Mode
    let mut file_direct = tempfile::tempfile().unwrap();
    src_file.seek(SeekFrom::Start(0)).unwrap();
    let header_direct = encrypt_file_pipelined(
        src_file.try_clone().unwrap(),
        file_direct.try_clone().unwrap(),
        &dek,
        &file_id,
        chunk_size,
        vec![wrap.clone()],
        Mode::Password,
        4,
        None,
        Some(vollcrypt_files_core::IoWriteMode::DirectOffset),
    )
    .unwrap();

    let mut data_direct = Vec::new();
    file_direct.seek(SeekFrom::Start(0)).unwrap();
    file_direct.read_to_end(&mut data_direct).unwrap();

    // Check equivalence of outputs
    assert_eq!(
        data_seq, data_batch,
        "Sequential and Batched outputs differ!"
    );
    assert_eq!(
        data_seq, data_direct,
        "Sequential and DirectOffset outputs differ!"
    );

    assert_eq!(header_seq.merkle_root, header_batch.merkle_root);
    assert_eq!(header_seq.merkle_root, header_direct.merkle_root);

    // Decrypt and verify roundtrip
    let mut decrypted = Vec::new();
    file_direct.seek(SeekFrom::Start(0)).unwrap();
    decrypt_file_pipelined(file_direct, &mut decrypted, &dek, 4).unwrap();

    assert_eq!(decrypted, plaintext);
}

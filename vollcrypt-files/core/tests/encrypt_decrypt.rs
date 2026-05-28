use vollcrypt_files_core::{decrypt_chunk, encrypt_chunk, FileFormatError};

#[test]
fn single_chunk_roundtrip() {
    let dek = [0xAA; 32];
    let file_id = [0x11; 16];
    let chunk_index = 42;
    let plaintext = vec![0xBC; 1024]; // 1 KB

    let envelope = encrypt_chunk(&dek, &file_id, chunk_index, &plaintext).unwrap();
    assert_eq!(envelope.chunk_index, chunk_index);

    let decrypted = decrypt_chunk(&dek, &file_id, chunk_index, &envelope).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn many_chunks_roundtrip() {
    let dek = [0xBB; 32];
    let file_id = [0x22; 16];
    let chunks_count = 100;

    let mut envelopes = Vec::new();
    let mut plaintexts = Vec::new();

    for i in 0..chunks_count {
        let plaintext = vec![i as u8; 256];
        let envelope = encrypt_chunk(&dek, &file_id, i, &plaintext).unwrap();
        envelopes.push(envelope);
        plaintexts.push(plaintext);
    }

    for i in 0..chunks_count {
        let decrypted = decrypt_chunk(&dek, &file_id, i, &envelopes[i as usize]).unwrap();
        assert_eq!(decrypted, plaintexts[i as usize]);
    }
}

#[test]
fn tamper_ciphertext_fails() {
    let dek = [0xCC; 32];
    let file_id = [0x33; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let mut envelope = encrypt_chunk(&dek, &file_id, chunk_index, plaintext).unwrap();

    // Tamper ciphertext
    envelope.ciphertext[0] ^= 1;

    let result = decrypt_chunk(&dek, &file_id, chunk_index, &envelope);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn tamper_iv_fails() {
    let dek = [0xDD; 32];
    let file_id = [0x44; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let mut envelope = encrypt_chunk(&dek, &file_id, chunk_index, plaintext).unwrap();

    // Tamper IV
    envelope.iv[0] ^= 1;

    let result = decrypt_chunk(&dek, &file_id, chunk_index, &envelope);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn tamper_tag_fails() {
    let dek = [0xEE; 32];
    let file_id = [0x55; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let mut envelope = encrypt_chunk(&dek, &file_id, chunk_index, plaintext).unwrap();

    // Tamper Tag
    envelope.tag[0] ^= 1;

    let result = decrypt_chunk(&dek, &file_id, chunk_index, &envelope);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn swap_chunks_fails() {
    let dek = [0xFF; 32];
    let file_id = [0x66; 16];

    let plaintext_a = b"Plaintext AAAAA";
    let plaintext_b = b"Plaintext BBBBB";

    let envelope_a = encrypt_chunk(&dek, &file_id, 0, plaintext_a).unwrap();
    let envelope_b = encrypt_chunk(&dek, &file_id, 1, plaintext_b).unwrap();

    // Try to decrypt envelope B as chunk index 0
    let result = decrypt_chunk(&dek, &file_id, 0, &envelope_b);
    // Should fail with ChunkIndexOutOfOrder since envelope_b.chunk_index (1) != 0
    assert!(matches!(
        result,
        Err(FileFormatError::ChunkIndexOutOfOrder {
            expected: 0,
            got: 1
        })
    ));

    // Try to decrypt envelope A as chunk index 1 (swapping envelope A's chunk index index)
    let mut tampered_envelope_a = envelope_a.clone();
    tampered_envelope_a.chunk_index = 1; // Lie about the chunk index
    let result = decrypt_chunk(&dek, &file_id, 1, &tampered_envelope_a);
    // Should fail with AesGcmDecryptFailed because AAD checks index in subkey / AAD block
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn wrong_file_id_fails() {
    let dek = [0x12; 32];
    let file_id_encrypt = [0x77; 16];
    let file_id_decrypt = [0x88; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let envelope = encrypt_chunk(&dek, &file_id_encrypt, chunk_index, plaintext).unwrap();

    let result = decrypt_chunk(&dek, &file_id_decrypt, chunk_index, &envelope);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn wrong_dek_fails() {
    let dek_encrypt = [0x13; 32];
    let dek_decrypt = [0x14; 32];
    let file_id = [0x99; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let envelope = encrypt_chunk(&dek_encrypt, &file_id, chunk_index, plaintext).unwrap();

    let result = decrypt_chunk(&dek_decrypt, &file_id, chunk_index, &envelope);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

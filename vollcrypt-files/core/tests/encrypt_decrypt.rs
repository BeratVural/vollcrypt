use vollcrypt_files_core::{
    decrypt_chunk, derive_chunk_keys, derive_chunk_subkey, encrypt_chunk, FileFormatError,
};

#[test]
fn single_chunk_roundtrip() {
    let dek = [0xAA; 32];
    let file_id = [0x11; 16];
    let chunk_index = 42;
    let plaintext = vec![0xBC; 1024]; // 1 KB

    let envelope = encrypt_chunk(&dek, &file_id, chunk_index, &plaintext, None).unwrap();
    assert_eq!(envelope.chunk_index, chunk_index);

    let decrypted = decrypt_chunk(&dek, &file_id, chunk_index, &envelope, None).unwrap();
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
        let envelope = encrypt_chunk(&dek, &file_id, i, &plaintext, None).unwrap();
        envelopes.push(envelope);
        plaintexts.push(plaintext);
    }

    for i in 0..chunks_count {
        let decrypted = decrypt_chunk(&dek, &file_id, i, &envelopes[i as usize], None).unwrap();
        assert_eq!(decrypted, plaintexts[i as usize]);
    }
}

#[test]
fn tamper_ciphertext_fails() {
    let dek = [0xCC; 32];
    let file_id = [0x33; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let mut envelope = encrypt_chunk(&dek, &file_id, chunk_index, plaintext, None).unwrap();

    // Tamper ciphertext
    envelope.ciphertext[0] ^= 1;

    let result = decrypt_chunk(&dek, &file_id, chunk_index, &envelope, None);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn tamper_iv_fails() {
    let dek = [0xDD; 32];
    let file_id = [0x44; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let mut envelope = encrypt_chunk(&dek, &file_id, chunk_index, plaintext, None).unwrap();

    // Tamper IV
    envelope.iv[0] ^= 1;

    let result = decrypt_chunk(&dek, &file_id, chunk_index, &envelope, None);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn tamper_tag_fails() {
    let dek = [0xEE; 32];
    let file_id = [0x55; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let mut envelope = encrypt_chunk(&dek, &file_id, chunk_index, plaintext, None).unwrap();

    // Tamper Tag
    envelope.tag[0] ^= 1;

    let result = decrypt_chunk(&dek, &file_id, chunk_index, &envelope, None);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn swap_chunks_fails() {
    let dek = [0xFF; 32];
    let file_id = [0x66; 16];

    let plaintext_a = b"Plaintext AAAAA";
    let plaintext_b = b"Plaintext BBBBB";

    let envelope_a = encrypt_chunk(&dek, &file_id, 0, plaintext_a, None).unwrap();
    let envelope_b = encrypt_chunk(&dek, &file_id, 1, plaintext_b, None).unwrap();

    // Try to decrypt envelope B as chunk index 0
    let result = decrypt_chunk(&dek, &file_id, 0, &envelope_b, None);
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
    let result = decrypt_chunk(&dek, &file_id, 1, &tampered_envelope_a, None);
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

    let envelope = encrypt_chunk(&dek, &file_id_encrypt, chunk_index, plaintext, None).unwrap();

    let result = decrypt_chunk(&dek, &file_id_decrypt, chunk_index, &envelope, None);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn wrong_dek_fails() {
    let dek_encrypt = [0x13; 32];
    let dek_decrypt = [0x14; 32];
    let file_id = [0x99; 16];
    let chunk_index = 0;
    let plaintext = b"Hello, World!";

    let envelope = encrypt_chunk(&dek_encrypt, &file_id, chunk_index, plaintext, None).unwrap();

    let result = decrypt_chunk(&dek_decrypt, &file_id, chunk_index, &envelope, None);
    assert!(matches!(result, Err(FileFormatError::AesGcmDecryptFailed)));
}

#[test]
fn derive_chunk_keys_subkey_matches_legacy() {
    let dek = [0x15; 32];
    let file_id = [0xAB; 16];
    let idx = 7;
    let keys = derive_chunk_keys(&dek, &file_id, idx).unwrap();
    let legacy = derive_chunk_subkey(&dek, &file_id, idx).unwrap();
    assert_eq!(keys.0, legacy);
}

#[test]
fn deterministic_iv_same_inputs() {
    let dek = [0x16; 32];
    let file_id = [0xBC; 16];
    let idx = 13;
    let keys1 = derive_chunk_keys(&dek, &file_id, idx).unwrap();
    let keys2 = derive_chunk_keys(&dek, &file_id, idx).unwrap();
    assert_eq!(keys1.1, keys2.1);
}

#[test]
fn iv_differs_across_chunk_index() {
    let dek = [0x17; 32];
    let file_id = [0xCD; 16];
    let keys1 = derive_chunk_keys(&dek, &file_id, 1).unwrap();
    let keys2 = derive_chunk_keys(&dek, &file_id, 2).unwrap();
    assert_ne!(keys1.1, keys2.1);
}

#[test]
fn iv_differs_across_file_id() {
    let dek = [0x18; 32];
    let file_id1 = [0xDE; 16];
    let file_id2 = [0xDF; 16];
    let keys1 = derive_chunk_keys(&dek, &file_id1, 1).unwrap();
    let keys2 = derive_chunk_keys(&dek, &file_id2, 1).unwrap();
    assert_ne!(keys1.1, keys2.1);
}

#[test]
fn encrypt_chunk_no_osrng_determinism() {
    let dek = [0x19; 32];
    let file_id = [0xEF; 16];
    let idx = 4;
    let pt = b"Deterministic payload";
    let env1 = encrypt_chunk(&dek, &file_id, idx, pt, None).unwrap();
    let env2 = encrypt_chunk(&dek, &file_id, idx, pt, None).unwrap();
    assert_eq!(env1.iv, env2.iv);
    assert_eq!(env1.ciphertext, env2.ciphertext);
    assert_eq!(env1.tag, env2.tag);
}

#[test]
fn different_dek_different_ciphertext() {
    let dek1 = [0x20; 32];
    let dek2 = [0x21; 32];
    let file_id = [0xF0; 16];
    let idx = 4;
    let pt = b"Deterministic payload";
    let env1 = encrypt_chunk(&dek1, &file_id, idx, pt, None).unwrap();
    let env2 = encrypt_chunk(&dek2, &file_id, idx, pt, None).unwrap();
    assert_ne!(env1.ciphertext, env2.ciphertext);
}

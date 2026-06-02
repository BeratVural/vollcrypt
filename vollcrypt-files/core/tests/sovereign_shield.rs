use std::io::{Cursor, Read, Write, Seek, SeekFrom};
use tempfile::tempfile;
use vollcrypt_files_core::{
    encrypt_file_pipelined, decrypt_file_pipelined, decrypt_file_pipelined_with_policy,
    seal_container, is_sealed, inspect_sealed, verify_container,
    generate_dek, generate_file_id, hybrid_keypair_generate,
    wrap_dek_with_password, KdfChoice,
    error::FileFormatError,
    header::{Header, Mode},
    shield::{ShieldPolicy, ShieldReport, ReleaseMode, SignaturePolicy},
    sovereign::{SealMode, SealOptions},
    pipelined_io::PipelinedSignInfo,
};

fn read_all(mut f: std::fs::File) -> Vec<u8> {
    f.seek(SeekFrom::Start(0)).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf
}

fn write_all(buf: &[u8]) -> std::fs::File {
    let mut f = tempfile().unwrap();
    f.write_all(buf).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f
}

#[test]
fn test_sovereign_seal_v1_v2_v3() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = b"Hello, this is a sovereign sealing test.";
    
    let password = b"seal-password";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    // --- V1 Container ---
    let dest_encrypt = tempfile().unwrap();
    encrypt_file_pipelined(
        Cursor::new(plaintext.to_vec()),
        dest_encrypt.try_clone().unwrap(),
        &dek,
        &file_id,
        4096,
        vec![wrap.clone()],
        Mode::Password,
        2,
        None,
        None,
    ).unwrap();

    let ciphertext = read_all(dest_encrypt);

    let mut dest_v1 = Vec::new();
    let opts = SealOptions {
        mode: SealMode::Seal,
        reason: Some("Testing V1 Seal".to_string()),
        sign_info: None,
    };
    seal_container(Cursor::new(&ciphertext), Cursor::new(&mut dest_v1), opts).unwrap();

    let (hdr_v1, _) = Header::parse(&dest_v1).unwrap();
    assert!(is_sealed(&hdr_v1));

    let inspect_v1 = inspect_sealed(Cursor::new(&dest_v1)).unwrap();
    assert!(inspect_v1.sealed_mode.is_none());
    assert!(inspect_v1.reason.is_none());

    // --- V2/V3 Container ---
    let (signer_pk, signer_sk) = hybrid_keypair_generate();
    let key_log_id = generate_dek();
    let timestamp = 1234567890;

    let sign_info = PipelinedSignInfo::Plain {
        signer_pk: signer_pk.clone(),
        signer_sk: signer_sk.clone(),
        key_log_id,
        timestamp,
    };

    let dest_encrypt_v3 = tempfile().unwrap();
    encrypt_file_pipelined(
        Cursor::new(plaintext.to_vec()),
        dest_encrypt_v3.try_clone().unwrap(),
        &dek,
        &file_id,
        4096,
        vec![wrap],
        Mode::Password,
        2,
        Some(sign_info.clone()),
        None,
    ).unwrap();

    let ciphertext_v3 = read_all(dest_encrypt_v3);

    let mut dest_v3 = Vec::new();
    let opts_v3 = SealOptions {
        mode: SealMode::Seal,
        reason: Some("Testing V3 Seal".to_string()),
        sign_info: Some(sign_info),
    };
    seal_container(Cursor::new(&ciphertext_v3), Cursor::new(&mut dest_v3), opts_v3).unwrap();

    let (hdr_v3, _) = Header::parse(&dest_v3).unwrap();
    assert!(is_sealed(&hdr_v3));

    let inspect_v3 = inspect_sealed(Cursor::new(&dest_v3)).unwrap();
    assert_eq!(inspect_v3.sealed_mode, Some(1));
    assert_eq!(inspect_v3.reason.as_deref(), Some("Testing V3 Seal"));
    assert_eq!(inspect_v3.timestamp, Some(timestamp));
}

#[test]
fn test_sovereign_purge() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = b"Sensitive content to be crypto-shredded.";
    
    let password = b"seal-password";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let dest_encrypt = tempfile().unwrap();
    encrypt_file_pipelined(
        Cursor::new(plaintext.to_vec()),
        dest_encrypt.try_clone().unwrap(),
        &dek,
        &file_id,
        4096,
        vec![wrap],
        Mode::Password,
        2,
        None,
        None,
    ).unwrap();

    let ciphertext = read_all(dest_encrypt);

    let mut dest_purged = Vec::new();
    let opts = SealOptions {
        mode: SealMode::Purge,
        reason: Some("Purging".to_string()),
        sign_info: None,
    };
    seal_container(Cursor::new(&ciphertext), Cursor::new(&mut dest_purged), opts).unwrap();

    let inspect = inspect_sealed(Cursor::new(&dest_purged)).unwrap();
    assert!(!inspect.ciphertext_present);

    // Normal decryption should fail
    let mut decrypted = Vec::new();
    let decrypt_res = decrypt_file_pipelined(
        write_all(&dest_purged),
        &mut decrypted,
        &dek,
        2,
    );
    assert!(matches!(decrypt_res.unwrap_err(), FileFormatError::ContainerSealed));
}

#[test]
fn test_idempotency_double_sealing() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = b"Double seal test.";
    
    let password = b"seal-password";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let dest_encrypt = tempfile().unwrap();
    encrypt_file_pipelined(
        Cursor::new(plaintext.to_vec()),
        dest_encrypt.try_clone().unwrap(),
        &dek,
        &file_id,
        4096,
        vec![wrap],
        Mode::Password,
        2,
        None,
        None,
    ).unwrap();

    let ciphertext = read_all(dest_encrypt);

    let mut dest_first = Vec::new();
    let opts = SealOptions {
        mode: SealMode::Seal,
        reason: Some("First seal".to_string()),
        sign_info: None,
    };
    seal_container(Cursor::new(&ciphertext), Cursor::new(&mut dest_first), opts.clone()).unwrap();

    let mut dest_second = Vec::new();
    seal_container(Cursor::new(&dest_first), Cursor::new(&mut dest_second), opts).unwrap();

    assert_eq!(dest_first, dest_second);
}

#[test]
fn test_shield_verified_vs_streaming() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = vec![0u8; 8192];
    
    let password = b"seal-password";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let dest_encrypt = tempfile().unwrap();
    encrypt_file_pipelined(
        Cursor::new(plaintext.clone()),
        dest_encrypt.try_clone().unwrap(),
        &dek,
        &file_id,
        4096,
        vec![wrap],
        Mode::Password,
        2,
        None,
        None,
    ).unwrap();

    let mut ciphertext = read_all(dest_encrypt);

    // Tamper with the last chunk's tag
    let len = ciphertext.len();
    ciphertext[len - 5] ^= 0x55; // Flip bit in the tag area of final chunk

    // Case 1: Verified Release Mode (emits 0 bytes and returns error)
    let mut dest_verified = Vec::new();
    let verified_policy = ShieldPolicy {
        release_mode: ReleaseMode::Verified,
        signature: SignaturePolicy::Optional,
        ..ShieldPolicy::strict()
    };
    let res_verified = decrypt_file_pipelined_with_policy(
        write_all(&ciphertext),
        &mut dest_verified,
        &dek,
        2,
        Some(&verified_policy),
    );
    assert!(res_verified.is_err());
    assert_eq!(dest_verified.len(), 0); // 0 bytes released

    // Case 2: Streaming Release Mode (emits first chunk but returns error on second chunk)
    let mut dest_streaming = Vec::new();
    let streaming_policy = ShieldPolicy {
        release_mode: ReleaseMode::Streaming,
        signature: SignaturePolicy::Optional,
        ..ShieldPolicy::strict()
    };
    let res_streaming = decrypt_file_pipelined_with_policy(
        write_all(&ciphertext),
        &mut dest_streaming,
        &dek,
        2,
        Some(&streaming_policy),
    );
    assert!(res_streaming.is_err());
    assert_eq!(dest_streaming.len(), 4096); // Emitted first valid chunk before realizing final chunk was tampered
}

#[test]
fn test_tamper_shield() {
    let dek = generate_dek();
    let file_id = generate_file_id();
    let plaintext = b"Tamper shield test.";
    
    let password = b"seal-password";
    let wrap = wrap_dek_with_password(&dek, password, KdfChoice::Pbkdf2 { iterations: 1000 }).unwrap();

    let (signer_pk, signer_sk) = hybrid_keypair_generate();
    let key_log_id = generate_dek();
    let timestamp = 1234567890;

    let sign_info = PipelinedSignInfo::Plain {
        signer_pk: signer_pk.clone(),
        signer_sk: signer_sk.clone(),
        key_log_id,
        timestamp,
    };

    let dest_encrypt = tempfile().unwrap();
    encrypt_file_pipelined(
        Cursor::new(plaintext.to_vec()),
        dest_encrypt.try_clone().unwrap(),
        &dek,
        &file_id,
        4096,
        vec![wrap],
        Mode::Password,
        2,
        Some(sign_info),
        None,
    ).unwrap();

    let ciphertext = read_all(dest_encrypt);

    // Verify it passes shield verify container
    let strict_policy = ShieldPolicy::strict();
    let report = verify_container(Cursor::new(&ciphertext), &strict_policy);
    assert_eq!(report, ShieldReport::Success);

    // Tamper with the signed metadata (e.g. modify timestamp)
    // Find metadata section in serialized header and alter it
    let mut tampered_ciphertext = ciphertext.clone();
    tampered_ciphertext[120] ^= 0xFF; // Modify signature or metadata section

    let report_tampered = verify_container(Cursor::new(&tampered_ciphertext), &strict_policy);
    assert!(matches!(report_tampered, ShieldReport::Signature | ShieldReport::MerkleRoot | ShieldReport::HeaderField(_)));
}

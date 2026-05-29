use vollcrypt_files_core::{
    hybrid_keypair_generate, generate_file_id, generate_gk, sign_header_plain, sign_header_sealed,
    CipherId, HashAlgorithm, Header, Mode, SignedMetadata, HybridSignature, HybridPublicKey,
};

fn create_test_header(version: u8) -> Header {
    Header {
        version,
        mode: Mode::Group,
        cipher_id: CipherId::Aes256Gcm,
        file_id: generate_file_id(),
        chunk_size: 4096,
        plaintext_size: 1000,
        merkle_root: [0x55; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![],
        signed_metadata: None,
        signature: None,
    }
}

#[test]
fn signed_v3_header_write_parse() {
    let mut header = create_test_header(3);
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;

    sign_header_plain(&mut header, &pk, &sk, key_log_id, timestamp).unwrap();

    let bytes = header.write();
    let (parsed, parsed_len) = Header::parse(&bytes).unwrap();

    assert_eq!(bytes.len(), parsed_len);
    assert_eq!(parsed.version, 3);
    assert_eq!(parsed.signature, header.signature);

    if let Some(SignedMetadata::Plain {
        signer_pubkey,
        timestamp: parsed_ts,
        key_log_id: parsed_kl,
    }) = parsed.signed_metadata
    {
        assert_eq!(signer_pubkey, pk);
        assert_eq!(parsed_ts, timestamp);
        assert_eq!(parsed_kl, key_log_id);
    } else {
        panic!("Expected Plain metadata");
    }
}

#[test]
fn sealed_v3_header_write_parse() {
    let mut header = create_test_header(3);
    let (pk, sk) = hybrid_keypair_generate();
    let key_log_id = [0xBB; 32];
    let timestamp = 987654321;
    let group_id = generate_file_id();
    let gk = generate_gk();

    sign_header_sealed(
        &mut header,
        &pk,
        &sk,
        key_log_id,
        timestamp,
        group_id,
        1,
        &gk,
    )
    .unwrap();

    let bytes = header.write();
    let (parsed, parsed_len) = Header::parse(&bytes).unwrap();

    assert_eq!(bytes.len(), parsed_len);
    assert_eq!(parsed.version, 3);
    assert_eq!(parsed.signature, header.signature);

    if let Some(SignedMetadata::Sealed {
        sealed_group_id,
        sealed_gk_version,
        iv,
        sealed_payload,
        sealed_tag,
        timestamp: parsed_ts,
    }) = parsed.signed_metadata
    {
        assert_eq!(sealed_group_id, group_id);
        assert_eq!(sealed_gk_version, 1);
        assert_eq!(parsed_ts, timestamp);
        assert_eq!(iv.len(), 12);
        // Under v3, sealed payload is exactly 32 bytes (only key_log_id)
        assert_eq!(sealed_payload.len(), 32); 
        assert_eq!(sealed_tag.len(), 16);
    } else {
        panic!("Expected Sealed metadata");
    }
}

#[test]
fn legacy_v2_header_write_parse() {
    // Manually construct a version 2 header to check backward compatibility
    let mut header = create_test_header(2);
    let ed25519_pk = [0x01; 32];
    let ed25519_sig = [0x02; 64];
    let key_log_id = [0xAA; 32];
    let timestamp = 123456789;

    header.signed_metadata = Some(SignedMetadata::Plain {
        signer_pubkey: HybridPublicKey {
            ed25519: ed25519_pk,
            mldsa: [0u8; 1952],
        },
        timestamp,
        key_log_id,
    });
    header.signature = Some(HybridSignature {
        ed25519: ed25519_sig,
        mldsa: Vec::new(),
    });

    let bytes = header.write();
    let (parsed, parsed_len) = Header::parse(&bytes).unwrap();

    assert_eq!(bytes.len(), parsed_len);
    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.signature, header.signature);

    if let Some(SignedMetadata::Plain {
        signer_pubkey,
        timestamp: parsed_ts,
        key_log_id: parsed_kl,
    }) = parsed.signed_metadata
    {
        assert_eq!(signer_pubkey.ed25519, ed25519_pk);
        // in v2, mldsa is parsed as all zeros because it's not present on-wire
        assert_eq!(signer_pubkey.mldsa, [0u8; 1952]); 
        assert_eq!(parsed_ts, timestamp);
        assert_eq!(parsed_kl, key_log_id);
    } else {
        panic!("Expected Plain metadata");
    }
}

#[test]
fn unsigned_header_writes_version_1() {
    let header = create_test_header(2);
    // unsigned header should write version 1 (since it has no signed metadata)
    let bytes = header.write();
    assert_eq!(bytes[8], 1);
}

#[test]
fn signed_header_writes_version_3() {
    let mut header = create_test_header(3);
    let (pk, sk) = hybrid_keypair_generate();
    sign_header_plain(&mut header, &pk, &sk, [0x00; 32], 100).unwrap();

    let bytes = header.write();
    assert_eq!(bytes[8], 3);
}

#[test]
fn parse_v1_still_works() {
    // Construct a manual version 1 header
    let file_id = generate_file_id();
    let mut v1_bytes = Vec::new();
    v1_bytes.extend_from_slice(b"VOLLVALT");
    v1_bytes.push(1); // Version = 1
    v1_bytes.push(2); // Mode = Group
    v1_bytes.push(0); // Cipher = Aes256Gcm
    v1_bytes.extend_from_slice(&file_id);
    v1_bytes.extend_from_slice(&4096u32.to_be_bytes());
    v1_bytes.extend_from_slice(&1000u64.to_be_bytes());
    v1_bytes.extend_from_slice(&[0xaa; 32]); // Merkle Root
    v1_bytes.push(0); // Wrap count = 0
    v1_bytes.extend_from_slice(&[0u8; 4]); // Reserved
    v1_bytes.extend_from_slice(&0u32.to_be_bytes()); // Variable len = 0

    let (parsed, parsed_len) = Header::parse(&v1_bytes).unwrap();
    assert_eq!(parsed_len, 80);
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.file_id, file_id);
    assert!(parsed.signed_metadata.is_none());
    assert!(parsed.signature.is_none());
}

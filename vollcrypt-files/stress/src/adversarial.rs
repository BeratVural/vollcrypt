#[cfg(test)]
mod tests {
    use rand::{Rng, RngCore};
    use vollcrypt_files_core::*;

    #[test]
    fn test_bit_flip_resistance() {
        let dek = [0u8; 32];
        let file_id = [0u8; 16];
        let plaintext = vec![0u8; 1024]; // 1 KB plaintext
        let env = encrypt_chunk(&dek, &file_id, 0, &plaintext, None).unwrap();

        let mut serialized = env.write();
        let total_bits = serialized.len() * 8;

        let mut failures = 0;

        for bit_to_flip in 0..total_bits {
            let byte_idx = bit_to_flip / 8;
            let bit_idx = bit_to_flip % 8;

            // Flip the bit
            serialized[byte_idx] ^= 1 << bit_idx;

            // Parse and attempt decrypt
            if let Ok(parsed_env) = ChunkEnvelope::parse(&serialized, plaintext.len()) {
                let decrypt_res = decrypt_chunk(&dek, &file_id, 0, &parsed_env, None);
                if decrypt_res.is_err() {
                    failures += 1;
                }
            } else {
                failures += 1;
            }

            // Restore the bit
            serialized[byte_idx] ^= 1 << bit_idx;
        }

        assert_eq!(
            failures, total_bits,
            "Some tampered ciphertexts successfully decrypted/parsed!"
        );
        println!("SECURITY AUDIT: Bit-flip resistance verified ({} / {} tampered inputs detected and rejected).", failures, total_bits);
    }

    #[test]
    fn test_tag_forgery() {
        let dek = [0u8; 32];
        let file_id = [0u8; 16];
        let plaintext = vec![0u8; 100];
        let mut env = encrypt_chunk(&dek, &file_id, 0, &plaintext, None).unwrap();

        let mut rng = rand::thread_rng();
        let attempts = 1000;
        let mut successful_forgeries = 0;

        for _ in 0..attempts {
            rng.fill_bytes(&mut env.tag);
            if decrypt_chunk(&dek, &file_id, 0, &env, None).is_ok() {
                successful_forgeries += 1;
            }
        }

        assert_eq!(
            successful_forgeries, 0,
            "A random tag was accepted as valid!"
        );
        println!(
            "SECURITY AUDIT: Tag forgery resistance verified (0 / {} random tags accepted).",
            attempts
        );
    }

    #[test]
    fn test_header_tampering_matrix() {
        let file_id = [1u8; 16];
        let header = Header {
            version: 1,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: 4096,
            plaintext_size: 10000,
            merkle_root: [9u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            }],
            signed_metadata: None,
            signature: None,
        };

        let mut serialized = header.write();

        // 1. Tamper Magic bytes
        serialized[0] ^= 0xFF;
        assert!(
            Header::parse(&serialized).is_err(),
            "Header parsing should fail with tampered magic"
        );
        serialized[0] ^= 0xFF; // Restore

        // 2. Tamper Version byte
        serialized[8] = 99;
        assert!(
            Header::parse(&serialized).is_err(),
            "Header parsing should fail with unsupported version"
        );
        serialized[8] = 1; // Restore

        // 3. Tamper File ID
        serialized[11] ^= 0xFF;
        let (parsed, _) = Header::parse(&serialized).unwrap();
        assert_ne!(parsed.file_id, file_id, "File ID tampering undetected");
        serialized[11] ^= 0xFF; // Restore

        // 4. Tamper Merkle Root
        serialized[39] ^= 0xFF;
        let (parsed, _) = Header::parse(&serialized).unwrap();
        assert_ne!(
            parsed.merkle_root, [9u8; 32],
            "Merkle root tampering undetected"
        );
        serialized[39] ^= 0xFF; // Restore

        println!("SECURITY AUDIT: Header tampering matrix tests completed successfully.");
    }

    #[test]
    fn test_replay_and_substitution() {
        let dek = [0u8; 32];
        let file_id_a = [1u8; 16];
        let file_id_b = [2u8; 16];
        let plaintext = vec![0u8; 100];

        // Deterministic IVs: Encrypting same plaintext with different indices/file_ids produces different envelopes.
        // Identical inputs produce the same envelope under deterministic IV.
        let env1 = encrypt_chunk(&dek, &file_id_a, 0, &plaintext, None).unwrap();
        let env2 = encrypt_chunk(&dek, &file_id_a, 1, &plaintext, None).unwrap();
        assert_ne!(env1.iv, env2.iv, "IV must differ across chunk indices!");
        assert_ne!(
            env1.ciphertext, env2.ciphertext,
            "Ciphertext must differ across chunk indices!"
        );

        let env3 = encrypt_chunk(&dek, &file_id_b, 0, &plaintext, None).unwrap();
        assert_ne!(env1.iv, env3.iv, "IV must differ across file IDs!");
        assert_ne!(
            env1.ciphertext, env3.ciphertext,
            "Ciphertext must differ across file IDs!"
        );

        // Cross-file chunk substitution
        let env_a = encrypt_chunk(&dek, &file_id_a, 0, &plaintext, None).unwrap();
        let res = decrypt_chunk(&dek, &file_id_b, 0, &env_a, None);
        assert!(
            res.is_err(),
            "Cross-file chunk substitution was not rejected!"
        );

        // Index substitution
        let res_idx = decrypt_chunk(&dek, &file_id_a, 1, &env_a, None);
        assert!(
            res_idx.is_err(),
            "Chunk index substitution was not rejected!"
        );
    }

    #[test]
    fn test_manifest_authority_tampering() {
        let group_id = [0u8; 16];
        let founder_id = [1u8; 16];
        let (admin_pk, admin_sk) = hybrid_keypair_generate();
        let (unauthorized_pk, unauthorized_sk) = hybrid_keypair_generate();

        let (rec_pk, _) = generate_recipient_keypair();
        let gk_wrap = wrap_key_to_recipient(&[0u8; 32], founder_id, 1, &rec_pk).unwrap();

        let mut manifest = GroupManifest::genesis(
            group_id,
            founder_id,
            &admin_sk,
            admin_pk.clone(),
            rec_pk.clone(),
            gk_wrap.clone(),
        );

        let member_id = [2u8; 16];
        let prev_op = manifest.operations.last().unwrap();
        let prev_hash = prev_op.hash(manifest.version);
        let op = Operation::AddMember {
            member_id,
            member_signing_pk: admin_pk,
            member_x25519_pk: rec_pk.x25519,
            member_mlkem_pk: rec_pk.ml_kem.clone(),
            gk_wrap: gk_wrap.clone(),
        };
        let data = op.to_bytes(manifest.version);

        let mut forged_signed_op = SignedOperation {
            op_type: 1,
            prev_hash,
            timestamp: 1234567,
            signer_pubkey: unauthorized_pk.clone(),
            data_len: data.len() as u32,
            data,
            signature: HybridSignature {
                ed25519: [0u8; 64],
                mldsa: Vec::new(),
            },
            epoch: 1,
        };
        let msg = forged_signed_op.sig_message_for_version(manifest.version);
        forged_signed_op.signature = hybrid_sign(&unauthorized_sk, &unauthorized_pk, "vollf-manifest-op", &[], &msg);

        // Inject the forged operation
        manifest.operations.push(forged_signed_op);

        // Manifest verification must fail due to unauthorized signer
        assert!(
            manifest.verify().is_err(),
            "Tampered manifest authority was verified successfully!"
        );
    }

    #[test]
    fn test_signed_header_tampering() {
        let file_id_1 = [1u8; 16];
        let file_id_2 = [2u8; 16];
        let (signer_pk, signer_sk) = hybrid_keypair_generate();

        let mut header = Header {
            version: 3,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id: file_id_1,
            chunk_size: 4096,
            plaintext_size: 100,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            }],
            signed_metadata: Some(SignedMetadata::Plain {
                signer_pubkey: signer_pk.clone(),
                timestamp: 123456789,
                key_log_id: [0u8; 32],
            }),
            signature: None,
        };

        // Sign the header
        let msg = header.signed_bytes();
        let sig = hybrid_sign(&signer_sk, &signer_pk, "vollf-hdr-plain", &[], &msg);
        header.signature = Some(sig);

        // Verification of clean header succeeds
        let serialized = header.write();
        let (parsed, _) = Header::parse(&serialized).unwrap();
        assert!(verify_header_signature_plain(&parsed, VerificationPolicy::RequireSigned).is_ok());

        // Replay/Tampering: Change the file_id in the signed header
        let mut tampered_header = parsed.clone();
        tampered_header.file_id = file_id_2;

        assert!(
            verify_header_signature_plain(&tampered_header, VerificationPolicy::RequireSigned).is_err(),
            "Signature verification succeeded on tampered header!"
        );
    }
}

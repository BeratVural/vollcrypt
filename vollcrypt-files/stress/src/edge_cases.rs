#[cfg(test)]
mod tests {
    use vollcrypt_files_core::*;

    #[test]
    fn test_boundary_sizes() {
        let dek = [0u8; 32];
        let file_id = [0u8; 16];

        // 0 byte plaintext
        let res_0 = encrypt_chunk(&dek, &file_id, 0, &[], None);
        assert!(res_0.is_ok());
        let env_0 = res_0.unwrap();
        assert_eq!(
            decrypt_chunk(&dek, &file_id, 0, &env_0, None)
                .unwrap()
                .len(),
            0
        );

        // 1 byte plaintext
        let res_1 = encrypt_chunk(&dek, &file_id, 0, &[42], None);
        assert!(res_1.is_ok());
        let env_1 = res_1.unwrap();
        assert_eq!(
            decrypt_chunk(&dek, &file_id, 0, &env_1, None).unwrap(),
            vec![42]
        );

        // Boundary chunk sizes
        let chunk_size = 64 * 1024;

        // chunk_size - 1
        let pt_minus_1 = vec![1u8; chunk_size - 1];
        let env = encrypt_chunk(&dek, &file_id, 0, &pt_minus_1, None).unwrap();
        assert_eq!(
            decrypt_chunk(&dek, &file_id, 0, &env, None).unwrap(),
            pt_minus_1
        );

        // chunk_size
        let pt_exact = vec![2u8; chunk_size];
        let env = encrypt_chunk(&dek, &file_id, 0, &pt_exact, None).unwrap();
        assert_eq!(
            decrypt_chunk(&dek, &file_id, 0, &env, None).unwrap(),
            pt_exact
        );

        // chunk_size + 1 (split into two chunks)
        let pt_plus_1 = vec![3u8; chunk_size + 1];
        let env_a = encrypt_chunk(&dek, &file_id, 0, &pt_plus_1[..chunk_size], None).unwrap();
        let env_b = encrypt_chunk(&dek, &file_id, 1, &pt_plus_1[chunk_size..], None).unwrap();
        assert_eq!(
            decrypt_chunk(&dek, &file_id, 0, &env_a, None)
                .unwrap()
                .len(),
            chunk_size
        );
        assert_eq!(
            decrypt_chunk(&dek, &file_id, 1, &env_b, None)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn test_extreme_values() {
        // chunk_size = 1 byte
        let dek = [0u8; 32];
        let file_id = [0u8; 16];
        let pt = vec![7u8; 1];
        let env = encrypt_chunk(&dek, &file_id, 0, &pt, None).unwrap();
        assert_eq!(decrypt_chunk(&dek, &file_id, 0, &env, None).unwrap(), pt);

        // Header with chunk_size = 16 MB (maximum allowed limit)
        let header_valid = Header {
            version: 1,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: 16_777_216,
            plaintext_size: 100,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            }],
            signed_metadata: None,
            signature: None,
        };
        let serialized_valid = header_valid.write();
        let (parsed, len) = Header::parse(&serialized_valid).unwrap();
        assert_eq!(parsed.chunk_size, 16_777_216);
        assert_eq!(len, serialized_valid.len());

        // Header with chunk_size = 16 MB + 1 byte (exceeds limit)
        let header_invalid = Header {
            version: 1,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: 16_777_217,
            plaintext_size: 100,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            }],
            signed_metadata: None,
            signature: None,
        };
        let serialized_invalid = header_invalid.write();
        assert!(Header::parse(&serialized_invalid).is_err());

        // Header with chunk_size = 4 GB (maximum u32, exceeds limit)
        let header_max = Header {
            version: 1,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: u32::MAX,
            plaintext_size: 100,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            }],
            signed_metadata: None,
            signature: None,
        };
        let serialized_max = header_max.write();
        assert!(Header::parse(&serialized_max).is_err());
    }

    #[test]
    fn test_manifest_extremes() {
        let group_id = [0u8; 16];
        let founder_id = [1u8; 16];
        let (admin_pk, admin_sk) = hybrid_keypair_generate();
        let (rec_pk, _) = generate_recipient_keypair();
        let gk_wrap = wrap_key_to_recipient(&[0u8; 32], founder_id, 1, &rec_pk).unwrap();

        // 0 members manifest (just genesis founder)
        let mut manifest = GroupManifest::genesis(
            group_id,
            founder_id,
            &admin_sk,
            admin_pk.clone(),
            rec_pk.clone(),
            gk_wrap.clone(),
        );
        assert_eq!(manifest.current_members().len(), 1);
        assert!(manifest.verify().is_ok());

        // Add member twice (duplicate handling)
        let member_id = [2u8; 16];
        manifest
            .add_member(
                &admin_sk,
                member_id,
                admin_pk.clone(),
                rec_pk.clone(),
                gk_wrap.clone(),
            )
            .unwrap();
        // Try adding the same member again
        let res_dup = manifest.add_member(
            &admin_sk,
            member_id,
            admin_pk,
            rec_pk.clone(),
            gk_wrap.clone(),
        );
        assert!(res_dup.is_ok());
        let active = manifest.current_members();
        assert_eq!(active.len(), 2);

        // Remove members sequentially until empty
        manifest.remove_member(&admin_sk, member_id).unwrap();
        manifest.remove_member(&admin_sk, founder_id).unwrap();
        assert!(manifest.current_members().is_empty());
    }

    #[test]
    fn test_group_key_extremes() {
        let group_id = [0u8; 16];
        let founder_id = [1u8; 16];
        let (admin_pk, admin_sk) = hybrid_keypair_generate();
        let (rec_pk, _) = generate_recipient_keypair();
        let gk_wrap = wrap_key_to_recipient(&[0u8; 32], founder_id, 1, &rec_pk).unwrap();

        let mut manifest = GroupManifest::genesis(
            group_id,
            founder_id,
            &admin_sk,
            admin_pk,
            rec_pk.clone(),
            gk_wrap.clone(),
        );

        // 1000 Rotations and some shredding in between to test mixed valid/shredded versions
        for version in 2..=1001 {
            let mut new_gk = [0u8; 32];
            new_gk[0..4].copy_from_slice(&(version as u32).to_be_bytes());
            manifest
                .rotate_group_key(&new_gk, &admin_sk, version as u64)
                .unwrap();

            if version == 501 || version == 1000 {
                manifest
                    .shred_group_key(
                        version - 1,
                        "Shredded for test",
                        &admin_sk,
                        version as u64,
                    )
                    .unwrap();
            }
        }

        assert_eq!(manifest.current_gk_version(), 1001);
        assert!(manifest.is_version_shredded(500));
        assert!(manifest.is_version_shredded(999));
        assert!(!manifest.is_version_shredded(1000));
        assert!(manifest.verify().is_ok());
    }

    #[test]
    fn test_wrap_entry_extremes() {
        // Header with 0 wraps (degenerate/shredded)
        let file_id = [0u8; 16];
        let header_0 = Header {
            version: 1,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: 1024,
            plaintext_size: 100,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![],
            signed_metadata: None,
            signature: None,
        };
        let serialized_0 = header_0.write();
        let (parsed_0, _) = Header::parse(&serialized_0).unwrap();
        assert_eq!(parsed_0.wraps.len(), 0);

        // Header with 255 wraps (maximum supported by 1-byte wrap count limit)
        let wraps_255 = vec![
            WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            };
            255
        ];
        let header_255 = Header {
            version: 1,
            mode: Mode::Recipient,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: 1024,
            plaintext_size: 100,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: wraps_255,
            signed_metadata: None,
            signature: None,
        };
        let serialized_255 = header_255.write();
        let (parsed_255, _) = Header::parse(&serialized_255).unwrap();
        assert_eq!(parsed_255.wraps.len(), 255);

        // Mixed wraps in the same header
        let mixed_wraps = vec![
            WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [1u8; 16],
                wrapped_dek: [1u8; 40],
            },
            WrapEntry::PasswordArgon2id {
                m_cost: 4096,
                t_cost: 3,
                p_cost: 1,
                salt: [2u8; 16],
                wrapped_dek: [2u8; 40],
            },
            WrapEntry::GroupWrap {
                group_id: [3u8; 16],
                gk_version: 1,
                wrapped_dek: [3u8; 40],
            },
        ];
        let header_mixed = Header {
            version: 1,
            mode: Mode::Recipient,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: 1024,
            plaintext_size: 100,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: mixed_wraps,
            signed_metadata: None,
            signature: None,
        };
        let serialized_mixed = header_mixed.write();
        let (parsed_mixed, _) = Header::parse(&serialized_mixed).unwrap();
        assert_eq!(parsed_mixed.wraps.len(), 3);
        assert!(matches!(
            parsed_mixed.wraps[0],
            WrapEntry::PasswordPbkdf2 { .. }
        ));
        assert!(matches!(
            parsed_mixed.wraps[1],
            WrapEntry::PasswordArgon2id { .. }
        ));
        assert!(matches!(parsed_mixed.wraps[2], WrapEntry::GroupWrap { .. }));
    }

    #[test]
    fn test_four_megabyte_chunk_size() {
        let dek = [0u8; 32];
        let file_id = [0u8; 16];
        let chunk_size = 4 * 1024 * 1024; // 4 MB

        let pt = vec![0xAB; chunk_size];
        let env = encrypt_chunk(&dek, &file_id, 0, &pt, None).unwrap();
        let dec = decrypt_chunk(&dek, &file_id, 0, &env, None).unwrap();
        assert_eq!(dec, pt);

        // Header check with 4 MB
        let header = Header {
            version: 1,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id,
            chunk_size: chunk_size as u32,
            plaintext_size: chunk_size as u64,
            merkle_root: [0u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            }],
            signed_metadata: None,
            signature: None,
        };
        let serialized = header.write();
        let (parsed, _) = Header::parse(&serialized).unwrap();
        assert_eq!(parsed.chunk_size, chunk_size as u32);
    }
}

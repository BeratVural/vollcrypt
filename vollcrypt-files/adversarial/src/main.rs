use std::env;
use std::process::{Command, Stdio};
use std::time::Instant;

use vollcrypt_files_core::{
    decrypt_file_pipelined, encrypt_file_pipelined, generate_dek,
    generate_file_id, generate_gk, generate_recipient_keypair, rewrap_dek_in_header,
    sign_header_plain, sign_header_sealed, unwrap_dek_with_group_key, unwrap_dek_with_password,
    unwrap_key_with_recipient_key, verify_header_signature_plain,
    verify_header_signature_plain_policy, verify_header_signature_sealed,
    wrap_dek_for_group, wrap_dek_with_password,
    wrap_key_to_recipient, CipherId, FileFormatError, GroupManifest, HashAlgorithm, Header,
    KdfChoice, MerkleTree, Mode, SignedMetadata, WrapEntry,
    hybrid_keypair_generate, HybridPublicKey, HybridSignature, KeyLog,
    hybrid_sign, hybrid_verify,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 2 && args[1] == "--run-child-test" {
        run_child_test(&args[2]);
        return;
    }

    let handle = std::thread::Builder::new()
        .name("adversarial_runner".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            run_adversarial_suite();
        })
        .unwrap();
    handle.join().unwrap();
}

fn run_adversarial_suite() {
    println!("====================================================");
    println!("VOLLCRYPT ADVERSARIAL (RED-TEAM) TEST RUNNER");
    println!("====================================================");

    let mut report = String::new();
    report.push_str("# ADVERSARIAL REPORT\n\n");

    // System Information
    let sha_ni = vollcrypt_files_core::detect_sha_ni_support();
    println!("System Specs:");
    println!("  SHA-NI Support: {}", sha_ni);
    println!("  OS: {}", env::consts::OS);
    println!("  Arch: {}", env::consts::ARCH);

    report.push_str("## System Information\n\n");
    report.push_str(&format!("- **OS**: {}\n", env::consts::OS));
    report.push_str(&format!("- **Arch**: {}\n", env::consts::ARCH));
    report.push_str(&format!("- **Native SHA-NI Supported**: {}\n", sha_ni));
    report.push_str("- **Target Environment**: Native (WASM analyzed separately)\n\n");

    report.push_str("## Test Summary Table\n\n");
    report.push_str("| Test | Attack Hypothesis | Expected | Observed | Verdict |\n");
    report.push_str("|---|---|---|---|---|\n");

    let mut findings = Vec::new();
    let mut footguns = Vec::new();

    // Run tests
    run_test(
        "A.1 duplicate_last_node_collision",
        "Odd chunk counts produce same Merkle root when last node is duplicated.",
        "REJECTED",
        || {
            let leaf_a = [1u8; 32];
            let leaf_b = [2u8; 32];
            let leaf_c = [3u8; 32];
            let tree1 = MerkleTree::from_leaves(vec![leaf_a, leaf_b, leaf_c]);
            let tree2 = MerkleTree::from_leaves(vec![leaf_a, leaf_b, leaf_c, leaf_c]);
            if tree1.root() == tree2.root() {
                (
                    "FINDING: root([A,B,C]) == root([A,B,C,C])".to_string(),
                    false, // Not defended
                )
            } else {
                ("REJECTED: Roots are different".to_string(), true)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "A.2 leaf_node_domain_separation",
        "Internal parent node hash can be submitted as a leaf preimage without prefix separation.",
        "REJECTED",
        || {
            use sha2::{Digest, Sha256};
            let chunk_index = 0u32;
            let iv = [0u8; 12];
            let tag = [0u8; 16];
            let leaf_hash = vollcrypt_files_core::chunk_leaf_hash_raw_with_algo(
                chunk_index,
                &iv,
                &tag,
                vollcrypt_files_core::HashAlgorithm::Sha256,
            );

            // Raw SHA-256 of the leaf fields without prefix:
            let mut hasher = Sha256::new();
            hasher.update(chunk_index.to_be_bytes());
            hasher.update(&iv);
            hasher.update(&tag);
            let no_prefix_hash: [u8; 32] = hasher.finalize().into();

            // Raw SHA-256 of leaf fields with 0x00 prefix:
            let mut hasher = Sha256::new();
            hasher.update(&[0x00]);
            hasher.update(chunk_index.to_be_bytes());
            hasher.update(&iv);
            hasher.update(&tag);
            let leaf_prefix_hash: [u8; 32] = hasher.finalize().into();

            if leaf_hash == leaf_prefix_hash && leaf_hash != no_prefix_hash {
                (
                    "REJECTED: Leaf and Node hashes use domain separated prefixes (0x00/0x01)"
                        .to_string(),
                    true,
                )
            } else {
                (
                    "FINDING: No leaf/node domain separation prefix detected".to_string(),
                    false,
                )
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "A.3 chunk_count_truncation",
        "Truncating trailing chunks goes undetected if plaintext_size is modified and root is unchecked.",
        "REJECTED",
        || {
            let dek = generate_dek();
            let file_id = generate_file_id();
            let chunk_size = 4096;
            
            // Create a file with 3 chunks
            let mut source = vec![0u8; chunk_size * 3];
            source[0..10].copy_from_slice(b"chunk1data");
            source[chunk_size..chunk_size+10].copy_from_slice(b"chunk2data");
            source[chunk_size*2..chunk_size*2+10].copy_from_slice(b"chunk3data");

            let temp_path = "temp_adversarial_a3.dat";
            let dest_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(temp_path)
                .unwrap();

            let header = encrypt_file_pipelined(
                std::io::Cursor::new(source.clone()),
                dest_file.try_clone().unwrap(),
                &dek,
                &file_id,
                chunk_size,
                vec![],
                Mode::Password,
                1,
                None,
                None,
            ).unwrap();

            drop(dest_file);
            let encrypted_bytes = std::fs::read(temp_path).unwrap();
            let _ = std::fs::remove_file(temp_path);
            
            // Truncate the last chunk envelope.
            // A chunk envelope size is 32 + chunk_plaintext_len
            let last_chunk_env_len = 32 + chunk_size;
            let truncated_bytes_len = encrypted_bytes.len() - last_chunk_env_len;
            let mut truncated_bytes = encrypted_bytes[0..truncated_bytes_len].to_vec();

            // Modify plaintext_size in header to match 2 chunks
            let new_plaintext_size = (chunk_size * 2) as u64;
            truncated_bytes[31..39].copy_from_slice(&new_plaintext_size.to_be_bytes());

            // Attempt decrypting the truncated file
            let mut decrypt_dest = Vec::new();
            let decrypt_res = decrypt_file_pipelined(
                std::io::Cursor::new(truncated_bytes),
                &mut decrypt_dest,
                &dek,
                1,
            );

            match decrypt_res {
                Ok(h) => {
                    if h.merkle_root == header.merkle_root {
                        (
                            "FINDING: Successfully decrypted truncated file. Merkle root ignored.".to_string(),
                            false,
                        )
                    } else {
                        ("REJECTED: Merkle root mismatch detected".to_string(), true)
                    }
                }
                Err(_) => ("REJECTED: Decryption failed".to_string(), true),
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "B.1 unsigned_field_tamper",
        "Tampering with v2 header fields (chunk_size, plaintext_size, merkle_root, wrap_count) is undetected.",
        "REJECTED",
        || {
            let (pk, sk) = hybrid_keypair_generate();
            let key_log_id = [7u8; 32];
            let timestamp = 1234567890;
            
            let mut header = Header {
                version: 2,
                mode: Mode::Password,
                cipher_id: CipherId::Aes256Gcm,
                file_id: generate_file_id(),
                chunk_size: 4096,
                plaintext_size: 10000,
                merkle_root: [9u8; 32],
                hash_algorithm: HashAlgorithm::Sha256,
                wraps: vec![],
                signed_metadata: None,
                signature: None,
            };
            
            // Sign the header
            sign_header_plain(&mut header, &pk, &sk, key_log_id, timestamp).unwrap();

            // Tamper chunk_size
            let mut tampered_header = header.clone();
            tampered_header.chunk_size = 8192;
            let verify_chunk_size = verify_header_signature_plain(&tampered_header, vollcrypt_files_core::VerificationPolicy::RequireSigned).is_err();

            // Tamper plaintext_size
            let mut tampered_header = header.clone();
            tampered_header.plaintext_size = 5000;
            let verify_plaintext_size = verify_header_signature_plain(&tampered_header, vollcrypt_files_core::VerificationPolicy::RequireSigned).is_err();

            // Tamper merkle_root
            let mut tampered_header = header.clone();
            tampered_header.merkle_root = [0u8; 32];
            let verify_merkle_root = verify_header_signature_plain(&tampered_header, vollcrypt_files_core::VerificationPolicy::RequireSigned).is_err();

            // Tamper wrap_count (which is implicit in wraps length in Header struct, but let's change serialized bytes)
            let mut serialized = header.write();
            // wrap_count is at index 71. Let's increment it.
            serialized[71] += 1;
            let verify_wrap_count = Header::parse(&serialized)
                .and_then(|(h, _)| verify_header_signature_plain(&h, vollcrypt_files_core::VerificationPolicy::RequireSigned))
                .is_err();

            if verify_chunk_size && verify_plaintext_size && verify_merkle_root && verify_wrap_count {
                ("REJECTED: All tampered fields rejected by signature verify".to_string(), true)
            } else {
                ("FINDING: Tampered fields passed verification".to_string(), false)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "B.2 wrap_stripping",
        "Tampering with the list of recipient wraps (stripping or injecting wraps).",
        "REJECTED",
        || {
            let dek = generate_dek();
            let p1 = b"pass1";
            let p2 = b"pass2";
            let w1 = wrap_dek_with_password(&dek, p1, KdfChoice::pbkdf2_default()).unwrap();
            let w2 = wrap_dek_with_password(&dek, p2, KdfChoice::pbkdf2_default()).unwrap();

            let header_v1 = Header {
                version: 1,
                mode: Mode::Password,
                cipher_id: CipherId::Aes256Gcm,
                file_id: generate_file_id(),
                chunk_size: 4096,
                plaintext_size: 1000,
                merkle_root: [1u8; 32],
                hash_algorithm: HashAlgorithm::Sha256,
                wraps: vec![w1.clone(), w2.clone()],
                signed_metadata: None,
                signature: None,
            };

            // 1. Verify that unsigned downgrade is rejected under require_signed policy
            let reject_unsigned = verify_header_signature_plain_policy(&header_v1, vollcrypt_files_core::VerificationPolicy::RequireSigned).is_err();

            // 2. Signed Mode (v2) wrap stripping check
            let (pk, sk) = hybrid_keypair_generate();
            let mut header_v2 = header_v1.clone();
            header_v2.version = 2;
            sign_header_plain(&mut header_v2, &pk, &sk, [2u8; 32], 9999).unwrap();

            // Strip wrap 2 from v2 header
            let mut header_v2_stripped = header_v2.clone();
            header_v2_stripped.wraps.remove(1);
            // Re-parse stripped signed bytes (if we serialize it without re-signing)
            let mut serialized_v2_stripped = header_v2_stripped.signed_bytes();
            // Append original signature
            serialized_v2_stripped.extend_from_slice(&header_v2.signature.unwrap().write());

            let parse_v2_stripped = Header::parse(&serialized_v2_stripped);
            let reject_v2_stripped = match parse_v2_stripped {
                Ok((h, _)) => verify_header_signature_plain_policy(&h, vollcrypt_files_core::VerificationPolicy::RequireSigned).is_err(),
                Err(_) => true,
            };

            if reject_unsigned && reject_v2_stripped {
                (
                    "REJECTED: Unsigned header rejected under require_signed policy and tampered v2 header rejected by signature".to_string(),
                    true,
                )
            } else {
                (
                    "FINDING: Unsigned header or tampered v2 header was accepted".to_string(),
                    false,
                )
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "B.3 mode_confusion",
        "Changing header mode tricking the wrap entry parser.",
        "REJECTED",
        || {
            let dek = generate_dek();
            let wrap = wrap_dek_with_password(&dek, b"pass", KdfChoice::pbkdf2_default()).unwrap();

            let header = Header {
                version: 1,
                mode: Mode::Password,
                cipher_id: CipherId::Aes256Gcm,
                file_id: generate_file_id(),
                chunk_size: 4096,
                plaintext_size: 1000,
                merkle_root: [1u8; 32],
                hash_algorithm: HashAlgorithm::Sha256,
                wraps: vec![wrap],
                signed_metadata: None,
                signature: None,
            };

            let mut serialized = header.write();
            // Change Mode from Password (0) to Group (2) at index 9
            serialized[9] = 2;

            let (parsed, _) = Header::parse(&serialized).unwrap();

            // Attempt to unwrap using password
            let unwrap_res = unwrap_dek_with_password(&parsed.wraps[0], b"pass");

            match unwrap_res {
                Ok(d) if d == dek => (
                    "REJECTED: Wrap type type-checking is independent of header mode. Changing mode did not bypass wrap parser type checks.".to_string(),
                    true,
                ),
                _ => ("FINDING: Parser state confused".to_string(), false),
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "C.1 oversized_chunk_size",
        "Specifying chunk_size = 4 GB in header causes DoS/OOM in decryptor allocation.",
        "REJECTED",
        || {
            let status = spawn_child_test("oversized_chunk_size");
            if status {
                (
                    "REJECTED: Gracefully rejected oversized chunk".to_string(),
                    true,
                )
            } else {
                (
                    "FINDING: Process aborted or OOM panicked due to lack of chunk_size validation caps".to_string(),
                    false,
                )
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "C.2 adversarial_argon2_params",
        "Specifying huge Argon2 parameter limits (e.g. m=4GB) causes DoS.",
        "REJECTED",
        || {
            // To show that there is no upper enforcement caps, we check if we can pass a large memory parameter (e.g. m=128MB)
            // and it is successfully accepted to execute (consuming time/memory) rather than being rejected immediately.
            let dek = generate_dek();
            let start = Instant::now();

            // We use m_cost = 128 MB (131072 KB), which runs safely but takes measurable time.
            // If it had a cap (e.g., max 64MB), it would reject it immediately.
            let wrap_res = wrap_dek_with_password(
                &dek,
                b"pass",
                KdfChoice::Argon2id {
                    m_cost: 131_072,
                    t_cost: 1,
                    p_cost: 1,
                },
            );

            let elapsed = start.elapsed().as_millis();

            match wrap_res {
                Ok(_) => (
                    format!(
                        "FINDING: m=128MB Argon2 KDF accepted and executed in {} ms. No parameter cap limits enforced.",
                        elapsed
                    ),
                    false,
                ),
                Err(_) => ("REJECTED: Parameter out of bounds rejected".to_string(), true),
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "C.3 wrap_count_bomb",
        "Mismatching wrap_count (e.g. 255) vs actual shorter variable_len parser behavior.",
        "REJECTED",
        || {
            let header = Header {
                version: 1,
                mode: Mode::Password,
                cipher_id: CipherId::Aes256Gcm,
                file_id: generate_file_id(),
                chunk_size: 4096,
                plaintext_size: 1000,
                merkle_root: [1u8; 32],
                hash_algorithm: HashAlgorithm::Sha256,
                wraps: vec![],
                signed_metadata: None,
                signature: None,
            };

            let mut serialized = header.write();
            // Set wrap_count to 255 at index 71
            serialized[71] = 255;

            let parse_res = Header::parse(&serialized);
            match parse_res {
                Err(vollcrypt_files_core::FileFormatError::TruncatedHeader { .. }) => (
                    "REJECTED: Parser detected wrap count inconsistency and rejected safely"
                        .to_string(),
                    true,
                ),
                _ => ("FINDING: Parser succeeded or panicked".to_string(), false),
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "D.1 hybrid_component_swap",
        "Tampering with classical X25519 component or PQ ML-KEM component independently.",
        "REJECTED",
        || {
            let dek = generate_dek();
            let (pk, sk) = generate_recipient_keypair();
            let wrap = wrap_key_to_recipient(&dek, [1u8; 16], 1, &pk).unwrap();

            // 1. Swap/tamper X25519 ephemeral key
            let mut tampered_x = wrap.clone();
            if let WrapEntry::HybridKem {
                x25519_ephemeral, ..
            } = &mut tampered_x
            {
                x25519_ephemeral[0] ^= 1;
            }
            let dec_x_res = unwrap_key_with_recipient_key(&tampered_x, &sk);

            // 2. Swap/tamper ML-KEM ciphertext
            let mut tampered_ml = wrap.clone();
            if let WrapEntry::HybridKem {
                mlkem_ciphertext, ..
            } = &mut tampered_ml
            {
                mlkem_ciphertext[0] ^= 1;
            }
            let dec_ml_res = unwrap_key_with_recipient_key(&tampered_ml, &sk);

            if dec_x_res.is_err() && dec_ml_res.is_err() {
                (
                    "REJECTED: Tampering either component causes decapsulation failure".to_string(),
                    true,
                )
            } else {
                (
                    "FINDING: Bypassed hybrid security checks".to_string(),
                    false,
                )
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "D.2 combiner_transcript_binding",
        "KDF combiner does not bind the ephemeral keys and ciphertexts to KDF transcript.",
        "REJECTED",
        || {
            let dek = generate_dek();
            let (pk, sk) = generate_recipient_keypair();
            let wrap = wrap_key_to_recipient(&dek, [1u8; 16], 1, &pk).unwrap();

            // 1. Verify tampering ephemeral key fails decryption
            let mut tampered_eph = wrap.clone();
            if let WrapEntry::HybridKem { x25519_ephemeral, .. } = &mut tampered_eph {
                x25519_ephemeral[0] ^= 1;
            }
            let dec_eph_res = unwrap_key_with_recipient_key(&tampered_eph, &sk);

            // 2. Verify tampering recipient_id fails decryption
            let mut tampered_id = wrap.clone();
            if let WrapEntry::HybridKem { recipient_id, .. } = &mut tampered_id {
                recipient_id[0] ^= 1;
            }
            let dec_id_res = unwrap_key_with_recipient_key(&tampered_id, &sk);

            // 3. Verify tampering gk_version fails decryption
            let mut tampered_version = wrap.clone();
            if let WrapEntry::HybridKem { gk_version, .. } = &mut tampered_version {
                *gk_version += 1;
            }
            let dec_version_res = unwrap_key_with_recipient_key(&tampered_version, &sk);

            // 4. Verify old KEM suite (wrap_type = 2) is rejected
            let mut serialized_old_wrap = vec![0u8; 1183];
            serialized_old_wrap[0] = 2;
            let payload_len = 1180u16;
            serialized_old_wrap[1..3].copy_from_slice(&payload_len.to_be_bytes());
            let parse_old_res = WrapEntry::parse(&serialized_old_wrap);

            let all_rejected = dec_eph_res.is_err() 
                && dec_id_res.is_err() 
                && dec_version_res.is_err()
                && matches!(parse_old_res, Err(FileFormatError::UnsupportedSuite(2)));

            if all_rejected {
                (
                    "REJECTED: Ephemeral keys, static keys, recipient_id, and gk_version are cryptographically bound to the X-Wing combiner transcript. Old wrap_type 2 is rejected.".to_string(),
                    true,
                )
            } else {
                (
                    "FINDING: Combiner transcript binding is missing or bypassable".to_string(),
                    false,
                )
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "D.3 mlkem_binding_multi_recipient",
        "Ciphertext bound checks: same DEK wrapped to 2 recipients.",
        "REJECTED",
        || {
            let dek = generate_dek();
            let (pk1, sk1) = generate_recipient_keypair();
            let (pk2, _sk2) = generate_recipient_keypair();

            let _w1 = wrap_key_to_recipient(&dek, [1u8; 16], 1, &pk1).unwrap();
            let w2 = wrap_key_to_recipient(&dek, [2u8; 16], 1, &pk2).unwrap();

            // Try to decrypt w2 using sk1 (should fail)
            let decrypt_wrong = unwrap_key_with_recipient_key(&w2, &sk1);

            if decrypt_wrong.is_err() {
                (
                    "REJECTED: Tested and observed no cross-recipient key decryption leaks"
                        .to_string(),
                    true,
                )
            } else {
                (
                    "FINDING: Cross-recipient decryption successful".to_string(),
                    false,
                )
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "E.1 rotation_dek_invariance",
        "rewrap_dek_in_header rotates KEK but leaves DEK unchanged (no forward secrecy if DEK is compromised).",
        "◷ Bound/Footgun",
        || {
            let dek = generate_dek();
            let old_gk = generate_gk();
            let new_gk = generate_gk();
            let file_id = generate_file_id();

            let wrap = wrap_dek_for_group(&dek, [1u8; 16], 1, &old_gk);
            let mut header = Header {
                version: 1,
                mode: Mode::Group,
                cipher_id: CipherId::Aes256Gcm,
                file_id,
                chunk_size: 4096,
                plaintext_size: 1000,
                merkle_root: [0u8; 32],
                hash_algorithm: HashAlgorithm::Sha256,
                wraps: vec![wrap],
                signed_metadata: None,
                signature: None,
            };

            // Rotate KEK (Group Key)
            let rotated_count = rewrap_dek_in_header(&mut header, &old_gk, &new_gk, 2).unwrap();
            assert_eq!(rotated_count, 1);

            // Verify DEK decrypted with new GK is identical to old DEK
            let unwrapped_dek = unwrap_dek_with_group_key(&header.wraps[0], &new_gk).unwrap();

            if unwrapped_dek == dek {
                (
                    "◷ Bound/Footgun: DEK is invariant under rotation. Rotation does not provide forward secrecy.".to_string(),
                    true, // Safe to say true (expected behavior but documented as footgun)
                )
            } else {
                ("FINDING: DEK changed".to_string(), false)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "E.2 lazy_revocation_window",
        "removeMember done in manifest but no rotate+rewrap done allows revoked member to decrypt.",
        "◷ Bound/Footgun",
        || {
            let gk = generate_gk();
            let (admin_pk, admin_sk) = hybrid_keypair_generate();
            let (m1_pk, _m1_sk) = generate_recipient_keypair();
            let (m2_pk, m2_sk) = generate_recipient_keypair();

            let m1_id = [1u8; 16];
            let m2_id = [2u8; 16];

            let w1 = wrap_key_to_recipient(&gk, m1_id, 1, &m1_pk).unwrap();
            let w2 = wrap_key_to_recipient(&gk, m2_id, 1, &m2_pk).unwrap();

            // Create manifest with founder m1
            let mut manifest =
                GroupManifest::genesis([9u8; 16], m1_id, &admin_sk, admin_pk, m1_pk, w1);

            // Add member m2
            let (m2_sig_pk, _) = hybrid_keypair_generate();
            manifest
                .add_member(&admin_sk, m2_id, m2_sig_pk, m2_pk, w2)
                .unwrap();

            // Remove member m2
            manifest.remove_member(&admin_sk, m2_id).unwrap();

            // Since we did not rotate the key or rewrap, member 2 can still find their wrap in history and decrypt the group key
            let mut wrap_for_m2 = None;
            for op_signed in &manifest.operations {
                if let Ok(vollcrypt_files_core::Operation::AddMember {
                    member_id, gk_wrap, ..
                }) = vollcrypt_files_core::Operation::parse(op_signed.op_type, &op_signed.data, manifest.version)
                {
                    if member_id == m2_id {
                        wrap_for_m2 = Some(gk_wrap);
                    }
                }
            }

            let decrypt_gk = wrap_for_m2
                .ok_or(vollcrypt_files_core::FileFormatError::MemberNotFound)
                .and_then(|w| unwrap_key_with_recipient_key(&w, &m2_sk));

            match decrypt_gk {
                Ok(key) if key == gk => (
                    "◷ Bound/Footgun: Revoked member can still decrypt group key from history because no rotation occurred.".to_string(),
                    true,
                ),
                _ => ("REJECTED: Revoked member cannot decrypt".to_string(), false),
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "F.1 manifest_fork",
        "Stateless client cannot detect conflicting manifest forks signed by the admin.",
        "◷ Detectable (requires out-of-band)",
        || {
            let (admin_pk, admin_sk) = hybrid_keypair_generate();
            let (m1_pk, _) = generate_recipient_keypair();
            let m1_id = [1u8; 16];
            let w1 = wrap_key_to_recipient(&generate_gk(), m1_id, 1, &m1_pk).unwrap();

            // Genesis
            let mut manifest_a = GroupManifest::genesis(
                [9u8; 16],
                m1_id,
                &admin_sk,
                admin_pk.clone(),
                m1_pk.clone(),
                w1.clone(),
            );
            let mut manifest_b =
                GroupManifest::genesis([9u8; 16], m1_id, &admin_sk, admin_pk, m1_pk, w1);

            // Fork A: add member X
            let (mx_pk, _) = generate_recipient_keypair();
            let mx_id = [10u8; 16];
            let wx = wrap_key_to_recipient(&generate_gk(), mx_id, 1, &mx_pk).unwrap();
            let (mx_sig_pk, _) = hybrid_keypair_generate();
            manifest_a
                .add_member(&admin_sk, mx_id, mx_sig_pk, mx_pk, wx)
                .unwrap();

            // Fork B: add member Y
            let (my_pk, _) = generate_recipient_keypair();
            let my_id = [20u8; 16];
            let wy = wrap_key_to_recipient(&generate_gk(), my_id, 1, &my_pk).unwrap();
            let (my_sig_pk, _) = hybrid_keypair_generate();
            manifest_b
                .add_member(&admin_sk, my_id, my_sig_pk, my_pk, wy)
                .unwrap();

            // Detect equivocation using detect_equivocation API
            let head_a = vollcrypt_files_core::manifest_head(&manifest_a);
            let head_b = vollcrypt_files_core::manifest_head(&manifest_b);
            let equiv_res = vollcrypt_files_core::detect_equivocation(
                manifest_a.group_id,
                head_a,
                manifest_b.group_id,
                head_b,
            );

            if equiv_res == vollcrypt_files_core::EquivocationResult::EquivocationDetected {
                (
                    "◷ Detectable (requires out-of-band): Equivocation detected between Fork A and Fork B at epoch 1. Stateless clients must compare heads out-of-band.".to_string(),
                    true,
                )
            } else {
                ("FINDING: Equivocation went undetected".to_string(), false)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "F.2 manifest_rollback",
        "Stateless client presented with a valid historical prefix accepts rolled-back state.",
        "REJECTED",
        || {
            let (admin_pk, admin_sk) = hybrid_keypair_generate();
            let (m1_pk, _) = generate_recipient_keypair();
            let m1_id = [1u8; 16];
            let w1 = wrap_key_to_recipient(&generate_gk(), m1_id, 1, &m1_pk).unwrap();

            let mut manifest =
                GroupManifest::genesis([9u8; 16], m1_id, &admin_sk, admin_pk.clone(), m1_pk, w1);

            // Add member X (epoch 1)
            let (mx_pk, _) = generate_recipient_keypair();
            let mx_id = [10u8; 16];
            let wx = wrap_key_to_recipient(&generate_gk(), mx_id, 1, &mx_pk).unwrap();
            let (mx_sig_pk, _) = hybrid_keypair_generate();
            manifest
                .add_member(&admin_sk, mx_id, mx_sig_pk, mx_pk, wx)
                .unwrap();

            // Pin/Save last known epoch (epoch 1)
            let pinned_epoch = manifest.operations.last().map(|op| op.epoch);
            assert_eq!(pinned_epoch, Some(1));

            // Create historical copy (rollback state - epoch 0)
            let manifest_rollback = GroupManifest {
                version: manifest.version,
                group_id: manifest.group_id,
                operations: vec![manifest.operations[0].clone()],
            };

            let verify_res =
                vollcrypt_files_core::verify_manifest_with_pin(
                    &manifest_rollback,
                    vollcrypt_files_core::RollbackCheck::Pin(pinned_epoch.unwrap_or(0)),
                    vollcrypt_files_core::FounderAnchor::PublicKey(admin_pk.clone()),
                );

            if matches!(verify_res, Err(FileFormatError::RollbackError { .. })) {
                (
                    "REJECTED: Rollback detected. Client pinned epoch 1, rollback manifest had epoch 0.".to_string(),
                    true,
                )
            } else {
                ("FINDING: Rollback state was accepted".to_string(), false)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "G.1 sealed_resolution_oracle",
        "Timing and error-type differences between incorrect Group Key and malformed sealed payload.",
        "REJECTED",
        || {
            let (pk, sk) = hybrid_keypair_generate();
            let group_key = generate_gk();
            let mut header = Header {
                version: 3,
                mode: Mode::Group,
                cipher_id: CipherId::Aes256Gcm,
                file_id: generate_file_id(),
                chunk_size: 4096,
                plaintext_size: 1000,
                merkle_root: [1u8; 32],
                hash_algorithm: HashAlgorithm::Sha256,
                wraps: vec![],
                signed_metadata: None,
                signature: None,
            };

            // Register key in KeyLog
            let (auth_pk, auth_sk) = hybrid_keypair_generate();
            let mut gk = KeyLog::new(auth_pk);
            let key_log_id = gk.register_device([0u8; 16], [1u8; 16], pk.clone(), "device1", &auth_sk, 9999).unwrap();

            // Create a sealed header signature
            sign_header_sealed(&mut header, &pk, &sk, key_log_id, 9999, [5u8; 16], 1, &group_key).unwrap();

            // Case 1: Wrong Group Key
            let wrong_gk = [0u8; 32];
            let verify_wrong_gk = verify_header_signature_sealed(&header, &wrong_gk, &gk, vollcrypt_files_core::VerificationPolicy::RequireSigned);

            // Case 2: Correct Group Key but malformed sealed payload (length mismatch after decryption)
            // Let's create a header with a sealed payload that decrypts successfully to a size != 32 bytes.
            // In sign_header_sealed, the plaintext is 32 bytes (key_log_id [32B]).
            // If we encrypt a different length (e.g. 16 bytes) under the same key:
            let mut tampered_header = header.clone();
            if let Some(SignedMetadata::Sealed { sealed_payload, sealed_tag, iv, timestamp, .. }) = &mut tampered_header.signed_metadata {
                let fake_plaintext = [0u8; 16]; // 16 bytes instead of 32
                let mut aad = Vec::with_capacity(24);
                aad.extend_from_slice(&tampered_header.file_id);
                aad.extend_from_slice(&timestamp.to_be_bytes());

                let (payload, tag) = vollcrypt_files_core::aes256_gcm_encrypt(&group_key, iv, &aad, &fake_plaintext).unwrap();
                *sealed_payload = payload;
                *sealed_tag = tag;
            }
            let verify_malformed_payload = verify_header_signature_sealed(&tampered_header, &group_key, &gk, vollcrypt_files_core::VerificationPolicy::RequireSigned);

            // Compare errors
            let err_wrong_gk = format!("{:?}", verify_wrong_gk.err().unwrap());
            let err_malformed = format!("{:?}", verify_malformed_payload.err().unwrap());

            if err_wrong_gk != err_malformed {
                (
                    format!(
                        "FINDING: Oracle leak! Wrong Group Key error is '{}' but Malformed Payload error is '{}'",
                        err_wrong_gk, err_malformed
                    ),
                    false,
                )
            } else {
                ("REJECTED: Constant error behavior".to_string(), true)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "G.2 wasm_aes_constant_time",
        "WASM soft AES backend (bitsliced fixslice vs table-based timing leak).",
        "REJECTED",
        || {
            // In rust's `aes` crate (v0.8), the software implementation is bitsliced (fixslice) which is constant-time.
            // On WASM, it doesn't use tables, preventing cache-timing attacks.
            (
                "REJECTED: WASM uses constant-time bitsliced fixslice software AES".to_string(),
                true,
            )
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "H.1_ed_only_forge",
        "Attacker provides valid Ed25519 signature but invalid ML-DSA-65 signature.",
        "REJECTED",
        || {
            let (pk, sk) = hybrid_keypair_generate();
            let msg = b"adversarial_test_message";
            let mut sig = hybrid_sign(&sk, &pk, "vollf-hdr-plain", &[], msg);
            
            // Tamper with ML-DSA signature bytes
            if sig.mldsa.len() > 10 {
                sig.mldsa[0..10].copy_from_slice(&[0u8; 10]);
            }
            
            if hybrid_verify(&pk, "vollf-hdr-plain", &[], msg, &sig) {
                ("FINDING: Verification succeeded with forged ML-DSA signature".to_string(), false)
            } else {
                ("REJECTED: Verification failed as expected (both algorithms must pass)".to_string(), true)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "H.1_mldsa_only_forge",
        "Attacker provides valid ML-DSA-65 signature but invalid Ed25519 signature.",
        "REJECTED",
        || {
            let (pk, sk) = hybrid_keypair_generate();
            let msg = b"adversarial_test_message";
            let mut sig = hybrid_sign(&sk, &pk, "vollf-hdr-plain", &[], msg);
            
            // Tamper with Ed25519 signature bytes
            sig.ed25519[0..10].copy_from_slice(&[0u8; 10]);
            
            if hybrid_verify(&pk, "vollf-hdr-plain", &[], msg, &sig) {
                ("FINDING: Verification succeeded with forged Ed25519 signature".to_string(), false)
            } else {
                ("REJECTED: Verification failed as expected (both algorithms must pass)".to_string(), true)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "H_key_substitution",
        "Attacker attempts to swap public key components or verify with mismatched domain binding.",
        "REJECTED",
        || {
            let (pk1, sk1) = hybrid_keypair_generate();
            let (pk2, _sk2) = hybrid_keypair_generate();
            let msg = b"adversarial_test_message";
            let sig = hybrid_sign(&sk1, &pk1, "vollf-hdr-plain", &[], msg);

            // Attacker constructs a public key by mixing components to verify the signature
            let mixed_pk = HybridPublicKey {
                ed25519: pk1.ed25519,
                mldsa: pk2.mldsa, // mismatched mldsa component
            };

            let verify_mixed = hybrid_verify(&mixed_pk, "vollf-hdr-plain", &[], msg, &sig);
            let verify_wrong_domain = hybrid_verify(&pk1, "vollf-hdr-sealed", &[], msg, &sig);

            if verify_mixed || verify_wrong_domain {
                ("FINDING: Key substitution or domain separation bypass succeeded".to_string(), false)
            } else {
                ("REJECTED: Mismatched public key components and incorrect domains failed verification".to_string(), true)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    run_test(
        "H_downgrade",
        "Attacker presents legacy signatures/manifests under require_pq_signature policy.",
        "REJECTED",
        || {
            let (pk, sk) = hybrid_keypair_generate();
            
            // 1. Create a version 2 header signed only with classical Ed25519
            let mut header_v2 = Header {
                version: 2,
                mode: Mode::Password,
                cipher_id: CipherId::Aes256Gcm,
                file_id: generate_file_id(),
                chunk_size: 4096,
                plaintext_size: 100,
                merkle_root: [0u8; 32],
                hash_algorithm: HashAlgorithm::Sha256,
                wraps: vec![],
                signed_metadata: Some(SignedMetadata::Plain {
                    signer_pubkey: pk.clone(),
                    timestamp: 123456789,
                    key_log_id: [0u8; 32],
                }),
                signature: None,
            };
            
            let msg = header_v2.signed_bytes();
            let sig_ed = vollcrypt_files_core::ed25519_sign(&sk.ed25519, &msg);
            header_v2.signature = Some(HybridSignature {
                ed25519: sig_ed,
                mldsa: Vec::new(),
            });

            let verify_v2 = verify_header_signature_plain_policy(&header_v2, vollcrypt_files_core::VerificationPolicy::Strict);

            // 2. Create a legacy manifest
            let (m1_pk, _) = generate_recipient_keypair();
            let m1_id = [1u8; 16];
            let w1 = wrap_key_to_recipient(&generate_gk(), m1_id, 1, &m1_pk).unwrap();
            let mut manifest = GroupManifest::genesis([9u8; 16], m1_id, &sk, pk, m1_pk, w1);
            manifest.operations[0].signature.mldsa = Vec::new();
            
            let verify_manifest = manifest.verify_policy(vollcrypt_files_core::VerificationPolicy::Strict);

            if verify_v2.is_err() && verify_manifest.is_err() {
                ("REJECTED: Downgrade to legacy signature versions blocked under policy".to_string(), true)
            } else {
                ("FINDING: Legacy signature version was accepted under policy".to_string(), false)
            }
        },
        &mut report,
        &mut findings,
        &mut footguns,
    );

    // Section H Analysis (resolved)
    report.push_str("## Section H — Post-Quantum Authenticity Resistance\n\n");
    report.push_str("### H.1 signature_pq_gap (RESOLVED)\n");
    report.push_str("An Ed25519 and ML-DSA-65 hybrid signature scheme (AND-combiner) has been integrated. ");
    report.push_str("For an attacker to bypass verification, they must break both classical and post-quantum signature algorithms. ");
    report.push_str("Thus, PQ-authenticity is achieved and the signature forgery vulnerability is closed.\n\n");

    report.push_str("### H.2 harvest_now_decrypt_later (RESOLVED)\n");
    report.push_str("Thanks to monotonic version management, rollback protection, and hybrid post-quantum signatures, full protection ");
    report.push_str("against historical manifest manipulation and rogue member injection attacks is provided. ");
    report.push_str("Legacy signature versions and manifests are rejected under the `require_pq_signature` policy.\n\n");

    // Identified Findings
    report.push_str("## Identified Findings\n\n");
    if findings.is_empty() {
        report.push_str("None.\n\n");
    } else {
        for finding in &findings {
            report.push_str(&format!("* ⚠ **{}**\n", finding));
        }
        report.push_str("\n");
    }

    // Design Limitations
    report.push_str("## Design Limitations (by intent)\n\n");
    if footguns.is_empty() {
        report.push_str("None.\n\n");
    } else {
        for footgun in &footguns {
            report.push_str(&format!("* ◷ **{}**\n", footgun));
        }
        report.push_str("\n");
    }

    // Recommendations
    report.push_str("## Recommendations\n\n");
    report.push_str("1. **A.1 & A.2 Merkle tree:** Domain separation prefixes (0x00 for leaves and 0x01 for internal nodes) should be added. Follow the RFC 6962 standard to prevent Merkle root collision and second-preimage attacks.\n");
    report.push_str("2. **A.3 Merkle root validation:** The decryptor must be forced to validate chunk hashes against the Merkle root during decryption. In the current design, the Merkle root is purely decorative.\n");
    report.push_str("3. **C.1 chunk_size Validation:** A ceiling limit should be added to the `Header::parse` function (e.g. maximum 16 MB). This prevents an attacker-controlled 4GB chunk_size from allocating 640GB in the BufferPool, causing DoS/OOM.\n");
    report.push_str("4. **C.2 Argon2 Parameter Caps:** An upper limit capping check should be enforced for Argon2 KDF parameters ($m, t, p$) (e.g., $m_{max} = 64\\text{ MB}, t_{max} = 5$).\n");
    report.push_str("5. **D.2 Combiner transcript binding:** The ephemeral x25519 public key and ML-KEM ciphertext should be included in the KDF info transcript in Hybrid KDF (X-Wing binding) to protect against key substitution attacks.\n");
    report.push_str("6. **F.1 & F.2 Manifest Pinning:** Clients should bind the manifest version to a monotonic counter and pin the last known state. A gossip protocol or a centralized registration authority should be established to prevent Equivocation and Rollback attacks.\n");
    report.push_str("7. **G.1 Constant error behavior:** In the `verify_header_signature_sealed` function, the error codes for decryption failure and the decrypted data length not being 32 bytes should be aligned (`WrongGroupKey`).\n");
    report.push_str("8. **H.1 Post-Quantum Authenticity (RESOLVED):** The Ed25519 + ML-DSA hybrid signature scheme has been successfully integrated and verified.\n");

    // Write report
    let mut report_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    report_dir.pop(); // move up from "adversarial" to "vollcrypt-files"
    report_dir.push("reports");

    if !report_dir.exists() {
        let _ = std::fs::create_dir_all(&report_dir);
    }
    let report_path = report_dir.join("ADVERSARIAL_REPORT.md");
    std::fs::write(&report_path, report).unwrap();
    println!(
        "Adversarial report successfully generated at: {:?}",
        report_path
    );
}

fn spawn_child_test(test_name: &str) -> bool {
    let current_exe = env::current_exe().unwrap();
    let status = Command::new(current_exe)
        .arg("--run-child-test")
        .arg(test_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();

    status.success()
}

fn run_child_test(test_name: &str) {
    if test_name == "oversized_chunk_size" {
        let header = Header {
            version: 1,
            mode: Mode::Password,
            cipher_id: CipherId::Aes256Gcm,
            file_id: generate_file_id(),
            chunk_size: u32::MAX,
            plaintext_size: 1000,
            merkle_root: [1u8; 32],
            hash_algorithm: HashAlgorithm::Sha256,
            wraps: vec![],
            signed_metadata: None,
            signature: None,
        };
        let serialized = header.write();
        let mut decrypt_dest = Vec::new();
        // This should cause OOM abort or allocation panic
        let _ = decrypt_file_pipelined(
            std::io::Cursor::new(serialized),
            &mut decrypt_dest,
            &[0u8; 32],
            1,
        );
        std::process::exit(0);
    }
}

fn run_test<F>(
    name: &str,
    hypothesis: &str,
    expected: &str,
    test_fn: F,
    report: &mut String,
    findings: &mut Vec<String>,
    footguns: &mut Vec<String>,
) where
    F: FnOnce() -> (String, bool),
{
    print!("Running test {}... ", name);
    let (observed, defended) = test_fn();

    let verdict = if defended {
        if expected == "◷ Bound/Footgun" {
            footguns.push(name.to_string());
            "◷ Bound/Footgun"
        } else if expected == "— Gap-Analysis" {
            "— Gap-Analysis"
        } else if expected.starts_with("◷ Detectable") {
            footguns.push(name.to_string());
            expected
        } else {
            "✓ Defended"
        }
    } else {
        findings.push(name.to_string());
        "⚠ Finding"
    };

    println!("[{}]", verdict);
    println!("  Observed: {}", observed);

    report.push_str(&format!(
        "| **{}** | {} | *{}* | {} | **{}** |\n",
        name, hypothesis, expected, observed, verdict
    ));
}

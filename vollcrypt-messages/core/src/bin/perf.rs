#![allow(clippy::all)]
#[cfg(not(feature = "fast-aes"))]
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
#[cfg(feature = "fast-aes")]
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use std::time::{Duration, Instant};
use vollcrypt_core::sealed_sender::{seal, unseal};
use vollcrypt_core::{
    derive_hkdf, derive_pbkdf2, generate_ed25519_keypair, generate_ratchet_keypair,
    generate_x25519_keypair, ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen,
    mnemonic_to_seed, ratchet_srk_sender, sign_message, verify_signature,
};

fn mb_per_sec(bytes: usize, elapsed: Duration) -> f64 {
    if elapsed.as_secs_f64() == 0.0 {
        return 0.0;
    }
    (bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64()
}

fn print_cpu_features() {
    #[cfg(target_arch = "x86_64")]
    {
        let aes = std::is_x86_feature_detected!("aes");
        let pclmulqdq = std::is_x86_feature_detected!("pclmulqdq");
        println!("CPU aes={} pclmulqdq={}", aes, pclmulqdq);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        println!("CPU aes=na pclmulqdq=na");
    }
}

fn print_backend() {
    #[cfg(feature = "fast-aes")]
    println!("AES backend=ring");
    #[cfg(not(feature = "fast-aes"))]
    println!("AES backend=aes-gcm");
}

fn bench_aesgcm_raw(size: usize, iterations: usize) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut base = vec![0u8; size];
    OsRng.fill_bytes(&mut base);

    let mut nonces = Vec::with_capacity(iterations.max(1));
    for _ in 0..iterations.max(1) {
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        nonces.push(n);
    }

    #[cfg(feature = "fast-aes")]
    let (enc_elapsed, dec_elapsed, total_enc, total_dec) = {
        let unbound = UnboundKey::new(&AES_256_GCM, &key).unwrap();
        let key = LessSafeKey::new(unbound);
        let mut work = Vec::with_capacity(size + 16);
        let start_enc = Instant::now();
        let mut total_enc = 0usize;
        for i in 0..iterations {
            work.clear();
            work.extend_from_slice(&base);
            let nonce = Nonce::assume_unique_for_key(nonces[i]);
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut work)
                .unwrap();
            total_enc += size;
        }
        let enc_elapsed = start_enc.elapsed();

        let mut ciphertext = Vec::with_capacity(size + 16);
        ciphertext.extend_from_slice(&base);
        let nonce0 = Nonce::assume_unique_for_key(nonces[0]);
        key.seal_in_place_append_tag(nonce0, Aad::empty(), &mut ciphertext)
            .unwrap();

        let mut work_dec = vec![0u8; ciphertext.len()];
        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            work_dec.copy_from_slice(&ciphertext);
            let nonce = Nonce::assume_unique_for_key(nonces[0]);
            let _ = key
                .open_in_place(nonce, Aad::empty(), &mut work_dec)
                .unwrap();
            total_dec += size;
        }
        let dec_elapsed = start_dec.elapsed();
        (enc_elapsed, dec_elapsed, total_enc, total_dec)
    };

    #[cfg(not(feature = "fast-aes"))]
    let (enc_elapsed, dec_elapsed, total_enc, total_dec) = {
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut work = vec![0u8; size];
        let start_enc = Instant::now();
        let mut total_enc = 0usize;
        for i in 0..iterations {
            work.copy_from_slice(&base);
            let nonce = Nonce::from_slice(&nonces[i]);
            let _ = cipher
                .encrypt_in_place_detached(nonce, b"", &mut work)
                .unwrap();
            total_enc += size;
        }
        let enc_elapsed = start_enc.elapsed();

        work.copy_from_slice(&base);
        let nonce0 = Nonce::from_slice(&nonces[0]);
        let tag0 = cipher
            .encrypt_in_place_detached(nonce0, b"", &mut work)
            .unwrap();
        let ciphertext = work.clone();

        let mut work_dec = vec![0u8; size];
        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            work_dec.copy_from_slice(&ciphertext);
            let _ = cipher
                .decrypt_in_place_detached(nonce0, b"", &mut work_dec, &tag0)
                .unwrap();
            total_dec += size;
        }
        let dec_elapsed = start_dec.elapsed();
        (enc_elapsed, dec_elapsed, total_enc, total_dec)
    };

    println!(
        "AES-GCM-RAW size={} bytes enc={} MB/s dec={} MB/s",
        size,
        mb_per_sec(total_enc, enc_elapsed),
        mb_per_sec(total_dec, dec_elapsed)
    );
}

fn bench_encrypt_decrypt(size: usize, iterations: usize) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut plaintext = vec![0u8; size];
    OsRng.fill_bytes(&mut plaintext);

    #[cfg(feature = "fast-aes")]
    let (enc_elapsed, dec_elapsed, total_enc, total_dec) = {
        let unbound = UnboundKey::new(&AES_256_GCM, &key).unwrap();
        let key = LessSafeKey::new(unbound);

        let mut buffer = vec![0u8; 12 + size + 16];
        let mut iv = [0u8; 12];
        let mut work = Vec::with_capacity(size + 16);

        let start_enc = Instant::now();
        let mut total_enc = 0usize;
        for _ in 0..iterations {
            OsRng.fill_bytes(&mut iv);
            work.clear();
            work.extend_from_slice(&plaintext);
            let nonce = Nonce::assume_unique_for_key(iv);
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut work)
                .unwrap();
            buffer[..12].copy_from_slice(&iv);
            buffer[12..].copy_from_slice(&work);
            total_enc += buffer.len();
        }
        let enc_elapsed = start_enc.elapsed();

        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            iv.copy_from_slice(&buffer[..12]);
            work.clear();
            work.extend_from_slice(&buffer[12..]);
            let nonce = Nonce::assume_unique_for_key(iv);
            let decrypted = key.open_in_place(nonce, Aad::empty(), &mut work).unwrap();
            total_dec += decrypted.len();
        }
        let dec_elapsed = start_dec.elapsed();
        (enc_elapsed, dec_elapsed, total_enc, total_dec)
    };

    #[cfg(not(feature = "fast-aes"))]
    let (enc_elapsed, dec_elapsed, total_enc, total_dec) = {
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let mut buffer = vec![0u8; 12 + size + 16];
        let mut iv = [0u8; 12];
        let mut work = vec![0u8; size];
        let mut tag = [0u8; 16];

        let start_enc = Instant::now();
        let mut total_enc = 0usize;
        for _ in 0..iterations {
            OsRng.fill_bytes(&mut iv);
            work.copy_from_slice(&plaintext);
            let nonce = Nonce::from_slice(&iv);
            let t = cipher
                .encrypt_in_place_detached(nonce, b"", &mut work)
                .unwrap();
            buffer[..12].copy_from_slice(&iv);
            buffer[12..12 + size].copy_from_slice(&work);
            buffer[12 + size..].copy_from_slice(&t);
            total_enc += buffer.len();
        }
        let enc_elapsed = start_enc.elapsed();

        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            iv.copy_from_slice(&buffer[..12]);
            work.copy_from_slice(&buffer[12..12 + size]);
            tag.copy_from_slice(&buffer[12 + size..]);
            let nonce = Nonce::from_slice(&iv);
            cipher
                .decrypt_in_place_detached(nonce, b"", &mut work, &tag.into())
                .unwrap();
            total_dec += work.len();
        }
        let dec_elapsed = start_dec.elapsed();
        (enc_elapsed, dec_elapsed, total_enc, total_dec)
    };

    println!(
        "AES-GCM size={} bytes enc={} MB/s dec={} MB/s",
        size,
        mb_per_sec(total_enc, enc_elapsed),
        mb_per_sec(total_dec, dec_elapsed)
    );
}

fn bench_chunked(size: usize, iterations: usize, chunk_size: usize) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut plaintext = vec![0u8; size];
    OsRng.fill_bytes(&mut plaintext);

    let chunk_count = if size == 0 {
        1
    } else {
        (size + chunk_size - 1) / chunk_size
    };
    let mut encrypted_buffer = vec![0u8; 4 + chunk_count * 36 + size];

    #[cfg(feature = "fast-aes")]
    let (enc_elapsed, dec_elapsed, total_enc, total_dec) = {
        let unbound = UnboundKey::new(&AES_256_GCM, &key).unwrap();
        let key = LessSafeKey::new(unbound);
        let mut iv = [0u8; 12];
        let mut aad = [0u8; 4];
        let mut work_enc = Vec::with_capacity(chunk_size + 16);
        let mut work_dec = Vec::with_capacity(chunk_size + 16);
        let mut decrypted_buffer = vec![0u8; size];

        let start_enc = Instant::now();
        let mut total_enc = 0usize;
        for _ in 0..iterations {
            encrypted_buffer[..4].copy_from_slice(&(chunk_count as u32).to_be_bytes());
            let mut offset = 4;
            for i in 0..chunk_count {
                let start = i * chunk_size;
                let end = (start + chunk_size).min(size);
                let chunk = &plaintext[start..end];

                aad.copy_from_slice(&(i as u32).to_be_bytes());
                OsRng.fill_bytes(&mut iv);

                work_enc.clear();
                work_enc.extend_from_slice(chunk);
                let nonce = Nonce::assume_unique_for_key(iv);
                key.seal_in_place_append_tag(nonce, Aad::from(&aad), &mut work_enc)
                    .unwrap();

                encrypted_buffer[offset..offset + 4].copy_from_slice(&(i as u32).to_be_bytes());
                offset += 4;
                let enc_len = 12 + work_enc.len();
                encrypted_buffer[offset..offset + 4]
                    .copy_from_slice(&(enc_len as u32).to_be_bytes());
                offset += 4;
                encrypted_buffer[offset..offset + 12].copy_from_slice(&iv);
                offset += 12;
                encrypted_buffer[offset..offset + work_enc.len()].copy_from_slice(&work_enc);
                offset += work_enc.len();
            }
            total_enc += offset;
        }
        let enc_elapsed = start_enc.elapsed();

        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            let mut offset = 4;
            let mut out_offset = 0;
            for _ in 0..chunk_count {
                let chunk_index = u32::from_be_bytes([
                    encrypted_buffer[offset],
                    encrypted_buffer[offset + 1],
                    encrypted_buffer[offset + 2],
                    encrypted_buffer[offset + 3],
                ]);
                let chunk_len = u32::from_be_bytes([
                    encrypted_buffer[offset + 4],
                    encrypted_buffer[offset + 5],
                    encrypted_buffer[offset + 6],
                    encrypted_buffer[offset + 7],
                ]) as usize;
                offset += 8;

                let mut iv_bytes = [0u8; 12];
                iv_bytes.copy_from_slice(&encrypted_buffer[offset..offset + 12]);
                let ciphertext_offset = offset + 12;
                let ct_tag_len = chunk_len - 12;
                let ct_tag = &encrypted_buffer[ciphertext_offset..ciphertext_offset + ct_tag_len];

                aad.copy_from_slice(&chunk_index.to_be_bytes());

                work_dec.clear();
                work_dec.extend_from_slice(ct_tag);

                let nonce = Nonce::assume_unique_for_key(iv_bytes);
                let decrypted = key
                    .open_in_place(nonce, Aad::from(&aad), &mut work_dec)
                    .unwrap();
                decrypted_buffer[out_offset..out_offset + decrypted.len()]
                    .copy_from_slice(decrypted);
                out_offset += decrypted.len();
                offset += chunk_len;
            }
            total_dec += decrypted_buffer.len();
        }
        let dec_elapsed = start_dec.elapsed();
        (enc_elapsed, dec_elapsed, total_enc, total_dec)
    };

    #[cfg(not(feature = "fast-aes"))]
    let (enc_elapsed, dec_elapsed, total_enc, total_dec) = {
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut iv = [0u8; 12];
        let mut aad = [0u8; 4];
        let mut work_enc = vec![0u8; chunk_size];
        let mut work_dec = vec![0u8; chunk_size];
        let mut decrypted_buffer = vec![0u8; size];

        let start_enc = Instant::now();
        let mut total_enc = 0usize;
        for _ in 0..iterations {
            encrypted_buffer[..4].copy_from_slice(&(chunk_count as u32).to_be_bytes());
            let mut offset = 4;
            for i in 0..chunk_count {
                let start = i * chunk_size;
                let end = (start + chunk_size).min(size);
                let chunk = &plaintext[start..end];
                let chunk_len = end - start;

                aad.copy_from_slice(&(i as u32).to_be_bytes());
                OsRng.fill_bytes(&mut iv);

                work_enc[..chunk_len].copy_from_slice(chunk);
                let nonce = Nonce::from_slice(&iv);
                let tag = cipher
                    .encrypt_in_place_detached(nonce, &aad, &mut work_enc[..chunk_len])
                    .unwrap();

                encrypted_buffer[offset..offset + 4].copy_from_slice(&(i as u32).to_be_bytes());
                offset += 4;
                let enc_len = 12 + chunk_len + 16;
                encrypted_buffer[offset..offset + 4]
                    .copy_from_slice(&(enc_len as u32).to_be_bytes());
                offset += 4;
                encrypted_buffer[offset..offset + 12].copy_from_slice(&iv);
                offset += 12;
                encrypted_buffer[offset..offset + chunk_len]
                    .copy_from_slice(&work_enc[..chunk_len]);
                offset += chunk_len;
                encrypted_buffer[offset..offset + 16].copy_from_slice(&tag);
                offset += 16;
            }
            total_enc += offset;
        }
        let enc_elapsed = start_enc.elapsed();

        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            let mut offset = 4;
            let mut out_offset = 0;
            for _ in 0..chunk_count {
                let chunk_index = u32::from_be_bytes([
                    encrypted_buffer[offset],
                    encrypted_buffer[offset + 1],
                    encrypted_buffer[offset + 2],
                    encrypted_buffer[offset + 3],
                ]);
                let chunk_len = u32::from_be_bytes([
                    encrypted_buffer[offset + 4],
                    encrypted_buffer[offset + 5],
                    encrypted_buffer[offset + 6],
                    encrypted_buffer[offset + 7],
                ]) as usize;
                offset += 8;

                let iv_bytes = &encrypted_buffer[offset..offset + 12];
                let ciphertext_offset = offset + 12;
                let real_chunk_len = chunk_len - 28;
                let ct = &encrypted_buffer[ciphertext_offset..ciphertext_offset + real_chunk_len];
                let tag_bytes = &encrypted_buffer
                    [ciphertext_offset + real_chunk_len..ciphertext_offset + real_chunk_len + 16];

                aad.copy_from_slice(&chunk_index.to_be_bytes());

                work_dec[..real_chunk_len].copy_from_slice(ct);
                let nonce = Nonce::from_slice(iv_bytes);
                cipher
                    .decrypt_in_place_detached(
                        nonce,
                        &aad,
                        &mut work_dec[..real_chunk_len],
                        tag_bytes.into(),
                    )
                    .unwrap();
                decrypted_buffer[out_offset..out_offset + real_chunk_len]
                    .copy_from_slice(&work_dec[..real_chunk_len]);
                out_offset += real_chunk_len;
                offset += chunk_len;
            }
            total_dec += decrypted_buffer.len();
        }
        let dec_elapsed = start_dec.elapsed();
        (enc_elapsed, dec_elapsed, total_enc, total_dec)
    };

    println!(
        "AES-GCM-CHUNKED size={} bytes chunk={} bytes enc={} MB/s dec={} MB/s",
        size,
        chunk_size,
        mb_per_sec(total_enc, enc_elapsed),
        mb_per_sec(total_dec, dec_elapsed)
    );
}

fn bench_kdf(iterations: usize) {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let salt = [0x11u8; 16];
    let info = [0x22u8; 16];
    let pw = b"perf-password";

    let start_hkdf = Instant::now();
    for _ in 0..iterations {
        let _ = derive_hkdf(&ikm, Some(&salt), Some(&info), 32).unwrap();
    }
    let hkdf_elapsed = start_hkdf.elapsed();
    let hkdf_ops = iterations as f64 / hkdf_elapsed.as_secs_f64();

    let start_pbkdf2 = Instant::now();
    for _ in 0..iterations {
        let _ = derive_pbkdf2(pw, &salt, 600_000, 32);
    }
    let pbkdf2_elapsed = start_pbkdf2.elapsed();
    let pbkdf2_ops = iterations as f64 / pbkdf2_elapsed.as_secs_f64();

    println!("HKDF ops/s={}", hkdf_ops);
    println!("PBKDF2(600k) ops/s={}", pbkdf2_ops);
}

fn bench_ml_kem(iterations: usize) {
    let (dk, ek) = ml_kem_keygen();

    let start_enc = Instant::now();
    let mut ct = Vec::new();
    let mut shared = Vec::new();
    for _ in 0..iterations {
        let (c, s) = ml_kem_encapsulate(&ek).unwrap();
        ct = c;
        shared = s;
    }
    let enc_elapsed = start_enc.elapsed();
    let enc_ops = iterations as f64 / enc_elapsed.as_secs_f64();

    let start_dec = Instant::now();
    let mut ok = 0usize;
    for _ in 0..iterations {
        let s = ml_kem_decapsulate(&dk, &ct).unwrap();
        if s == shared {
            ok += 1;
        }
    }
    let dec_elapsed = start_dec.elapsed();
    let dec_ops = iterations as f64 / dec_elapsed.as_secs_f64();

    println!("ML-KEM encaps ops/s={}", enc_ops);
    println!("ML-KEM decaps ops/s={}", dec_ops);
    println!("ML-KEM match={}/{}", ok, iterations);
}

fn bench_sealed_sender(iterations: usize) {
    let (bob_sk_vec, bob_pk_vec) = generate_x25519_keypair();
    let bob_pk: [u8; 32] = bob_pk_vec.try_into().unwrap();
    let bob_sk: [u8; 32] = bob_sk_vec.try_into().unwrap();
    let sender_id = b"alice@example.com";
    let content = b"Secret message content";

    let start_seal = Instant::now();
    let mut last_packet = Vec::new();
    for _ in 0..iterations {
        let sealed = seal(&bob_pk, sender_id, content).unwrap();
        last_packet = sealed;
    }
    let seal_elapsed = start_seal.elapsed();
    let seal_ops = iterations as f64 / seal_elapsed.as_secs_f64();

    let start_unseal = Instant::now();
    for _ in 0..iterations {
        let _ = unseal(&last_packet, &bob_sk).unwrap();
    }
    let unseal_elapsed = start_unseal.elapsed();
    let unseal_ops = iterations as f64 / unseal_elapsed.as_secs_f64();

    println!("Sealed Sender seal ops/s={:.2}", seal_ops);
    println!("Sealed Sender unseal ops/s={:.2}", unseal_ops);
}

fn bench_pcs_ratchet(iterations: usize) {
    let current_srk = [0x55u8; 32];
    let chat_id = b"perf-chat-id";
    let alice_kp = generate_ratchet_keypair().unwrap();
    let bob_kp = generate_ratchet_keypair().unwrap();

    let start_keygen = Instant::now();
    for _ in 0..iterations {
        let _ = generate_ratchet_keypair().unwrap();
    }
    let keygen_elapsed = start_keygen.elapsed();
    let keygen_ops = iterations as f64 / keygen_elapsed.as_secs_f64();

    let start_ratchet = Instant::now();
    for i in 0..iterations {
        let _ = ratchet_srk_sender(
            &current_srk,
            &alice_kp.secret_key(),
            &bob_kp.public_key,
            chat_id,
            i as u64,
        )
        .unwrap();
    }
    let ratchet_elapsed = start_ratchet.elapsed();
    let ratchet_ops = iterations as f64 / ratchet_elapsed.as_secs_f64();

    println!("PCS Ratchet keygen ops/s={:.2}", keygen_ops);
    println!("PCS Ratchet step computation ops/s={:.2}", ratchet_ops);
}

fn bench_key_verification(iterations: usize) {
    let key_a = [0x11u8; 32];
    let key_b = [0x22u8; 32];
    let conversation_id = b"perf-conversation-id-12345";

    let start_ver = Instant::now();
    for _ in 0..iterations {
        let _ = vollcrypt_core::verification::generate_verification_code(
            &key_a,
            &key_b,
            conversation_id,
        );
    }
    let ver_elapsed = start_ver.elapsed();
    let ver_ops = iterations as f64 / ver_elapsed.as_secs_f64();

    println!("Key Verification Code generation ops/s={:.2}", ver_ops);
}

fn bench_key_transparency_log(iterations: usize) {
    use vollcrypt_core::key_log::{GENESIS_HASH, KeyAction, KeyLog, create_entry};

    let mut log = KeyLog::new();
    let mut prev_hash = GENESIS_HASH;
    let kp = generate_ed25519_keypair();
    let mut signing_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    signing_key.copy_from_slice(&kp.0);
    public_key.copy_from_slice(&kp.1);

    for i in 0..100 {
        let entry = create_entry(
            b"alice",
            &public_key,
            1000 + i,
            &prev_hash,
            if i == 0 {
                KeyAction::Add
            } else {
                KeyAction::Update
            },
            &signing_key,
        )
        .unwrap();
        prev_hash = entry.compute_hash();
        log.append(entry).unwrap();
    }

    let start_verify = Instant::now();
    for _ in 0..iterations {
        let _ = log.verify_chain().unwrap();
    }
    let verify_elapsed = start_verify.elapsed();
    let verify_ops = iterations as f64 / verify_elapsed.as_secs_f64();

    println!(
        "Key Transparency Log verify chain (100 entries) ops/s={:.2}",
        verify_ops
    );
}

fn bench_ed25519(iterations: usize) {
    let kp = generate_ed25519_keypair();
    let mut signing_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    signing_key.copy_from_slice(&kp.0);
    public_key.copy_from_slice(&kp.1);

    let mut payload_1kb = vec![0u8; 1024];
    OsRng.fill_bytes(&mut payload_1kb);

    let mut payload_1mb = vec![0u8; 1024 * 1024];
    OsRng.fill_bytes(&mut payload_1mb);

    let start_sign_1kb = Instant::now();
    let mut last_sig_1kb = Vec::new();
    for _ in 0..iterations {
        let sig = sign_message(&signing_key, &payload_1kb).unwrap();
        last_sig_1kb = sig;
    }
    let sign_1kb_elapsed = start_sign_1kb.elapsed();
    let sign_1kb_ops = iterations as f64 / sign_1kb_elapsed.as_secs_f64();

    let start_verify_1kb = Instant::now();
    for _ in 0..iterations {
        let _ = verify_signature(&public_key, &payload_1kb, &last_sig_1kb);
    }
    let verify_1kb_elapsed = start_verify_1kb.elapsed();
    let verify_1kb_ops = iterations as f64 / verify_1kb_elapsed.as_secs_f64();

    let iter_1mb = iterations / 10;
    let start_sign_1mb = Instant::now();
    let mut last_sig_1mb = Vec::new();
    for _ in 0..iter_1mb {
        let sig = sign_message(&signing_key, &payload_1mb).unwrap();
        last_sig_1mb = sig;
    }
    let sign_1mb_elapsed = start_sign_1mb.elapsed();
    let sign_1mb_ops = iter_1mb as f64 / sign_1mb_elapsed.as_secs_f64();

    let start_verify_1mb = Instant::now();
    for _ in 0..iter_1mb {
        let _ = verify_signature(&public_key, &payload_1mb, &last_sig_1mb);
    }
    let verify_1mb_elapsed = start_verify_1mb.elapsed();
    let verify_1mb_ops = iter_1mb as f64 / verify_1mb_elapsed.as_secs_f64();

    println!("Ed25519 Sign (1KB) ops/s={:.2}", sign_1kb_ops);
    println!("Ed25519 Verify (1KB) ops/s={:.2}", verify_1kb_ops);
    println!("Ed25519 Sign (1MB) ops/s={:.2}", sign_1mb_ops);
    println!("Ed25519 Verify (1MB) ops/s={:.2}", verify_1mb_ops);
}

fn bench_bip39(iterations: usize) {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = mnemonic_to_seed(mnemonic, Some("perf-passphrase")).unwrap();
    }
    let elapsed = start.elapsed();
    let ops = iterations as f64 / elapsed.as_secs_f64();

    println!("BIP-39 Mnemonic to Seed ops/s={:.2}", ops);
}

fn bench_multithreaded_handshake(iterations_per_thread: usize) {
    use std::sync::Arc;

    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    println!(
        "Multi-threaded scaling benchmark using {} threads...",
        num_threads
    );

    let (bob_sk_vec, bob_pk_vec) = generate_x25519_keypair();
    let bob_pk: [u8; 32] = bob_pk_vec.try_into().unwrap();
    let bob_sk: [u8; 32] = bob_sk_vec.try_into().unwrap();
    let sender_id = b"alice@example.com";
    let content = b"Secret message content";
    let sealed_packet = seal(&bob_pk, sender_id, content).unwrap();

    let (_dk, ek) = ml_kem_keygen();

    let shared_sealed = Arc::new(sealed_packet);
    let shared_ek = Arc::new(ek);
    let bob_sk_arc = Arc::new(bob_sk);

    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..num_threads {
        let sealed_clone = Arc::clone(&shared_sealed);
        let ek_clone = Arc::clone(&shared_ek);
        let sk_clone = Arc::clone(&bob_sk_arc);

        handles.push(std::thread::spawn(move || {
            let mut ok = 0usize;
            for _ in 0..iterations_per_thread {
                let (_ct, _ss) = ml_kem_encapsulate(&ek_clone).unwrap();
                let _unsealed = unseal(&sealed_clone, &sk_clone).unwrap();
                ok += 1;
            }
            ok
        }));
    }

    let mut total_ops = 0;
    for h in handles {
        total_ops += h.join().unwrap();
    }
    let elapsed = start.elapsed();
    let total_crypto_ops = total_ops * 2;
    let ops_per_sec = total_crypto_ops as f64 / elapsed.as_secs_f64();

    println!(
        "Multi-threaded Handshake Scaling ({} threads) aggregate ops/s={:.2}",
        num_threads, ops_per_sec
    );
}

struct ReplayPreventionStore {
    seen_hashes: std::collections::HashSet<[u8; 32]>,
}

impl ReplayPreventionStore {
    fn new() -> Self {
        Self {
            seen_hashes: std::collections::HashSet::new(),
        }
    }

    fn has_seen(&self, hash: &[u8; 32]) -> bool {
        self.seen_hashes.contains(hash)
    }

    fn insert(&mut self, hash: [u8; 32]) -> bool {
        self.seen_hashes.insert(hash)
    }
}

fn bench_replay_prevention_store(iterations: usize) {
    let mut store = ReplayPreventionStore::new();
    let mut existing_hashes = Vec::with_capacity(100_000);

    for _ in 0..100_000 {
        let mut h = [0u8; 32];
        OsRng.fill_bytes(&mut h);
        store.insert(h);
        existing_hashes.push(h);
    }

    let start_lookup_hit = Instant::now();
    for i in 0..iterations {
        let idx = i % existing_hashes.len();
        let _ = store.has_seen(&existing_hashes[idx]);
    }
    let lookup_hit_elapsed = start_lookup_hit.elapsed();
    let lookup_hit_ns = lookup_hit_elapsed.as_nanos() as f64 / iterations as f64;

    let mut non_existing = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut h = [0u8; 32];
        OsRng.fill_bytes(&mut h);
        while store.has_seen(&h) {
            OsRng.fill_bytes(&mut h);
        }
        non_existing.push(h);
    }

    let start_lookup_miss = Instant::now();
    for i in 0..iterations {
        let _ = store.has_seen(&non_existing[i]);
    }
    let lookup_miss_elapsed = start_lookup_miss.elapsed();
    let lookup_miss_ns = lookup_miss_elapsed.as_nanos() as f64 / iterations as f64;

    let mut to_insert = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut h = [0u8; 32];
        OsRng.fill_bytes(&mut h);
        while store.has_seen(&h) {
            OsRng.fill_bytes(&mut h);
        }
        to_insert.push(h);
    }

    let start_insert = Instant::now();
    for i in 0..iterations {
        let _ = store.insert(to_insert[i]);
    }
    let insert_elapsed = start_insert.elapsed();
    let insert_ns = insert_elapsed.as_nanos() as f64 / iterations as f64;

    println!(
        "Replay Store Lookup (Hit) avg_latency={:.2} ns",
        lookup_hit_ns
    );
    println!(
        "Replay Store Lookup (Miss) avg_latency={:.2} ns",
        lookup_miss_ns
    );
    println!("Replay Store Insertion avg_latency={:.2} ns", insert_ns);
}

fn main() {
    println!("Vollcrypt perf");
    print_cpu_features();
    print_backend();
    bench_aesgcm_raw(64 * 1024, 2000);
    bench_aesgcm_raw(1024 * 1024, 400);
    bench_aesgcm_raw(16 * 1024 * 1024, 20);
    bench_encrypt_decrypt(1024, 2000);
    bench_encrypt_decrypt(64 * 1024, 400);
    bench_encrypt_decrypt(1024 * 1024, 80);
    bench_encrypt_decrypt(16 * 1024 * 1024, 5);

    bench_chunked(16 * 1024 * 1024, 5, 1024 * 1024);
    bench_chunked(64 * 1024 * 1024, 2, 1024 * 1024);

    bench_kdf(50);
    bench_ml_kem(200);
    bench_sealed_sender(500);
    bench_pcs_ratchet(500);
    bench_key_verification(1000);
    bench_key_transparency_log(100);

    bench_ed25519(500);
    bench_bip39(200);
    bench_multithreaded_handshake(200);
    bench_replay_prevention_store(5000);
}

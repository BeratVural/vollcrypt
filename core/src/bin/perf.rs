use std::time::{Duration, Instant};
use rand::{RngCore, rngs::OsRng};
#[cfg(not(feature = "fast-aes"))]
use aes_gcm::{Aes256Gcm, Nonce, aead::{AeadInPlace, KeyInit}};
#[cfg(feature = "fast-aes")]
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use vollcrypt_core::{
    encrypt_aes256gcm, decrypt_aes256gcm,
    encrypt_aes256gcm_chunked, decrypt_aes256gcm_chunked,
    derive_pbkdf2, derive_hkdf,
    ml_kem_keygen, ml_kem_encapsulate, ml_kem_decapsulate,
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
        let start_enc = Instant::now();
        let mut total_enc = 0usize;
        for i in 0..iterations {
            let mut in_out = base.clone();
            let nonce = Nonce::assume_unique_for_key(nonces[i]);
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).unwrap();
            total_enc += size;
        }
        let enc_elapsed = start_enc.elapsed();

        let mut ciphertext = base.clone();
        let nonce0 = Nonce::assume_unique_for_key(nonces[0]);
        key.seal_in_place_append_tag(nonce0, Aad::empty(), &mut ciphertext).unwrap();

        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            let mut in_out = ciphertext.clone();
            let nonce = Nonce::assume_unique_for_key(nonces[0]);
            let _ = key.open_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
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
            let _ = cipher.encrypt_in_place_detached(nonce, b"", &mut work).unwrap();
            total_enc += size;
        }
        let enc_elapsed = start_enc.elapsed();

        work.copy_from_slice(&base);
        let nonce0 = Nonce::from_slice(&nonces[0]);
        let tag0 = cipher.encrypt_in_place_detached(nonce0, b"", &mut work).unwrap();
        let ciphertext = work.clone();

        let mut work_dec = vec![0u8; size];
        let start_dec = Instant::now();
        let mut total_dec = 0usize;
        for _ in 0..iterations {
            work_dec.copy_from_slice(&ciphertext);
            let _ = cipher.decrypt_in_place_detached(nonce0, b"", &mut work_dec, &tag0).unwrap();
            total_dec += size;
        }
        let dec_elapsed = start_dec.elapsed();
        (enc_elapsed, dec_elapsed, total_enc, total_dec)
    };

    println!(
        "AES-GCM-RAW size={} bytes enc={} MB/s dec={} MB/s",
        size, mb_per_sec(total_enc, enc_elapsed), mb_per_sec(total_dec, dec_elapsed)
    );
}

fn bench_encrypt_decrypt(size: usize, iterations: usize) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut plaintext = vec![0u8; size];
    OsRng.fill_bytes(&mut plaintext);

    let start_enc = Instant::now();
    let mut total_enc = 0usize;
    for _ in 0..iterations {
        let ct = encrypt_aes256gcm(&key, &plaintext, None).unwrap();
        total_enc += ct.len();
    }
    let enc_elapsed = start_enc.elapsed();

    let ct = encrypt_aes256gcm(&key, &plaintext, None).unwrap();
    let start_dec = Instant::now();
    let mut total_dec = 0usize;
    for _ in 0..iterations {
        let pt = decrypt_aes256gcm(&key, &ct, None).unwrap();
        total_dec += pt.len();
    }
    let dec_elapsed = start_dec.elapsed();

    println!("AES-GCM size={} bytes enc={} MB/s dec={} MB/s", size, mb_per_sec(total_enc, enc_elapsed), mb_per_sec(total_dec, dec_elapsed));
}

fn bench_chunked(size: usize, iterations: usize, chunk_size: usize) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut plaintext = vec![0u8; size];
    OsRng.fill_bytes(&mut plaintext);

    let start_enc = Instant::now();
    let mut total_enc = 0usize;
    for _ in 0..iterations {
        let ct = encrypt_aes256gcm_chunked(&key, &plaintext, None, chunk_size).unwrap();
        total_enc += ct.len();
    }
    let enc_elapsed = start_enc.elapsed();

    let ct = encrypt_aes256gcm_chunked(&key, &plaintext, None, chunk_size).unwrap();
    let start_dec = Instant::now();
    let mut total_dec = 0usize;
    for _ in 0..iterations {
        let pt = decrypt_aes256gcm_chunked(&key, &ct, None).unwrap();
        total_dec += pt.len();
    }
    let dec_elapsed = start_dec.elapsed();

    println!(
        "AES-GCM-CHUNKED size={} bytes chunk={} bytes enc={} MB/s dec={} MB/s",
        size, chunk_size, mb_per_sec(total_enc, enc_elapsed), mb_per_sec(total_dec, dec_elapsed)
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
        let _ = derive_pbkdf2(pw, &salt, 100_000, 32);
    }
    let pbkdf2_elapsed = start_pbkdf2.elapsed();
    let pbkdf2_ops = iterations as f64 / pbkdf2_elapsed.as_secs_f64();

    println!("HKDF ops/s={}", hkdf_ops);
    println!("PBKDF2(100k) ops/s={}", pbkdf2_ops);
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
}

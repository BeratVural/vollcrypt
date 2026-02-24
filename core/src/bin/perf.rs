use std::time::{Duration, Instant};
use rand::{RngCore, rngs::OsRng};
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
    bench_encrypt_decrypt(1024, 2000);
    bench_encrypt_decrypt(64 * 1024, 400);
    bench_encrypt_decrypt(1024 * 1024, 80);
    bench_encrypt_decrypt(16 * 1024 * 1024, 5);

    bench_chunked(16 * 1024 * 1024, 5, 1024 * 1024);
    bench_chunked(64 * 1024 * 1024, 2, 1024 * 1024);

    bench_kdf(50);
    bench_ml_kem(200);
}

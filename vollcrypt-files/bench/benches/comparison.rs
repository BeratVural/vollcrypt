use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use vollcrypt_files_core::*;

fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn bench_raw_vs_vollcrypt(c: &mut Criterion) {
    let size = 1024 * 1024; // 1 MB
    let plaintext = vec![0u8; size];
    let dek = [0u8; 32];
    let file_id = [0u8; 16];

    let mut g = c.benchmark_group("comparison_vs_raw");
    g.throughput(Throughput::Bytes(size as u64));

    // Raw AES-256-GCM
    g.bench_function("raw_aes_gcm", |b| {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&dek);
        let cipher = Aes256Gcm::new(key);
        let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
        b.iter(|| {
            let res = cipher.encrypt(nonce, black_box(plaintext.as_slice())).unwrap();
            let _ = black_box(res);
        });
    });

    // Vollcrypt Encrypt Chunk (which includes key derivation, subkey zeroization, AAD framing)
    g.bench_function("vollcrypt_encrypt_chunk", |b| {
        b.iter(|| {
            let res = encrypt_chunk(&dek, &file_id, 0, black_box(&plaintext)).unwrap();
            let _ = black_box(res);
        });
    });

    g.finish();
}

fn check_compression_entropy(c: &mut Criterion) {
    let size = 100_000;
    let plaintext = vec![0u8; size]; // zero input to verify high output entropy
    let dek = [0u8; 32];
    let file_id = [0u8; 16];

    let env = encrypt_chunk(&dek, &file_id, 0, &plaintext).unwrap();
    let ciphertext = env.write();
    let entropy = calculate_shannon_entropy(&ciphertext);

    let mut g = c.benchmark_group("entropy_validation");
    g.bench_function("entropy_check", |b| {
        b.iter(|| {
            let ent = calculate_shannon_entropy(black_box(&ciphertext));
            let _ = black_box(ent);
        });
    });
    g.finish();

    // Log the actual entropy so the user report compiles it
    println!("VERIFICATION: Shannon Entropy of 100KB ciphertext: {:.6} bits/byte (ideal: 8.000000, ratio: {:.2}%)", 
             entropy, (entropy / 8.0) * 100.0);
}

criterion_group!(
    benches,
    bench_raw_vs_vollcrypt,
    check_compression_entropy
);
criterion_main!(benches);

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vollcrypt_files_core::*;

fn bench_chunk_encrypt_decrypt(c: &mut Criterion) {
    let dek = [0u8; 32];
    let file_id = [0u8; 16];
    let chunk_index = 0u32;

    let sizes = [4 * 1024, 64 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024];

    // Chunk Encrypt
    let mut g_enc = c.benchmark_group("chunk_encrypt");
    for &size in &sizes {
        let plaintext = vec![0u8; size];
        g_enc.throughput(Throughput::Bytes(size as u64));
        g_enc.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let res = encrypt_chunk(&dek, &file_id, chunk_index, black_box(&plaintext));
                let _ = black_box(res);
            });
        });
    }
    g_enc.finish();

    // Chunk Decrypt
    let mut g_dec = c.benchmark_group("chunk_decrypt");
    for &size in &sizes {
        let plaintext = vec![0u8; size];
        let env = encrypt_chunk(&dek, &file_id, chunk_index, &plaintext).unwrap();
        g_dec.throughput(Throughput::Bytes(size as u64));
        g_dec.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let res = decrypt_chunk(&dek, &file_id, chunk_index, black_box(&env));
                let _ = black_box(res);
            });
        });
    }
    g_dec.finish();
}

fn bench_merkle(c: &mut Criterion) {
    let leaf_counts = [16, 256, 4096, 65536];

    let mut g_merkle = c.benchmark_group("merkle_root_construction");
    for &count in &leaf_counts {
        let leaves = vec![[0u8; 32]; count];
        g_merkle.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                let tree = MerkleTree::from_leaves(black_box(leaves.clone()));
                let r = tree.root();
                let _ = black_box(r);
            });
        });
    }
    g_merkle.finish();

    // Merkle Proof
    let leaves_proof = vec![[0u8; 32]; 65536];
    let tree = MerkleTree::from_leaves(leaves_proof);
    let root = tree.root();
    let index = 12345;
    let proof = tree.proof(index);

    let mut g_proof = c.benchmark_group("merkle_proof");
    g_proof.bench_function("generate", |b| {
        b.iter(|| {
            let p = tree.proof(black_box(index));
            let _ = black_box(p);
        });
    });
    g_proof.bench_function("verify", |b| {
        b.iter(|| {
            let res = verify_merkle_proof(
                black_box(&[0u8; 32]),
                black_box(index),
                black_box(65536),
                black_box(&proof),
                black_box(&root),
            );
            let _ = black_box(res);
        });
    });
    g_proof.finish();
}

fn bench_hkdf_subkey(c: &mut Criterion) {
    let dek = [0u8; 32];
    let file_id = [0u8; 16];
    c.bench_function("hkdf_derive_chunk_subkey", |b| {
        b.iter(|| {
            let res = derive_chunk_subkey(black_box(&dek), black_box(&file_id), black_box(42));
            let _ = black_box(res);
        });
    });
}

fn bench_aes_kw(c: &mut Criterion) {
    let kek = [0u8; 32];
    let dek = [0u8; 32];
    let wrapped = aes256_kw_wrap(&kek, &dek);

    let mut g = c.benchmark_group("aes_kw_wrap_unwrap");
    g.bench_function("wrap", |b| {
        b.iter(|| {
            let res = aes256_kw_wrap(black_box(&kek), black_box(&dek));
            let _ = black_box(res);
        });
    });
    g.bench_function("unwrap", |b| {
        b.iter(|| {
            let res = aes256_kw_unwrap(black_box(&kek), black_box(&wrapped));
            let _ = black_box(res);
        });
    });
    g.finish();
}

fn bench_ed25519(c: &mut Criterion) {
    let (pk, sk) = ed25519_keypair_generate();
    let msg = vec![0u8; 1024];
    let sig = ed25519_sign(&sk, &msg);

    let mut g = c.benchmark_group("ed25519_sign_verify");
    g.bench_function("sign", |b| {
        b.iter(|| {
            let res = ed25519_sign(black_box(&sk), black_box(&msg));
            let _ = black_box(res);
        });
    });
    g.bench_function("verify", |b| {
        b.iter(|| {
            let res = ed25519_verify(black_box(&pk), black_box(&msg), black_box(&sig));
            let _ = black_box(res);
        });
    });
    g.finish();
}

fn bench_header_ops(c: &mut Criterion) {
    // 1 wrap entry
    let header_1 = Header {
        version: 1,
        mode: Mode::Password,
        cipher_id: CipherId::Aes256Gcm,
        file_id: [0u8; 16],
        chunk_size: 1024 * 1024,
        plaintext_size: 1234567,
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
    let serialized_1 = header_1.write();

    // 100 wrap entries
    let header_100 = Header {
        version: 1,
        mode: Mode::Recipient,
        cipher_id: CipherId::Aes256Gcm,
        file_id: [0u8; 16],
        chunk_size: 1024 * 1024,
        plaintext_size: 1234567,
        merkle_root: [0u8; 32],
        hash_algorithm: HashAlgorithm::Sha256,
        wraps: vec![
            WrapEntry::PasswordPbkdf2 {
                iterations: 1000,
                salt: [0u8; 16],
                wrapped_dek: [0u8; 40],
            };
            100
        ],
        signed_metadata: None,
        signature: None,
    };
    let serialized_100 = header_100.write();

    let mut g = c.benchmark_group("header_parse_write");
    g.bench_function("write_1_wrap", |b| {
        b.iter(|| {
            let res = black_box(&header_1).write();
            let _ = black_box(res);
        });
    });
    g.bench_function("parse_1_wrap", |b| {
        b.iter(|| {
            let res = Header::parse(black_box(&serialized_1));
            let _ = black_box(res);
        });
    });
    g.bench_function("write_100_wrap", |b| {
        b.iter(|| {
            let res = black_box(&header_100).write();
            let _ = black_box(res);
        });
    });
    g.bench_function("parse_100_wrap", |b| {
        b.iter(|| {
            let res = Header::parse(black_box(&serialized_100));
            let _ = black_box(res);
        });
    });
    g.finish();
}

fn bench_chunk_envelope(c: &mut Criterion) {
    let env = ChunkEnvelope {
        chunk_index: 0,
        iv: [0u8; 12],
        ciphertext: vec![0u8; 1024 * 1024],
        tag: [0u8; 16],
    };
    let serialized = env.write();

    let mut g = c.benchmark_group("chunk_envelope_parse_write");
    g.bench_function("write_1_mb", |b| {
        b.iter(|| {
            let res = black_box(&env).write();
            let _ = black_box(res);
        });
    });
    g.bench_function("parse_1_mb", |b| {
        b.iter(|| {
            let res = ChunkEnvelope::parse(black_box(&serialized), black_box(1024 * 1024));
            let _ = black_box(res);
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_chunk_encrypt_decrypt,
    bench_merkle,
    bench_hkdf_subkey,
    bench_aes_kw,
    bench_ed25519,
    bench_header_ops,
    bench_chunk_envelope
);
criterion_main!(benches);

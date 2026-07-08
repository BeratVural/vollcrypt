use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vollcrypt_files_core::pqc::*;
use vollcrypt_files_core::recipient::*;

fn bench_hybrid_kem_breakdown(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_kem_operations");

    // 1. Key Generation
    g.bench_function("generate_recipient_keypair", |b| {
        b.iter(|| {
            let res = generate_recipient_keypair();
            let _ = black_box(res);
        });
    });

    // 2. Classical ECDH alone
    let (_x_pk1, x_sk1) = x25519_keypair_generate();
    let (x_pk2, _x_sk2) = x25519_keypair_generate();
    g.bench_function("x25519_dh_only", |b| {
        b.iter(|| {
            let ss = x25519_diffie_hellman(black_box(&x_sk1), black_box(&x_pk2)).unwrap();
            let _ = black_box(ss);
        });
    });

    // 3. Post-Quantum Encapsulate alone
    let (m_pk, m_sk) = mlkem768_keypair_generate();
    g.bench_function("mlkem768_encapsulate_only", |b| {
        b.iter(|| {
            let res = mlkem768_encapsulate(black_box(&m_pk)).unwrap();
            let _ = black_box(res);
        });
    });

    // 4. Post-Quantum Decapsulate alone
    let (_, ct) = mlkem768_encapsulate(&m_pk).unwrap();
    g.bench_function("mlkem768_decapsulate_only", |b| {
        b.iter(|| {
            let res = mlkem768_decapsulate(black_box(&m_sk), black_box(&ct)).unwrap();
            let _ = black_box(res);
        });
    });

    // 5. Full wrap_key_to_recipient
    let (pk, sk) = generate_recipient_keypair();
    let key = [0u8; 32];
    let recipient_id = [0u8; 16];
    g.bench_function("full_hybrid_wrap", |b| {
        b.iter(|| {
            let wrap = wrap_key_to_recipient(
                black_box(&key),
                black_box(recipient_id),
                black_box(1),
                black_box(&pk),
            );
            let _ = black_box(wrap);
        });
    });

    // 6. Full unwrap_key_with_recipient_key
    let wrap = wrap_key_to_recipient(&key, recipient_id, 1, &pk).unwrap();
    g.bench_function("full_hybrid_unwrap", |b| {
        b.iter(|| {
            let res = unwrap_key_with_recipient_key(black_box(&wrap), black_box(&sk));
            let _ = black_box(res);
        });
    });

    g.finish();
}

fn bench_pure_vs_hybrid(c: &mut Criterion) {
    // Pure X25519 wrap simulation vs Hybrid
    // In our library, wrap_key_to_recipient is hybrid. Let's compare pure classical ECDH keywrap
    // (ECDH -> HKDF -> AES-KW) against the hybrid wrap.
    let mut g = c.benchmark_group("pure_vs_hybrid");

    let (x_pk, _x_sk) = x25519_keypair_generate();
    let key = [0u8; 32];

    g.bench_function("pure_x25519_wrap_sim", |b| {
        b.iter(|| {
            let (_eph_pk, eph_sk) = x25519_keypair_generate();
            let ss = x25519_diffie_hellman(&eph_sk, &x_pk).unwrap();
            let mut info = [0u8; 48];
            info[0..28].copy_from_slice(b"vollcrypt-file-hybrid-kem-v1");
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &ss);
            let mut kek = [0u8; 32];
            let _ = hk.expand(&info, &mut kek);
            let wrapped_dek = vollcrypt_files_core::keywrap::aes256_kw_wrap(&kek, &key);
            let _ = black_box(wrapped_dek);
        });
    });

    let (pk, _) = generate_recipient_keypair();
    let recipient_id = [0u8; 16];
    g.bench_function("hybrid_kem_wrap", |b| {
        b.iter(|| {
            let wrap = wrap_key_to_recipient(&key, recipient_id, 1, &pk).unwrap();
            let _ = black_box(wrap);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_hybrid_kem_breakdown, bench_pure_vs_hybrid);
criterion_main!(benches);

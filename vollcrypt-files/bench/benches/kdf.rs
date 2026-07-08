use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use vollcrypt_files_core::*;

fn bench_pbkdf2(c: &mut Criterion) {
    let password = b"SuperSecureMasterPassword123!";
    let salt = [0u8; 16];

    // iterations: 10k, 100k, 600k (default is 600k for high security, but we keep runs fast using 10k, 100k, 300k, 600k)
    let pbkdf2_iterations = [10_000, 100_000, 300_000, 600_000];

    let mut g = c.benchmark_group("pbkdf2_latency");
    for &iters in &pbkdf2_iterations {
        g.bench_with_input(BenchmarkId::new("iterations", iters), &iters, |b, &i| {
            b.iter(|| {
                let res = derive_kek_pbkdf2(black_box(password), black_box(&salt), black_box(i)).unwrap();
                let _ = black_box(res);
            });
        });
    }
    g.finish();
}

fn bench_argon2id(c: &mut Criterion) {
    let password = b"SuperSecureMasterPassword123!";
    let salt = [0u8; 16];

    // Presets: (name, m_cost, t_cost, p_cost)
    // Interactive: m=19456 (19 MB), t=2, p=1
    // Default: m=65536 (64 MB), t=3, p=4
    // Sensitive: m=262144 (256 MB), t=5, p=8
    let presets = [
        ("interactive", 19456, 2, 1),
        ("default", 65536, 3, 4),
        ("sensitive", 262144, 5, 8),
    ];

    let mut g = c.benchmark_group("argon2id_presets");
    for &(name, m, t, p) in &presets {
        g.bench_function(name, |b| {
            b.iter(|| {
                let res = derive_kek_argon2id(
                    black_box(password),
                    black_box(&salt),
                    black_box(m),
                    black_box(t),
                    black_box(p),
                );
                let _ = black_box(res);
            });
        });
    }
    g.finish();
}

fn bench_argon2id_cores(c: &mut Criterion) {
    let password = b"SuperSecureMasterPassword123!";
    let salt = [0u8; 16];
    let m = 65536;
    let t = 3;
    let p_costs = [1, 2, 4, 8];

    let mut g = c.benchmark_group("argon2id_p_cost");
    for &p in &p_costs {
        g.bench_with_input(BenchmarkId::new("p_cost", p), &p, |b, &p_val| {
            b.iter(|| {
                let res = derive_kek_argon2id(
                    black_box(password),
                    black_box(&salt),
                    black_box(m),
                    black_box(t),
                    black_box(p_val),
                );
                let _ = black_box(res);
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_pbkdf2, bench_argon2id, bench_argon2id_cores);
criterion_main!(benches);

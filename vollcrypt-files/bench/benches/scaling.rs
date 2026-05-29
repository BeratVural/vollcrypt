use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use vollcrypt_files_core::*;

fn bench_multi_recipient_wrap(c: &mut Criterion) {
    let dek = [0u8; 32];

    // N recipients
    let recipient_counts = [1, 10, 100];

    let mut g = c.benchmark_group("multi_recipient_wrap");
    for &count in &recipient_counts {
        // Generate recipient public keys
        let recipients: Vec<(RecipientPublicKey, [u8; 16])> = (0..count)
            .map(|idx| {
                let (pk, _) = generate_recipient_keypair();
                let mut id = [0u8; 16];
                id[0..4].copy_from_slice(&(idx as u32).to_be_bytes());
                (pk, id)
            })
            .collect();

        g.bench_with_input(BenchmarkId::new("recipients", count), &count, |b, _| {
            b.iter(|| {
                let mut wraps = Vec::new();
                for (pk, id) in &recipients {
                    let wrap = wrap_key_to_recipient(
                        black_box(&dek),
                        black_box(*id),
                        black_box(1),
                        black_box(pk),
                    )
                    .unwrap();
                    wraps.push(wrap);
                }
                let _ = black_box(wraps);
            });
        });
    }
    g.finish();
}

fn bench_group_manifest_scaling(c: &mut Criterion) {
    let group_id = [0u8; 16];
    let founder_id = [1u8; 16];
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
    let (rec_pk, _) = generate_recipient_keypair();
    let gk_wrap = wrap_key_to_recipient(&[0u8; 32], founder_id, 1, &rec_pk).unwrap();

    let manifest_sizes = [1, 10, 100];
    let mut g = c.benchmark_group("group_manifest_ops");

    for &size in &manifest_sizes {
        let mut manifest = GroupManifest::genesis(
            group_id,
            founder_id,
            &admin_sk,
            admin_pk,
            rec_pk.clone(),
            gk_wrap.clone(),
        );

        for idx in 0..size {
            let mut mid = [0u8; 16];
            mid[0..4].copy_from_slice(&(idx as u32 + 2).to_be_bytes());
            manifest
                .add_member(&admin_sk, mid, admin_pk, rec_pk.clone(), gk_wrap.clone())
                .unwrap();
        }

        g.bench_with_input(BenchmarkId::new("manifest_size", size), &size, |b, _| {
            b.iter(|| {
                let active = black_box(&manifest).current_members();
                let _ = black_box(active);
            });
        });

        g.bench_with_input(BenchmarkId::new("manifest_verify", size), &size, |b, _| {
            b.iter(|| {
                let res = black_box(&manifest).verify();
                let _ = black_box(res);
            });
        });
    }
    g.finish();
}

fn bench_rotation_cost(c: &mut Criterion) {
    let group_id = [0u8; 16];
    let founder_id = [1u8; 16];
    let (admin_pk, admin_sk) = ed25519_keypair_generate();
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

    // Let's add 50 members to keep key rotation benchmark runtime under control
    for idx in 0..50 {
        let mut mid = [0u8; 16];
        mid[0..4].copy_from_slice(&(idx as u32 + 2).to_be_bytes());
        manifest
            .add_member(&admin_sk, mid, admin_pk, rec_pk.clone(), gk_wrap.clone())
            .unwrap();
    }

    let mut g = c.benchmark_group("key_rotation");
    g.bench_function("rotate_50_members", |b| {
        b.iter(|| {
            let mut manifest_clone = manifest.clone();
            let new_gk = [2u8; 32];
            let res = manifest_clone.rotate_group_key(
                black_box(&new_gk),
                black_box(&admin_pk),
                black_box(&admin_sk),
                black_box(123456789),
            );
            let _ = black_box(res);
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_multi_recipient_wrap,
    bench_group_manifest_scaling,
    bench_rotation_cost
);
criterion_main!(benches);

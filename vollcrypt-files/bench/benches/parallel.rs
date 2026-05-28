use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rayon::prelude::*;
use vollcrypt_files_core::*;

fn bench_parallel_encrypt_decrypt(c: &mut Criterion) {
    let dek = [0u8; 32];
    let file_id = [0u8; 16];
    let chunk_size = 4 * 1024 * 1024; // 4 MB chunk
    let num_chunks = 16;
    let total_size = chunk_size * num_chunks;

    let plaintexts: Vec<Vec<u8>> = (0..num_chunks).map(|_| vec![0u8; chunk_size]).collect();

    let mut g_enc = c.benchmark_group("parallel_chunk_encrypt");
    g_enc.throughput(Throughput::Bytes(total_size as u64));

    let physical_cpus = num_cpus::get_physical();
    let thread_counts = [1, 2, 4, physical_cpus];

    for &threads in &thread_counts {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
        g_enc.bench_with_input(BenchmarkId::new("workers", threads), &threads, |b, _| {
            b.iter(|| {
                pool.install(|| {
                    let res: Vec<_> = plaintexts
                        .par_iter()
                        .enumerate()
                        .map(|(idx, pt)| {
                            encrypt_chunk(&dek, &file_id, idx as u32, black_box(pt)).unwrap()
                        })
                        .collect();
                    let _ = black_box(res);
                });
            });
        });
    }
    g_enc.finish();

    // Parallel Decrypt
    let envelopes: Vec<_> = plaintexts
        .iter()
        .enumerate()
        .map(|(idx, pt)| encrypt_chunk(&dek, &file_id, idx as u32, pt).unwrap())
        .collect();

    let mut g_dec = c.benchmark_group("parallel_chunk_decrypt");
    g_dec.throughput(Throughput::Bytes(total_size as u64));

    for &threads in &thread_counts {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
        g_dec.bench_with_input(BenchmarkId::new("workers", threads), &threads, |b, _| {
            b.iter(|| {
                pool.install(|| {
                    let res: Vec<_> = envelopes
                        .par_iter()
                        .enumerate()
                        .map(|(idx, env)| {
                            decrypt_chunk(&dek, &file_id, idx as u32, black_box(env)).unwrap()
                        })
                        .collect();
                    let _ = black_box(res);
                });
            });
        });
    }
    g_dec.finish();
}

fn parallel_build_merkle(leaves: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut current_level = leaves.to_vec();
    while current_level.len() > 1 {
        current_level = current_level
            .par_chunks(2)
            .map(|chunk| {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&hasher.finalize());
                parent
            })
            .collect();
    }
    current_level.first().copied().unwrap_or([0u8; 32])
}

fn bench_parallel_merkle(c: &mut Criterion) {
    let count = 65536;
    let leaves = vec![[0u8; 32]; count];

    let mut g = c.benchmark_group("parallel_merkle");
    g.bench_function("sequential", |b| {
        b.iter(|| {
            let tree = MerkleTree::from_leaves(black_box(leaves.clone()));
            let r = tree.root();
            let _ = black_box(r);
        });
    });

    g.bench_function("parallel", |b| {
        b.iter(|| {
            let r = parallel_build_merkle(black_box(&leaves));
            let _ = black_box(r);
        });
    });
    g.finish();
}

fn bench_parallel_recipient_wrap(c: &mut Criterion) {
    let count = 100;
    let dek = [0u8; 32];
    
    let recipients: Vec<(RecipientPublicKey, [u8; 16])> = (0..count)
        .map(|idx| {
            let (pk, _) = generate_recipient_keypair();
            let mut id = [0u8; 16];
            id[0..4].copy_from_slice(&(idx as u32).to_be_bytes());
            (pk, id)
        })
        .collect();

    let mut g = c.benchmark_group("parallel_multi_recipient_wrap");
    g.bench_function("sequential", |b| {
        b.iter(|| {
            let wraps: Vec<_> = recipients
                .iter()
                .map(|(pk, id)| {
                    wrap_key_to_recipient(&dek, *id, 1, pk).unwrap()
                })
                .collect();
            let _ = black_box(wraps);
        });
    });

    g.bench_function("parallel", |b| {
        b.iter(|| {
            let wraps: Vec<_> = recipients
                .par_iter()
                .map(|(pk, id)| {
                    wrap_key_to_recipient(&dek, *id, 1, pk).unwrap()
                })
                .collect();
            let _ = black_box(wraps);
        });
    });
    g.finish();
}

fn bench_parallel_manifest_verify(c: &mut Criterion) {
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

    for idx in 0..100 {
        let mut mid = [0u8; 16];
        mid[0..4].copy_from_slice(&(idx as u32 + 2).to_be_bytes());
        manifest.add_member(&admin_sk, mid, admin_pk, rec_pk.clone(), gk_wrap.clone()).unwrap();
    }

    let mut g = c.benchmark_group("parallel_manifest_verify");
    g.bench_function("sequential", |b| {
        b.iter(|| {
            let res = black_box(&manifest).verify();
            let _ = black_box(res);
        });
    });

    g.bench_function("parallel", |b| {
        b.iter(|| {
            let founder_pk = manifest.founder_signing_pk().unwrap();
            let signatures_valid = manifest.operations.par_iter().all(|op| {
                let msg = op.sig_message();
                ed25519_verify(&founder_pk, &msg, &op.signature).is_ok()
            });
            let _ = black_box(signatures_valid);
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_parallel_encrypt_decrypt,
    bench_parallel_merkle,
    bench_parallel_recipient_wrap,
    bench_parallel_manifest_verify
);
criterion_main!(benches);

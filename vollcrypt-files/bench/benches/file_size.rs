use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rayon::prelude::*;
use vollcrypt_files_core::*;
use vollcrypt_files_bench::get_current_rss_mb;

fn bench_file_size_scaling(c: &mut Criterion) {
    let dek = [0u8; 32];
    let file_id = [0u8; 16];
    let chunk_size = 1024 * 1024; // 1 MB chunks

    let file_sizes = [1_048_576, 10_485_760, 104_857_600];

    let mut g_seq = c.benchmark_group("file_size_single_core");
    for &size in &file_sizes {
        let num_chunks = size / chunk_size;
        let plain_chunk = vec![0u8; chunk_size];
        g_seq.throughput(Throughput::Bytes(size as u64));
        g_seq.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let mut leaf_hashes = Vec::with_capacity(num_chunks);
                let start_rss = get_current_rss_mb();
                for idx in 0..num_chunks {
                    let env = encrypt_chunk(&dek, &file_id, idx as u32, black_box(&plain_chunk)).unwrap();
                    leaf_hashes.push(chunk_leaf_hash(&env));
                }
                let tree = MerkleTree::from_leaves(leaf_hashes);
                let root = tree.root();
                let end_rss = get_current_rss_mb();
                let _ = black_box((root, start_rss, end_rss));
            });
        });
    }
    g_seq.finish();

    let mut g_par = c.benchmark_group("file_size_all_cores");
    for &size in &file_sizes {
        let num_chunks = size / chunk_size;
        let plain_chunk = vec![0u8; chunk_size];
        g_par.throughput(Throughput::Bytes(size as u64));
        g_par.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let pool = rayon::ThreadPoolBuilder::new().build().unwrap();
                pool.install(|| {
                    let leaf_hashes: Vec<[u8; 32]> = (0..num_chunks)
                        .into_par_iter()
                        .map(|idx| {
                            let env = encrypt_chunk(&dek, &file_id, idx as u32, black_box(&plain_chunk)).unwrap();
                            chunk_leaf_hash(&env)
                        })
                        .collect();
                    let tree = MerkleTree::from_leaves(leaf_hashes);
                    let root = tree.root();
                    let _ = black_box(root);
                });
            });
        });
    }
    g_par.finish();
}

fn bench_chunk_size_sensitivity(c: &mut Criterion) {
    let dek = [0u8; 32];
    let file_id = [0u8; 16];
    let file_size = 32 * 1024 * 1024; // 32 MB file for speed

    let chunk_sizes = [
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
    ];

    let mut g = c.benchmark_group("chunk_size_sensitivity");
    g.throughput(Throughput::Bytes(file_size as u64));

    for &c_size in &chunk_sizes {
        let num_chunks = file_size / c_size;
        let plain_chunk = vec![0u8; c_size];
        g.bench_with_input(BenchmarkId::from_parameter(c_size), &c_size, |b, _| {
            b.iter(|| {
                let mut leaf_hashes = Vec::with_capacity(num_chunks);
                for idx in 0..num_chunks {
                    let env = encrypt_chunk(&dek, &file_id, idx as u32, black_box(&plain_chunk)).unwrap();
                    leaf_hashes.push(chunk_leaf_hash(&env));
                }
                let tree = MerkleTree::from_leaves(leaf_hashes);
                let _ = black_box(tree.root());
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_file_size_scaling,
    bench_chunk_size_sensitivity
);
criterion_main!(benches);

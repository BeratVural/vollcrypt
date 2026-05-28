# Vollcrypt File Performance Report

Generated: 2026-05-28T13:31:16.213228200+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| RAM | 15.62 GB (9.39 GB available) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## Executive Summary

- **Peak single-core throughput:** 2.03 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.87 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 73.03 ms
- **Hybrid KEM wrap latency:** 0.10 ms
- **1 GB file encryption (all cores):** 0.15 s (measured)

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 2.60 μs | 1.18 μs | 1502.40 MB/s |
| decrypt_chunk | 4 KB | 2.70 μs | 0.25 μs | 1446.76 MB/s |
| encrypt_chunk | 64 KB | 30.00 μs | 11.48 μs | 2083.33 MB/s |
| decrypt_chunk | 64 KB | 30.30 μs | 10.98 μs | 2062.71 MB/s |
| encrypt_chunk | 1 MB | 628.10 μs | 46.55 μs | 1592.10 MB/s |
| decrypt_chunk | 1 MB | 612.70 μs | 13.40 μs | 1632.12 MB/s |
| encrypt_chunk | 4 MB | 2265.20 μs | 261.64 μs | 1765.85 MB/s |
| decrypt_chunk | 4 MB | 2233.60 μs | 6.75 μs | 1790.83 MB/s |
| encrypt_chunk | 16 MB | 8307.60 μs | 924.83 μs | 1925.95 MB/s |
| decrypt_chunk | 16 MB | 8597.00 μs | 470.36 μs | 1861.11 MB/s |
| merkle_root_construction | 16 leaves | 2.50 μs | 1.39 μs | N/A |
| merkle_root_construction | 256 leaves | 23.50 μs | 3.02 μs | N/A |
| merkle_root_construction | 4096 leaves | 271.10 μs | 62.04 μs | N/A |
| merkle_root_construction | 65536 leaves | 4557.90 μs | 79.28 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.40 μs | 0.05 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.30 μs | 0.09 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.313 μs | 0.027 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.50 μs | 0.36 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.50 μs | 0.05 μs | N/A |
| ed25519_sign | 1 KB message | 38.00 μs | 2.43 μs | N/A |
| ed25519_verify | 1 KB message | 29.10 μs | 1.71 μs | N/A |
| header_write | 1 wrap | 0.20 μs | 0.33 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.17 μs | N/A |
| chunk_envelope_write | 1 MB | 175.00 μs | 39.31 μs | N/A |
| chunk_envelope_parse | 1 MB | 134.20 μs | 4.06 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.901 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 3.183 GB/s | 1.67x | 83.7% |
| parallel_encrypt | 4 | 4.643 GB/s | 2.44x | 61.0% |
| parallel_encrypt | 6 | 5.869 GB/s | 3.09x | 51.5% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.58 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 5.80 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 34.44 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 11.98 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 73.03 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 528.78 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.066 ms |
| wrap_key_to_recipient | 0.101 ms |
| unwrap_key_with_recipient_key | 0.089 ms |
| **Post-Quantum Cost Ratio** | **88.4%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.61 ms | 0.55 ms | 0.57 MB |
| 10 MB | 5.50 ms | 4.95 ms | 0.10 MB |
| 100 MB | 52.43 ms | 47.19 ms | 0.10 MB |
| 1 GB | 551.45 ms | 496.31 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.13 ms | 1263 B |
| 10 | 1.05 ms | 11910 B |
| 100 | 10.77 ms | 118380 B |
| 1000 | 102.92 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.061 ms | 0.07 ms | 0.00 ms | 5208 B |
| 10 | 0.051 ms | 0.30 ms | 0.02 ms | 28500 B |
| 100 | 0.052 ms | 2.78 ms | 0.14 ms | 261420 B |
| 1000 | 0.052 ms | 29.42 ms | 1.47 ms | 2590620 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.54 s (measured) | 0.15 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.51 s (measured) | 0.13 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.18 s (scaled) | N/A | Single-threaded CLI tool |
| Age Tool | 0.83 s (scaled) | N/A | Single-threaded CLI tool (X25519) |

*Note: Baseline timings scaled mathematically based on 100MB runs, OpenSSL, or Age speed caps.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.31 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

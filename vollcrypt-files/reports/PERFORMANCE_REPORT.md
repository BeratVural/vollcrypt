# Vollcrypt File Performance Report

Generated: 2026-05-28T15:12:04.091116300+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| RAM | 15.62 GB (9.40 GB available) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## Executive Summary

- **Peak single-core throughput:** 1.38 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.33 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 71.43 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.16 s (measured)

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 3.60 μs | 3.44 μs | 1085.07 MB/s |
| decrypt_chunk | 4 KB | 3.60 μs | 0.17 μs | 1085.07 MB/s |
| encrypt_chunk | 64 KB | 44.20 μs | 11.13 μs | 1414.03 MB/s |
| decrypt_chunk | 64 KB | 44.40 μs | 9.50 μs | 1407.66 MB/s |
| encrypt_chunk | 1 MB | 858.50 μs | 54.24 μs | 1164.82 MB/s |
| decrypt_chunk | 1 MB | 835.70 μs | 11.02 μs | 1196.60 MB/s |
| encrypt_chunk | 4 MB | 3163.30 μs | 223.17 μs | 1264.50 MB/s |
| decrypt_chunk | 4 MB | 3186.30 μs | 24.55 μs | 1255.37 MB/s |
| encrypt_chunk | 16 MB | 13041.20 μs | 584.05 μs | 1226.88 MB/s |
| decrypt_chunk | 16 MB | 11929.70 μs | 700.68 μs | 1341.19 MB/s |
| merkle_root_construction | 16 leaves | 3.60 μs | 2.81 μs | N/A |
| merkle_root_construction | 256 leaves | 28.10 μs | 4.79 μs | N/A |
| merkle_root_construction | 4096 leaves | 347.80 μs | 5.97 μs | N/A |
| merkle_root_construction | 65536 leaves | 5881.10 μs | 232.04 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.50 μs | 0.16 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.60 μs | 0.09 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.391 μs | 0.002 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.80 μs | 0.54 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.80 μs | 0.09 μs | N/A |
| ed25519_sign | 1 KB message | 33.70 μs | 1.98 μs | N/A |
| ed25519_verify | 1 KB message | 32.50 μs | 2.21 μs | N/A |
| header_write | 1 wrap | 0.20 μs | 0.42 μs | N/A |
| header_parse | 1 wrap | 0.20 μs | 0.08 μs | N/A |
| chunk_envelope_write | 1 MB | 305.10 μs | 100.53 μs | N/A |
| chunk_envelope_parse | 1 MB | 146.80 μs | 16.05 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.291 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.554 GB/s | 1.98x | 98.9% |
| parallel_encrypt | 4 | 4.285 GB/s | 3.32x | 83.0% |
| parallel_encrypt | 6 | 5.335 GB/s | 4.13x | 68.9% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.80 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 7.91 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 47.50 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 11.75 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 71.43 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 503.52 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.046 ms |
| wrap_key_to_recipient | 0.083 ms |
| unwrap_key_with_recipient_key | 0.074 ms |
| **Post-Quantum Cost Ratio** | **61.4%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.79 ms | 0.71 ms | 0.52 MB |
| 10 MB | 7.91 ms | 7.12 ms | 0.10 MB |
| 100 MB | 71.50 ms | 64.35 ms | 0.10 MB |
| 1 GB | 725.70 ms | 653.13 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.09 ms | 1263 B |
| 10 | 0.91 ms | 11910 B |
| 100 | 8.33 ms | 118380 B |
| 1000 | 82.33 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.048 ms | 0.07 ms | 0.00 ms | 5208 B |
| 10 | 0.045 ms | 0.39 ms | 0.02 ms | 28500 B |
| 100 | 0.045 ms | 3.49 ms | 0.17 ms | 261420 B |
| 1000 | 0.045 ms | 35.93 ms | 1.80 ms | 2590620 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.73 s (measured) | 0.16 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.72 s (measured) | 0.15 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.18 s (scaled) | N/A | Single-threaded CLI tool |
| Age Tool | 0.83 s (scaled) | N/A | Single-threaded CLI tool (X25519) |

*Note: Baseline timings scaled mathematically based on 100MB runs, OpenSSL, or Age speed caps.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.39 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

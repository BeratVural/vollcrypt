# Vollcrypt File Performance Report

Generated: 2026-05-28T01:07:07.256331500+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| RAM | 15.62 GB (9.23 GB available) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## Executive Summary

- **Peak single-core throughput:** 1.87 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 6.23 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 72.29 ms
- **Hybrid KEM wrap latency:** 0.10 ms
- **1 GB file encryption (all cores):** 0.29 s (measured)

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 11.10 μs | 78.07 μs | 351.91 MB/s |
| decrypt_chunk | 4 KB | 2.70 μs | 1.27 μs | 1446.76 MB/s |
| encrypt_chunk | 64 KB | 32.70 μs | 10.33 μs | 1911.31 MB/s |
| decrypt_chunk | 64 KB | 33.80 μs | 11.18 μs | 1849.11 MB/s |
| encrypt_chunk | 1 MB | 601.30 μs | 61.26 μs | 1663.06 MB/s |
| decrypt_chunk | 1 MB | 607.10 μs | 16.32 μs | 1647.18 MB/s |
| encrypt_chunk | 4 MB | 2239.90 μs | 262.73 μs | 1785.79 MB/s |
| decrypt_chunk | 4 MB | 2239.60 μs | 3.49 μs | 1786.03 MB/s |
| encrypt_chunk | 16 MB | 8693.90 μs | 779.00 μs | 1840.37 MB/s |
| decrypt_chunk | 16 MB | 8842.60 μs | 235.76 μs | 1809.42 MB/s |
| merkle_root_construction | 16 leaves | 3.20 μs | 5.42 μs | N/A |
| merkle_root_construction | 256 leaves | 25.00 μs | 6.42 μs | N/A |
| merkle_root_construction | 4096 leaves | 343.80 μs | 64.27 μs | N/A |
| merkle_root_construction | 65536 leaves | 4874.40 μs | 196.57 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.60 μs | 0.14 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.50 μs | 1.18 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.323 μs | 0.033 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.40 μs | 2.07 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.50 μs | 0.05 μs | N/A |
| ed25519_sign | 1 KB message | 31.40 μs | 0.00 μs | N/A |
| ed25519_verify | 1 KB message | 24.20 μs | 6.16 μs | N/A |
| header_write | 1 wrap | 0.50 μs | 1.87 μs | N/A |
| header_parse | 1 wrap | 0.30 μs | 2.10 μs | N/A |
| chunk_envelope_write | 1 MB | 132.70 μs | 49.62 μs | N/A |
| chunk_envelope_parse | 1 MB | 139.20 μs | 12.21 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.555 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 3.336 GB/s | 2.14x | 107.2% |
| parallel_encrypt | 4 | 5.277 GB/s | 3.39x | 84.8% |
| parallel_encrypt | 6 | 6.230 GB/s | 4.01x | 66.8% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.69 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 6.91 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 34.46 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 13.36 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 72.29 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 514.22 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.063 ms |
| wrap_key_to_recipient | 0.100 ms |
| unwrap_key_with_recipient_key | 0.091 ms |
| **Post-Quantum Cost Ratio** | **88.8%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 1.22 ms | 1.10 ms | 0.61 MB |
| 10 MB | 12.67 ms | 11.40 ms | 0.10 MB |
| 100 MB | 112.37 ms | 101.13 ms | 0.10 MB |
| 1 GB | 1195.80 ms | 1076.22 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.11 ms | 1263 B |
| 10 | 1.03 ms | 11910 B |
| 100 | 10.04 ms | 118380 B |
| 1000 | 99.23 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.056 ms | 0.06 ms | 0.00 ms | 5208 B |
| 10 | 0.051 ms | 0.30 ms | 0.01 ms | 28500 B |
| 100 | 0.050 ms | 2.69 ms | 0.13 ms | 261420 B |
| 1000 | 0.058 ms | 27.38 ms | 1.37 ms | 2590620 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 1.18 s (measured) | 0.29 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.52 s (measured) | 0.11 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.18 s (scaled) | N/A | Single-threaded CLI tool |
| Age Tool | 0.83 s (scaled) | N/A | Single-threaded CLI tool (X25519) |

*Note: Baseline timings scaled mathematically based on 100MB runs, OpenSSL, or Age speed caps.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.32 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

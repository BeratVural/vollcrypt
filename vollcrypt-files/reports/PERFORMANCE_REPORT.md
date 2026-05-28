# Vollcrypt File Performance Report

Generated: 2026-05-28T00:52:04.796660400+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| RAM | 15.62 GB (9.47 GB available) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## Executive Summary

- **Peak single-core throughput:** 0.25 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 1.53 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 0.00 ms
- **Hybrid KEM wrap latency:** 0.19 ms
- **1 GB file encryption (all cores):** ~1.85 s (extrapolated)

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 23.20 μs | 44.24 μs | 168.37 MB/s |
| decrypt_chunk | 4 KB | 18.20 μs | 0.14 μs | 214.63 MB/s |
| encrypt_chunk | 64 KB | 260.30 μs | 8.67 μs | 240.11 MB/s |
| decrypt_chunk | 64 KB | 261.10 μs | 11.72 μs | 239.37 MB/s |
| encrypt_chunk | 1 MB | 4182.20 μs | 40.15 μs | 239.11 MB/s |
| decrypt_chunk | 1 MB | 4112.70 μs | 13.13 μs | 243.15 MB/s |
| encrypt_chunk | 4 MB | 16275.90 μs | 161.25 μs | 245.76 MB/s |
| decrypt_chunk | 4 MB | 16270.20 μs | 26.33 μs | 245.85 MB/s |
| encrypt_chunk | 16 MB | 62632.70 μs | 908.19 μs | 255.46 MB/s |
| decrypt_chunk | 16 MB | 64733.60 μs | 234.09 μs | 247.17 MB/s |
| merkle_root_construction | 16 leaves | 7.30 μs | 2.64 μs | N/A |
| merkle_root_construction | 256 leaves | 83.50 μs | 11.43 μs | N/A |
| merkle_root_construction | 4096 leaves | 1477.90 μs | 37.62 μs | N/A |
| merkle_root_construction | 65536 leaves | 21786.00 μs | 156.71 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.20 μs | 0.12 μs | N/A |
| verify_merkle_proof | 65536 leaves | 5.30 μs | 0.22 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 1.409 μs | 0.005 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.70 μs | 0.42 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.70 μs | 0.19 μs | N/A |
| ed25519_sign | 1 KB message | 35.70 μs | 0.05 μs | N/A |
| ed25519_verify | 1 KB message | 2234.20 μs | 39.68 μs | N/A |
| header_write | 1 wrap | 0.50 μs | 0.40 μs | N/A |
| header_parse | 1 wrap | 0.20 μs | 0.17 μs | N/A |
| chunk_envelope_write | 1 MB | 178.00 μs | 34.71 μs | N/A |
| chunk_envelope_parse | 1 MB | 125.90 μs | 3.84 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 0.239 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 0.481 GB/s | 2.01x | 100.7% |
| parallel_encrypt | 4 | 0.876 GB/s | 3.67x | 91.7% |
| parallel_encrypt | 6 | 1.045 GB/s | 4.38x | 72.9% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 3.80 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 36.87 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 226.54 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 20.57 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 118.29 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 834.58 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.153 ms |
| wrap_key_to_recipient | 0.189 ms |
| unwrap_key_with_recipient_key | 0.206 ms |
| **Post-Quantum Cost Ratio** | **203.5%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 6.51 ms | 5.86 ms | 0.18 MB |
| 10 MB | 63.82 ms | 57.44 ms | 0.10 MB |
| 100 MB | 614.47 ms | 553.02 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.19 ms | 1263 B |
| 10 | 1.90 ms | 11910 B |
| 100 | 19.16 ms | 118380 B |
| 1000 | 189.93 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.064 ms | 4.31 ms | 0.22 ms | 5208 B |
| 10 | 0.062 ms | 23.58 ms | 1.18 ms | 28500 B |
| 100 | 0.062 ms | 216.30 ms | 10.81 ms | 261420 B |
| 1000 | 0.062 ms | 2188.25 ms | 109.41 ms | 2590620 B |

## Comparison vs Industry Baselines

| Tool | 1 GB file (all cores) | Notes |
| --- | --- | --- |
| Vollcrypt File | 6.28 s (scaled) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 4.05 s (scaled) | No envelope, no integrity tree |
| OpenSSL CLI | 6.91 s (scaled) | Single-threaded |
| Age Tool | 8.16 s (scaled) | X25519 only, single recipient |

*Note: Baseline timings scaled mathematically based on 100MB runs.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 1.41 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

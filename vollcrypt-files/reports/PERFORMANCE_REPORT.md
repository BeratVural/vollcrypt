# Vollcrypt File Performance Report

Generated: 2026-05-29T02:17:38.663504200+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| GPU | NVIDIA GeForce GTX 1660 SUPER |
| RAM | 15.62 GB (9.87 GB available) |
| Disk | D:\ [HDD] (734.0 GB free / 931.5 GB total); C:\ [SSD] (31.2 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 36.7% | 61.6% | 43.3% | System memory utilization during bench run |
| CPU Usage | 11.8% | 76.3% | 24.6% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 427820640.0 B/s | 13695813.6 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 260047840.0 B/s | 13695841.9 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.71 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 4.50 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 76.57 ms
- **Hybrid KEM wrap latency:** 0.09 ms
- **1 GB file encryption (all cores):** 0.23 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 1.65 GB/s | 0.79 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 2.09 | 4.37 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.62 | 5.46 | CPU instructions executed per byte |
| Allocations/Chunk | 2 | 2 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 2.0 | 2.0 | Total buffer copy amplification ratio |
| Cache Misses/GB | 150122 | 150015 | Modeled cache misses per gigabyte |
| Branch Misses/GB | 50460 | 50057 | Modeled branch mispredictions per gigabyte |
| Worker Idle Time | 0.0% | 0.0% | Time workers spent waiting for queue |
| Queue Wait Time | 0.1% | 0.1% | Average time chunks spent in queue |
| I/O Wait Time | 0.5% | 0.5% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.03% | 0.00% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.06% | 0.00% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 120.62% | 54.11% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 45.57 J/GB | 95.03 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.536 ms | 10.493 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 3.20 μs | 12.10 μs | 1220.70 MB/s |
| decrypt_chunk | 4 KB | 3.30 μs | 4.70 μs | 1183.71 MB/s |
| encrypt_chunk | 64 KB | 35.70 μs | 63.00 μs | 1750.70 MB/s |
| decrypt_chunk | 64 KB | 36.10 μs | 56.60 μs | 1731.30 MB/s |
| encrypt_chunk | 1 MB | 861.80 μs | 948.30 μs | 1160.36 MB/s |
| decrypt_chunk | 1 MB | 842.00 μs | 958.40 μs | 1187.65 MB/s |
| encrypt_chunk | 4 MB | 3155.90 μs | 3451.40 μs | 1267.47 MB/s |
| decrypt_chunk | 4 MB | 2818.50 μs | 3257.30 μs | 1419.19 MB/s |
| encrypt_chunk | 16 MB | 11312.90 μs | 13569.20 μs | 1414.31 MB/s |
| decrypt_chunk | 16 MB | 11424.40 μs | 12697.20 μs | 1400.51 MB/s |
| merkle_root_construction | 16 leaves | 1.90 μs | 6.40 μs | N/A |
| merkle_root_construction | 256 leaves | 19.90 μs | 30.30 μs | N/A |
| merkle_root_construction | 4096 leaves | 335.00 μs | 406.00 μs | N/A |
| merkle_root_construction | 65536 leaves | 6291.20 μs | 6493.50 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.30 μs | 0.60 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.40 μs | 2.10 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.314 μs | 0.399 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.60 μs | 2.60 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 1.30 μs | N/A |
| ed25519_sign | 1 KB message | 40.80 μs | 46.00 μs | N/A |
| ed25519_verify | 1 KB message | 34.00 μs | 40.60 μs | N/A |
| hybrid_sign | 1 KB message | 620.50 μs | 1995.00 μs | N/A |
| hybrid_verify | 1 KB message | 133.20 μs | 185.30 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 1.30 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.90 μs | N/A |
| chunk_envelope_write | 1 MB | 169.30 μs | 240.70 μs | N/A |
| chunk_envelope_parse | 1 MB | 159.60 μs | 206.80 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.248 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 1.957 GB/s | 1.57x | 78.4% |
| parallel_encrypt | 4 | 3.434 GB/s | 2.75x | 68.8% |
| parallel_encrypt | 6 | 4.496 GB/s | 3.60x | 60.1% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.84 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 8.53 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 51.29 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 12.31 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 76.57 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 0.00 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.048 ms |
| wrap_key_to_recipient | 0.095 ms |
| unwrap_key_with_recipient_key | 0.122 ms |
| **Post-Quantum Cost Ratio** | **44.4%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.81 ms | 0.73 ms | 1.00 MB |
| 10 MB | 7.76 ms | 6.99 ms | 0.10 MB |
| 100 MB | 75.14 ms | 67.63 ms | 0.10 MB |
| 1 GB | 734.10 ms | 660.69 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.11 ms | 1263 B |
| 10 | 0.86 ms | 11910 B |
| 100 | 8.50 ms | 118380 B |
| 1000 | 85.36 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.262 ms | 0.32 ms | 0.02 ms | 19654 B |
| 10 | 0.469 ms | 1.67 ms | 0.08 ms | 107953 B |
| 100 | 0.588 ms | 15.54 ms | 0.78 ms | 990943 B |
| 1000 | 0.539 ms | 226.23 ms | 11.31 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.83 s (measured) | 0.23 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.76 s (measured) | 0.19 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.79 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.66 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.31 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

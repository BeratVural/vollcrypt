# Vollcrypt File Performance Report

Generated: 2026-05-30T11:58:58.833823200+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| GPU | NVIDIA GeForce GTX 1660 SUPER |
| RAM | 15.62 GB (9.25 GB available) |
| Disk | D:\ [HDD] (734.0 GB free / 931.5 GB total); C:\ [SSD] (27.7 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 40.1% | 59.3% | 46.8% | System memory utilization during bench run |
| CPU Usage | 7.5% | 79.6% | 29.1% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 1904.0 B/s | 21.8 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.65 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.42 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 70.17 ms
- **Hybrid KEM wrap latency:** 0.09 ms
- **1 GB file encryption (all cores):** 0.15 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 3.38 GB/s | 2.97 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 1.02 | 1.16 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 1.27 | 1.45 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Cache Misses/GB | 150122 | 150015 | Modeled cache misses per gigabyte |
| Branch Misses/GB | 50460 | 50057 | Modeled branch mispredictions per gigabyte |
| Worker Idle Time | 0.0% | 0.0% | Time workers spent waiting for queue |
| Queue Wait Time | 0.1% | 0.1% | Average time chunks spent in queue |
| I/O Wait Time | 0.5% | 0.5% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.05% | 0.01% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.13% | 0.01% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 243.35% | 220.25% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 22.16 J/GB | 25.26 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.182 ms | 1.772 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 2.90 μs | 25.20 μs | 1346.98 MB/s |
| decrypt_chunk | 4 KB | 3.30 μs | 3.70 μs | 1183.71 MB/s |
| encrypt_chunk | 64 KB | 36.90 μs | 82.70 μs | 1693.77 MB/s |
| decrypt_chunk | 64 KB | 36.90 μs | 58.40 μs | 1693.77 MB/s |
| encrypt_chunk | 1 MB | 687.70 μs | 813.20 μs | 1454.12 MB/s |
| decrypt_chunk | 1 MB | 694.90 μs | 746.80 μs | 1439.06 MB/s |
| encrypt_chunk | 4 MB | 2601.10 μs | 3091.30 μs | 1537.81 MB/s |
| decrypt_chunk | 4 MB | 2646.40 μs | 2680.60 μs | 1511.49 MB/s |
| encrypt_chunk | 16 MB | 10506.80 μs | 11809.40 μs | 1522.82 MB/s |
| decrypt_chunk | 16 MB | 10616.50 μs | 10648.10 μs | 1507.09 MB/s |
| merkle_root_construction | 16 leaves | 2.10 μs | 9.30 μs | N/A |
| merkle_root_construction | 256 leaves | 20.60 μs | 30.30 μs | N/A |
| merkle_root_construction | 4096 leaves | 322.50 μs | 415.50 μs | N/A |
| merkle_root_construction | 65536 leaves | 6000.10 μs | 6211.70 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.10 μs | 0.40 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.50 μs | 1.90 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.314 μs | 0.326 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.50 μs | 7.40 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 0.70 μs | N/A |
| ed25519_sign | 1 KB message | 28.10 μs | 28.20 μs | N/A |
| ed25519_verify | 1 KB message | 26.50 μs | 42.20 μs | N/A |
| hybrid_sign | 1 KB message | 337.90 μs | 1238.20 μs | N/A |
| hybrid_verify | 1 KB message | 128.00 μs | 145.50 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 3.00 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.50 μs | N/A |
| chunk_envelope_write | 1 MB | 134.00 μs | 230.10 μs | N/A |
| chunk_envelope_parse | 1 MB | 132.90 μs | 166.90 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.347 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.605 GB/s | 1.93x | 96.7% |
| parallel_encrypt | 4 | 4.299 GB/s | 3.19x | 79.8% |
| parallel_encrypt | 6 | 5.419 GB/s | 4.02x | 67.1% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.80 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 8.04 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 50.22 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 11.59 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 70.17 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 0.00 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.047 ms |
| wrap_key_to_recipient | 0.085 ms |
| unwrap_key_with_recipient_key | 0.086 ms |
| **Post-Quantum Cost Ratio** | **66.0%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.80 ms | 0.72 ms | 1.00 MB |
| 10 MB | 7.32 ms | 6.59 ms | 0.10 MB |
| 100 MB | 71.04 ms | 63.94 ms | 0.10 MB |
| 1 GB | 727.72 ms | 654.95 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.09 ms | 1263 B |
| 10 | 0.83 ms | 11910 B |
| 100 | 8.11 ms | 118380 B |
| 1000 | 81.46 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.593 ms | 0.32 ms | 0.02 ms | 19654 B |
| 10 | 0.690 ms | 1.67 ms | 0.08 ms | 107953 B |
| 100 | 0.489 ms | 15.29 ms | 0.76 ms | 990943 B |
| 1000 | 0.533 ms | 152.20 ms | 7.61 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.73 s (measured) | 0.15 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.72 s (measured) | 0.15 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.75 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.58 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.31 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

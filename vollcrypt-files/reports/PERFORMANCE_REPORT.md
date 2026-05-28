# Vollcrypt File Performance Report

Generated: 2026-05-28T16:19:47.718054800+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| GPU | NVIDIA GeForce GTX 1660 SUPER |
| RAM | 15.62 GB (9.43 GB available) |
| Disk | D:\ [HDD] (733.8 GB free / 931.5 GB total); C:\ [SSD] (27.4 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 39.5% | 59.0% | 43.1% | System memory utilization during bench run |
| CPU Usage | 11.7% | 63.8% | 20.5% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 260047840.0 B/s | 15790467.4 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 234881920.0 B/s | 15790498.5 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.70 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.33 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 70.26 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.17 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 1.56 GB/s | 1.79 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 2.21 | 1.92 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.77 | 2.40 | CPU instructions executed per byte |
| Allocations/Chunk | 2 | 2 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 2.0 | 2.0 | Total buffer copy amplification ratio |
| Cache Misses/GB | 150122 | 150015 | Modeled cache misses per gigabyte |
| Branch Misses/GB | 50460 | 50057 | Modeled branch mispredictions per gigabyte |
| Worker Idle Time | 0.0% | 0.0% | Time workers spent waiting for queue |
| Queue Wait Time | 0.1% | 0.1% | Average time chunks spent in queue |
| I/O Wait Time | 0.5% | 0.5% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.02% | 0.01% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.06% | 0.01% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 112.08% | 124.65% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 48.13 J/GB | 41.85 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.473 ms | 3.636 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 2.80 μs | 6.70 μs | 1395.09 MB/s |
| decrypt_chunk | 4 KB | 2.90 μs | 4.10 μs | 1346.98 MB/s |
| encrypt_chunk | 64 KB | 36.00 μs | 55.20 μs | 1736.11 MB/s |
| decrypt_chunk | 64 KB | 36.90 μs | 55.10 μs | 1693.77 MB/s |
| encrypt_chunk | 1 MB | 880.90 μs | 1059.20 μs | 1135.20 MB/s |
| decrypt_chunk | 1 MB | 723.00 μs | 896.40 μs | 1383.13 MB/s |
| encrypt_chunk | 4 MB | 2683.20 μs | 3146.60 μs | 1490.76 MB/s |
| decrypt_chunk | 4 MB | 2658.80 μs | 2678.50 μs | 1504.44 MB/s |
| encrypt_chunk | 16 MB | 10543.30 μs | 11821.10 μs | 1517.55 MB/s |
| decrypt_chunk | 16 MB | 10669.50 μs | 11022.40 μs | 1499.60 MB/s |
| merkle_root_construction | 16 leaves | 1.70 μs | 4.70 μs | N/A |
| merkle_root_construction | 256 leaves | 16.20 μs | 31.90 μs | N/A |
| merkle_root_construction | 4096 leaves | 248.70 μs | 334.40 μs | N/A |
| merkle_root_construction | 65536 leaves | 4810.20 μs | 4877.70 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.10 μs | 0.30 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.30 μs | 1.70 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.320 μs | 0.325 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.50 μs | 1.50 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 0.70 μs | N/A |
| ed25519_sign | 1 KB message | 28.10 μs | 40.70 μs | N/A |
| ed25519_verify | 1 KB message | 26.20 μs | 35.10 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 0.70 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.40 μs | N/A |
| chunk_envelope_write | 1 MB | 139.60 μs | 234.70 μs | N/A |
| chunk_envelope_parse | 1 MB | 122.00 μs | 163.10 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.396 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.609 GB/s | 1.87x | 93.5% |
| parallel_encrypt | 4 | 4.423 GB/s | 3.17x | 79.2% |
| parallel_encrypt | 6 | 5.327 GB/s | 3.82x | 63.6% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.79 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 8.27 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 48.04 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 11.29 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 70.26 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 504.94 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.057 ms |
| wrap_key_to_recipient | 0.083 ms |
| unwrap_key_with_recipient_key | 0.075 ms |
| **Post-Quantum Cost Ratio** | **58.8%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.81 ms | 0.73 ms | 1.00 MB |
| 10 MB | 7.15 ms | 6.43 ms | 0.10 MB |
| 100 MB | 70.78 ms | 63.70 ms | 0.10 MB |
| 1 GB | 725.31 ms | 652.78 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.09 ms | 1263 B |
| 10 | 0.89 ms | 11910 B |
| 100 | 8.27 ms | 118380 B |
| 1000 | 82.57 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.048 ms | 0.06 ms | 0.00 ms | 5208 B |
| 10 | 0.045 ms | 0.33 ms | 0.02 ms | 28500 B |
| 100 | 0.045 ms | 3.06 ms | 0.15 ms | 261420 B |
| 1000 | 0.045 ms | 30.64 ms | 1.53 ms | 2590620 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.73 s (measured) | 0.17 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.72 s (measured) | 0.16 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.75 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.58 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.32 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

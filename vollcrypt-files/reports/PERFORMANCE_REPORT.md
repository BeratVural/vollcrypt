# Vollcrypt File Performance Report

Generated: 2026-05-28T17:40:46.228013100+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| GPU | NVIDIA GeForce GTX 1660 SUPER |
| RAM | 15.62 GB (9.16 GB available) |
| Disk | D:\ [HDD] (733.8 GB free / 931.5 GB total); C:\ [SSD] (22.4 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 41.1% | 64.7% | 47.2% | System memory utilization during bench run |
| CPU Usage | 11.6% | 64.9% | 20.7% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 343934240.0 B/s | 13421897.3 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 260047840.0 B/s | 13421923.7 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.73 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.31 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 70.24 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.16 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 1.60 GB/s | 0.76 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 2.15 | 4.51 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.69 | 5.64 | CPU instructions executed per byte |
| Allocations/Chunk | 2 | 2 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 2.0 | 2.0 | Total buffer copy amplification ratio |
| Cache Misses/GB | 150122 | 150015 | Modeled cache misses per gigabyte |
| Branch Misses/GB | 50460 | 50057 | Modeled branch mispredictions per gigabyte |
| Worker Idle Time | 0.0% | 0.0% | Time workers spent waiting for queue |
| Queue Wait Time | 0.1% | 0.1% | Average time chunks spent in queue |
| I/O Wait Time | 0.5% | 0.5% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.02% | 0.00% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.06% | 0.00% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 114.91% | 52.69% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 46.79 J/GB | 98.23 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.511 ms | 9.305 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 2.80 μs | 18.10 μs | 1395.09 MB/s |
| decrypt_chunk | 4 KB | 2.90 μs | 3.50 μs | 1346.98 MB/s |
| encrypt_chunk | 64 KB | 35.20 μs | 54.00 μs | 1775.57 MB/s |
| decrypt_chunk | 64 KB | 36.80 μs | 53.40 μs | 1698.37 MB/s |
| encrypt_chunk | 1 MB | 721.20 μs | 828.10 μs | 1386.58 MB/s |
| decrypt_chunk | 1 MB | 730.50 μs | 891.80 μs | 1368.93 MB/s |
| encrypt_chunk | 4 MB | 2655.30 μs | 3085.50 μs | 1506.42 MB/s |
| decrypt_chunk | 4 MB | 2656.80 μs | 3286.20 μs | 1505.57 MB/s |
| encrypt_chunk | 16 MB | 11552.00 μs | 12648.60 μs | 1385.04 MB/s |
| decrypt_chunk | 16 MB | 10638.50 μs | 12054.50 μs | 1503.97 MB/s |
| merkle_root_construction | 16 leaves | 1.40 μs | 9.70 μs | N/A |
| merkle_root_construction | 256 leaves | 16.00 μs | 22.10 μs | N/A |
| merkle_root_construction | 4096 leaves | 250.20 μs | 342.50 μs | N/A |
| merkle_root_construction | 65536 leaves | 4846.10 μs | 5562.20 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.20 μs | 0.50 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.30 μs | 1.60 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.323 μs | 0.334 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.50 μs | 8.80 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 0.70 μs | N/A |
| ed25519_sign | 1 KB message | 28.10 μs | 31.00 μs | N/A |
| ed25519_verify | 1 KB message | 26.60 μs | 38.80 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 2.80 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.40 μs | N/A |
| chunk_envelope_write | 1 MB | 135.00 μs | 227.00 μs | N/A |
| chunk_envelope_parse | 1 MB | 129.60 μs | 170.30 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.394 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.592 GB/s | 1.86x | 93.0% |
| parallel_encrypt | 4 | 4.334 GB/s | 3.11x | 77.7% |
| parallel_encrypt | 6 | 5.312 GB/s | 3.81x | 63.5% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.80 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 7.89 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 47.29 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 11.38 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 70.24 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 505.16 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.045 ms |
| wrap_key_to_recipient | 0.083 ms |
| unwrap_key_with_recipient_key | 0.078 ms |
| **Post-Quantum Cost Ratio** | **68.1%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.78 ms | 0.70 ms | 1.00 MB |
| 10 MB | 7.16 ms | 6.44 ms | 0.10 MB |
| 100 MB | 71.97 ms | 64.77 ms | 0.10 MB |
| 1 GB | 743.61 ms | 669.25 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.11 ms | 1263 B |
| 10 | 0.92 ms | 11910 B |
| 100 | 8.20 ms | 118380 B |
| 1000 | 81.87 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.050 ms | 0.06 ms | 0.00 ms | 5208 B |
| 10 | 0.046 ms | 0.32 ms | 0.02 ms | 28500 B |
| 100 | 0.045 ms | 2.96 ms | 0.15 ms | 261420 B |
| 1000 | 0.045 ms | 29.33 ms | 1.47 ms | 2590620 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.75 s (measured) | 0.16 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.73 s (measured) | 0.16 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.77 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.62 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.32 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

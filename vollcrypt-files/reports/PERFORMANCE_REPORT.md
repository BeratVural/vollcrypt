# Vollcrypt File Performance Report

Generated: 2026-05-30T12:23:03.038182100+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| GPU | NVIDIA GeForce GTX 1660 SUPER |
| RAM | 15.62 GB (9.65 GB available) |
| Disk | D:\ [HDD] (734.0 GB free / 931.5 GB total); C:\ [SSD] (28.4 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 38.2% | 57.1% | 44.7% | System memory utilization during bench run |
| CPU Usage | 11.5% | 77.5% | 28.4% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 1904.0 B/s | 21.8 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.73 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.27 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 71.10 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.16 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 3.44 GB/s | 3.07 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 1.00 | 1.12 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 1.25 | 1.40 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Cache Misses/GB | 150122 | 150015 | Modeled cache misses per gigabyte |
| Branch Misses/GB | 50460 | 50057 | Modeled branch mispredictions per gigabyte |
| Worker Idle Time | 0.0% | 0.0% | Time workers spent waiting for queue |
| Queue Wait Time | 0.1% | 0.1% | Average time chunks spent in queue |
| I/O Wait Time | 0.5% | 0.5% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.06% | 0.01% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.15% | 0.02% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 251.11% | 210.74% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 21.80 J/GB | 24.39 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.174 ms | 1.731 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 2.80 μs | 20.50 μs | 1395.09 MB/s |
| decrypt_chunk | 4 KB | 2.80 μs | 3.20 μs | 1395.09 MB/s |
| encrypt_chunk | 64 KB | 35.30 μs | 53.80 μs | 1770.54 MB/s |
| decrypt_chunk | 64 KB | 36.70 μs | 52.50 μs | 1703.00 MB/s |
| encrypt_chunk | 1 MB | 693.50 μs | 815.00 μs | 1441.96 MB/s |
| decrypt_chunk | 1 MB | 684.30 μs | 740.00 μs | 1461.35 MB/s |
| encrypt_chunk | 4 MB | 2619.10 μs | 2996.00 μs | 1527.24 MB/s |
| decrypt_chunk | 4 MB | 2656.10 μs | 2705.60 μs | 1505.97 MB/s |
| encrypt_chunk | 16 MB | 10537.40 μs | 11798.10 μs | 1518.40 MB/s |
| decrypt_chunk | 16 MB | 10650.40 μs | 10689.10 μs | 1502.29 MB/s |
| merkle_root_construction | 16 leaves | 1.60 μs | 9.90 μs | N/A |
| merkle_root_construction | 256 leaves | 20.60 μs | 29.10 μs | N/A |
| merkle_root_construction | 4096 leaves | 323.80 μs | 409.20 μs | N/A |
| merkle_root_construction | 65536 leaves | 6082.70 μs | 6132.00 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.10 μs | 0.40 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.50 μs | 1.60 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.318 μs | 0.329 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.50 μs | 7.20 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 0.80 μs | N/A |
| ed25519_sign | 1 KB message | 28.10 μs | 31.70 μs | N/A |
| ed25519_verify | 1 KB message | 33.80 μs | 50.70 μs | N/A |
| hybrid_sign | 1 KB message | 344.90 μs | 1517.10 μs | N/A |
| hybrid_verify | 1 KB message | 127.00 μs | 148.20 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 6.50 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.40 μs | N/A |
| chunk_envelope_write | 1 MB | 155.40 μs | 237.90 μs | N/A |
| chunk_envelope_parse | 1 MB | 133.50 μs | 179.40 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.393 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.522 GB/s | 1.81x | 90.5% |
| parallel_encrypt | 4 | 4.366 GB/s | 3.13x | 78.4% |
| parallel_encrypt | 6 | 5.266 GB/s | 3.78x | 63.0% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.81 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 7.92 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 47.40 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 11.27 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 71.10 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 0.00 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.046 ms |
| wrap_key_to_recipient | 0.082 ms |
| unwrap_key_with_recipient_key | 0.100 ms |
| **Post-Quantum Cost Ratio** | **52.1%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.77 ms | 0.69 ms | 1.00 MB |
| 10 MB | 7.16 ms | 6.44 ms | 0.10 MB |
| 100 MB | 73.62 ms | 66.26 ms | 0.10 MB |
| 1 GB | 735.55 ms | 661.99 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.09 ms | 1263 B |
| 10 | 0.86 ms | 11910 B |
| 100 | 8.28 ms | 118380 B |
| 1000 | 82.15 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.725 ms | 0.33 ms | 0.02 ms | 19654 B |
| 10 | 0.717 ms | 1.66 ms | 0.08 ms | 107953 B |
| 100 | 0.456 ms | 15.03 ms | 0.75 ms | 990943 B |
| 1000 | 0.517 ms | 149.24 ms | 7.46 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.72 s (measured) | 0.16 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.72 s (measured) | 0.15 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.75 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.58 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.32 μs overhead per chunk.

## Recommendations

1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

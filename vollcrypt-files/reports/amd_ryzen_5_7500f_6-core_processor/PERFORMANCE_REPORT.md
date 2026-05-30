# Vollcrypt File Performance Report

Generated: 2026-05-30T14:57:38.794706300+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| GPU | NVIDIA GeForce GTX 1660 SUPER |
| RAM | 15.62 GB (10.34 GB available) |
| Disk | D:\ [HDD] (734.0 GB free / 931.5 GB total); C:\ [SSD] (26.4 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 33.9% | 52.6% | 39.7% | System memory utilization during bench run |
| CPU Usage | 8.4% | 63.8% | 21.5% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 1862.0 B/s | 16.3 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.50 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.28 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 67.78 ms
- **Hybrid KEM wrap latency:** 0.11 ms
- **1 GB file encryption (all cores):** 0.15 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 3.62 GB/s | 3.26 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 0.95 | 1.06 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 1.19 | 1.32 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 56.3% | 63.3% | Time workers spent waiting for queue |
| Queue Wait Time | 11.3% | 12.7% | Average time chunks spent in queue |
| I/O Wait Time | 45.0% | 50.6% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.01% | 0.00% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.02% | 0.00% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 43.72% | 36.74% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 20.72 J/GB | 23.01 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.185 ms | 0.744 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 4.20 μs | 9.50 μs | 930.06 MB/s |
| decrypt_chunk | 4 KB | 4.30 μs | 4.80 μs | 908.43 MB/s |
| encrypt_chunk | 64 KB | 44.00 μs | 57.90 μs | 1420.45 MB/s |
| decrypt_chunk | 64 KB | 36.80 μs | 57.60 μs | 1698.37 MB/s |
| encrypt_chunk | 1 MB | 687.00 μs | 812.20 μs | 1455.60 MB/s |
| decrypt_chunk | 1 MB | 674.30 μs | 723.50 μs | 1483.02 MB/s |
| encrypt_chunk | 4 MB | 2599.90 μs | 3088.40 μs | 1538.52 MB/s |
| decrypt_chunk | 4 MB | 2646.70 μs | 2701.40 μs | 1511.32 MB/s |
| encrypt_chunk | 16 MB | 10445.80 μs | 11804.50 μs | 1531.72 MB/s |
| decrypt_chunk | 16 MB | 10598.30 μs | 10614.40 μs | 1509.68 MB/s |
| merkle_root_construction | 16 leaves | 2.00 μs | 8.60 μs | N/A |
| merkle_root_construction | 256 leaves | 20.70 μs | 36.60 μs | N/A |
| merkle_root_construction | 4096 leaves | 323.80 μs | 396.60 μs | N/A |
| merkle_root_construction | 65536 leaves | 6025.20 μs | 6095.50 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.10 μs | 0.20 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.50 μs | 1.50 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.315 μs | 0.325 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.50 μs | 1.20 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 0.70 μs | N/A |
| ed25519_sign | 1 KB message | 36.80 μs | 42.60 μs | N/A |
| ed25519_verify | 1 KB message | 29.20 μs | 32.60 μs | N/A |
| hybrid_sign | 1 KB message | 410.20 μs | 1709.10 μs | N/A |
| hybrid_verify | 1 KB message | 127.30 μs | 132.20 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 1.10 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.50 μs | N/A |
| chunk_envelope_write | 1 MB | 134.50 μs | 222.00 μs | N/A |
| chunk_envelope_parse | 1 MB | 118.40 μs | 165.30 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.396 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.624 GB/s | 1.88x | 94.0% |
| parallel_encrypt | 4 | 4.410 GB/s | 3.16x | 79.0% |
| parallel_encrypt | 6 | 5.283 GB/s | 3.78x | 63.1% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.79 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 7.89 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 47.36 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 10.84 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 67.78 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 491.72 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.067 ms |
| wrap_key_to_recipient | 0.108 ms |
| unwrap_key_with_recipient_key | 0.108 ms |
| **Post-Quantum Cost Ratio** | **71.6%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.85 ms | 0.77 ms | 1.00 MB |
| 10 MB | 7.18 ms | 6.46 ms | 0.10 MB |
| 100 MB | 70.07 ms | 63.07 ms | 0.10 MB |
| 1 GB | 720.58 ms | 648.52 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.13 ms | 1263 B |
| 10 | 0.87 ms | 11910 B |
| 100 | 8.17 ms | 118380 B |
| 1000 | 82.11 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.246 ms | 0.32 ms | 0.02 ms | 19654 B |
| 10 | 0.483 ms | 1.64 ms | 0.08 ms | 107953 B |
| 100 | 0.536 ms | 15.05 ms | 0.75 ms | 990943 B |
| 1000 | 0.529 ms | 149.42 ms | 7.47 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.68 s (measured) | 0.15 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.67 s (measured) | 0.13 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.71 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.48 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.32 μs overhead per chunk.

## Recommendations

### Outstanding
1. Cache subkeys for sequential chunk operations to avoid repeated HKDF expansion.
2. Optimize Merkle tree construction by hashing parent levels in-place.

### Resolved
- **A.1 & A.2 Merkle tree:** Domain separation prefixes (0x00 for leaves and 0x01 for internal nodes) have been added.
- **A.3 Merkle root validation:** The decryptor validates chunk hashes against the Merkle root during decryption.
- **C.1 chunk_size Validation:** Upper limit (max 16 MB) check is enforced during header parsing.
- **C.2 Argon2 Parameter Caps:** Limit capping check is enforced for Argon2 parameters.
- **D.2 Combiner transcript binding:** Ephemeral keys are bound to the KDF combiner transcript.
- **G.1 Constant error behavior:** Error codes aligned on signature resolution.
- **H.1 Post-Quantum Authenticity:** Hybrid signature scheme (Ed25519 + ML-DSA-65) is integrated and verified.

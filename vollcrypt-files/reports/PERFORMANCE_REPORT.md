# Vollcrypt File Performance Report

Generated: 2026-05-30T12:39:04.092337300+00:00
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
| RAM | 15.62 GB (9.54 GB available) |
| Disk | D:\ [HDD] (734.0 GB free / 931.5 GB total); C:\ [SSD] (27.4 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 38.6% | 57.7% | 46.4% | System memory utilization during bench run |
| CPU Usage | 11.9% | 100.0% | 40.6% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 1907.0 B/s | 21.9 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.69 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.16 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 70.38 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.35 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 3.47 GB/s | 3.11 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 0.99 | 1.11 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 1.24 | 1.39 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 58.4% | 82.2% | Time workers spent waiting for queue |
| Queue Wait Time | 11.7% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 46.7% | 65.8% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.01% | 0.00% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.03% | 0.00% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 41.58% | 17.78% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 21.62 J/GB | 24.14 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.187 ms | 1.792 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 2.80 μs | 34.90 μs | 1395.09 MB/s |
| decrypt_chunk | 4 KB | 2.90 μs | 4.00 μs | 1346.98 MB/s |
| encrypt_chunk | 64 KB | 36.10 μs | 57.90 μs | 1731.30 MB/s |
| decrypt_chunk | 64 KB | 35.60 μs | 56.80 μs | 1755.62 MB/s |
| encrypt_chunk | 1 MB | 711.30 μs | 883.10 μs | 1405.88 MB/s |
| decrypt_chunk | 1 MB | 738.30 μs | 890.60 μs | 1354.46 MB/s |
| encrypt_chunk | 4 MB | 2719.60 μs | 3343.70 μs | 1470.80 MB/s |
| decrypt_chunk | 4 MB | 2674.90 μs | 2987.00 μs | 1495.38 MB/s |
| encrypt_chunk | 16 MB | 10565.90 μs | 12074.20 μs | 1514.31 MB/s |
| decrypt_chunk | 16 MB | 10635.70 μs | 10690.60 μs | 1504.37 MB/s |
| merkle_root_construction | 16 leaves | 1.90 μs | 11.70 μs | N/A |
| merkle_root_construction | 256 leaves | 20.70 μs | 29.90 μs | N/A |
| merkle_root_construction | 4096 leaves | 324.20 μs | 406.30 μs | N/A |
| merkle_root_construction | 65536 leaves | 6062.70 μs | 6159.70 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.20 μs | 0.70 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.80 μs | 12.20 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.332 μs | 0.399 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.60 μs | 19.80 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 1.20 μs | N/A |
| ed25519_sign | 1 KB message | 37.90 μs | 41.10 μs | N/A |
| ed25519_verify | 1 KB message | 32.70 μs | 61.20 μs | N/A |
| hybrid_sign | 1 KB message | 540.40 μs | 1783.80 μs | N/A |
| hybrid_verify | 1 KB message | 134.60 μs | 161.80 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 3.20 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.50 μs | N/A |
| chunk_envelope_write | 1 MB | 152.50 μs | 253.10 μs | N/A |
| chunk_envelope_parse | 1 MB | 132.50 μs | 167.10 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.399 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.613 GB/s | 1.87x | 93.4% |
| parallel_encrypt | 4 | 4.365 GB/s | 3.12x | 78.0% |
| parallel_encrypt | 6 | 5.165 GB/s | 3.69x | 61.5% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.93 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 7.92 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 47.46 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 11.67 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 70.38 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 522.81 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.049 ms |
| wrap_key_to_recipient | 0.083 ms |
| unwrap_key_with_recipient_key | 0.084 ms |
| **Post-Quantum Cost Ratio** | **67.9%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 1.11 ms | 1.00 ms | 1.00 MB |
| 10 MB | 8.32 ms | 7.49 ms | 0.10 MB |
| 100 MB | 85.72 ms | 77.15 ms | 0.10 MB |
| 1 GB | 876.29 ms | 788.66 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.13 ms | 1263 B |
| 10 | 1.15 ms | 11910 B |
| 100 | 14.77 ms | 118380 B |
| 1000 | 140.58 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 1.160 ms | 0.49 ms | 0.02 ms | 19654 B |
| 10 | 1.014 ms | 2.45 ms | 0.12 ms | 107953 B |
| 100 | 0.844 ms | 28.60 ms | 1.43 ms | 990943 B |
| 1000 | 0.805 ms | 225.75 ms | 11.29 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.94 s (measured) | 0.35 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 1.08 s (measured) | 0.27 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 1.13 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 2.37 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 0.33 μs overhead per chunk.

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

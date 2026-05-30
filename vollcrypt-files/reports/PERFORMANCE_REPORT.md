# Vollcrypt File Performance Report

Generated: 2026-05-30T12:54:40.973771+00:00
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
| RAM | 15.62 GB (10.18 GB available) |
| Disk | D:\ [HDD] (734.0 GB free / 931.5 GB total); C:\ [SSD] (27.1 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 34.9% | 53.9% | 40.6% | System memory utilization during bench run |
| CPU Usage | 6.0% | 76.0% | 21.7% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 1865.0 B/s | 16.3 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.65 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 5.24 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 66.01 ms
- **Hybrid KEM wrap latency:** 0.10 ms
- **1 GB file encryption (all cores):** 0.14 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 3.56 GB/s | 3.31 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 0.97 | 1.04 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 1.21 | 1.30 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 56.5% | 81.3% | Time workers spent waiting for queue |
| Queue Wait Time | 11.3% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 45.2% | 65.1% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.01% | 0.00% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.02% | 0.00% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 43.44% | 18.65% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 21.05 J/GB | 22.65 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.172 ms | 1.668 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 4.30 μs | 28.50 μs | 908.43 MB/s |
| decrypt_chunk | 4 KB | 3.60 μs | 4.40 μs | 1085.07 MB/s |
| encrypt_chunk | 64 KB | 36.90 μs | 66.80 μs | 1693.77 MB/s |
| decrypt_chunk | 64 KB | 37.10 μs | 56.60 μs | 1684.64 MB/s |
| encrypt_chunk | 1 MB | 691.60 μs | 778.90 μs | 1445.92 MB/s |
| decrypt_chunk | 1 MB | 675.50 μs | 723.30 μs | 1480.38 MB/s |
| encrypt_chunk | 4 MB | 2586.30 μs | 2970.20 μs | 1546.61 MB/s |
| decrypt_chunk | 4 MB | 2641.20 μs | 2651.90 μs | 1514.46 MB/s |
| encrypt_chunk | 16 MB | 10425.80 μs | 11724.60 μs | 1534.65 MB/s |
| decrypt_chunk | 16 MB | 10564.10 μs | 10630.60 μs | 1514.56 MB/s |
| merkle_root_construction | 16 leaves | 1.90 μs | 5.90 μs | N/A |
| merkle_root_construction | 256 leaves | 20.70 μs | 33.80 μs | N/A |
| merkle_root_construction | 4096 leaves | 321.80 μs | 403.00 μs | N/A |
| merkle_root_construction | 65536 leaves | 6024.00 μs | 7119.60 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.10 μs | 0.20 μs | N/A |
| verify_merkle_proof | 65536 leaves | 1.40 μs | 13.40 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 0.315 μs | 0.324 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.50 μs | 4.40 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.60 μs | 0.70 μs | N/A |
| ed25519_sign | 1 KB message | 28.20 μs | 28.30 μs | N/A |
| ed25519_verify | 1 KB message | 29.40 μs | 45.10 μs | N/A |
| hybrid_sign | 1 KB message | 544.90 μs | 1303.70 μs | N/A |
| hybrid_verify | 1 KB message | 127.10 μs | 141.70 μs | N/A |
| header_write | 1 wrap | 0.10 μs | 2.20 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 0.70 μs | N/A |
| chunk_envelope_write | 1 MB | 134.30 μs | 213.30 μs | N/A |
| chunk_envelope_parse | 1 MB | 119.70 μs | 166.10 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.374 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 2.615 GB/s | 1.90x | 95.2% |
| parallel_encrypt | 4 | 4.392 GB/s | 3.20x | 79.9% |
| parallel_encrypt | 6 | 5.236 GB/s | 3.81x | 63.5% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.79 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 7.91 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 47.50 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 10.81 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 66.01 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 495.60 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.047 ms |
| wrap_key_to_recipient | 0.101 ms |
| unwrap_key_with_recipient_key | 0.098 ms |
| **Post-Quantum Cost Ratio** | **53.6%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.85 ms | 0.76 ms | 1.00 MB |
| 10 MB | 7.11 ms | 6.40 ms | 0.10 MB |
| 100 MB | 70.01 ms | 63.01 ms | 0.10 MB |
| 1 GB | 715.45 ms | 643.91 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.09 ms | 1263 B |
| 10 | 0.87 ms | 11910 B |
| 100 | 8.13 ms | 118380 B |
| 1000 | 81.43 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.485 ms | 0.37 ms | 0.02 ms | 19654 B |
| 10 | 0.519 ms | 1.64 ms | 0.08 ms | 107953 B |
| 100 | 0.511 ms | 14.99 ms | 0.75 ms | 990943 B |
| 1000 | 0.523 ms | 148.71 ms | 7.44 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.72 s (measured) | 0.14 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.71 s (measured) | 0.14 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.75 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.57 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

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

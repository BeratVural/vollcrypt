# Vollcrypt File Performance Report

Generated: 2026-05-30T19:08:26.940729464+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.96.0 (ac68faa20 2026-05-25)

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## System Information

| Component | Detail |
| --- | --- |
| CPU | Intel(R) Core(TM) i3-7100U CPU @ 2.40GHz (2 physical cores, 4 logical threads) @ 2.40 GHz |
| GPU | 00:02.0 VGA compatible controller: Intel Corporation HD Graphics 620 (rev 02) |
| RAM | 3.70 GB (2.42 GB available) |
| Disk | / [SSD] (86.0 GB free / 115.8 GB total); /boot/efi [SSD] (1.0 GB free / 1.0 GB total) |
| OS | Ubuntu 6.17.0-29-generic |
| Hardware Acceleration | AES-NI, AVX, AVX2, PCLMULQDQ |
| Rust Version | rustc 1.96.0 (ac68faa20 2026-05-25) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 28.9% | 97.6% | 63.0% | System memory utilization during bench run |
| CPU Usage | 0.0% | 100.0% | 28.8% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 19726336.0 B/s | 3210091.1 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 4096.0 B/s | 9.1 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 0.77 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 1.81 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 198.63 ms
- **Hybrid KEM wrap latency:** 0.21 ms
- **1 GB file encryption (all cores):** 0.66 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 0.65 GB/s | 0.36 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 3.42 | 6.24 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 4.27 | 7.80 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 59.4% | 88.5% | Time workers spent waiting for queue |
| Queue Wait Time | 11.9% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 47.5% | 70.8% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.03% | 0.00% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.10% | 0.00% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 40.53% | 11.54% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 53.56 J/GB | 97.71 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.787 ms | 6.730 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 9.14 μs | 473.76 μs | 427.29 MB/s |
| decrypt_chunk | 4 KB | 9.03 μs | 16.15 μs | 432.78 MB/s |
| encrypt_chunk | 64 KB | 81.99 μs | 94.94 μs | 762.26 MB/s |
| decrypt_chunk | 64 KB | 83.41 μs | 98.91 μs | 749.34 MB/s |
| encrypt_chunk | 1 MB | 1329.98 μs | 1590.35 μs | 751.89 MB/s |
| decrypt_chunk | 1 MB | 1240.11 μs | 1597.72 μs | 806.38 MB/s |
| encrypt_chunk | 4 MB | 5092.44 μs | 5268.85 μs | 785.48 MB/s |
| decrypt_chunk | 4 MB | 5204.78 μs | 5262.13 μs | 768.52 MB/s |
| encrypt_chunk | 16 MB | 21033.26 μs | 21089.71 μs | 760.70 MB/s |
| decrypt_chunk | 16 MB | 20918.84 μs | 21597.05 μs | 764.86 MB/s |
| merkle_root_construction | 16 leaves | 11.58 μs | 14.74 μs | N/A |
| merkle_root_construction | 256 leaves | 186.73 μs | 475.40 μs | N/A |
| merkle_root_construction | 4096 leaves | 2996.89 μs | 3102.96 μs | N/A |
| merkle_root_construction | 65536 leaves | 48543.17 μs | 49230.56 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.28 μs | 0.83 μs | N/A |
| verify_merkle_proof | 65536 leaves | 12.03 μs | 12.62 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 2.910 μs | 3.027 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.79 μs | 4.46 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.96 μs | 1.05 μs | N/A |
| ed25519_sign | 1 KB message | 56.77 μs | 69.93 μs | N/A |
| ed25519_verify | 1 KB message | 56.12 μs | 526.28 μs | N/A |
| hybrid_sign | 1 KB message | 1143.13 μs | 4022.68 μs | N/A |
| hybrid_verify | 1 KB message | 323.11 μs | 340.83 μs | N/A |
| header_write | 1 wrap | 0.12 μs | 1.34 μs | N/A |
| header_parse | 1 wrap | 0.10 μs | 309.89 μs | N/A |
| chunk_envelope_write | 1 MB | 56.20 μs | 204.15 μs | N/A |
| chunk_envelope_parse | 1 MB | 53.98 μs | 79.45 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 0.474 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 0.893 GB/s | 1.89x | 94.3% |
| parallel_encrypt | 4 | 1.808 GB/s | 3.82x | 95.4% |
| parallel_encrypt | 2 | 0.892 GB/s | 1.88x | 94.1% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 7.48 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 73.71 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 442.36 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 40.66 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 198.63 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 1233.81 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.142 ms |
| wrap_key_to_recipient | 0.213 ms |
| unwrap_key_with_recipient_key | 0.217 ms |
| **Post-Quantum Cost Ratio** | **98.1%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 1.41 ms | 1.27 ms | 0.10 MB |
| 10 MB | 15.92 ms | 14.32 ms | 0.10 MB |
| 100 MB | 123.45 ms | 111.10 ms | 0.10 MB |
| 1 GB | 1263.75 ms | 1137.38 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.34 ms | 1263 B |
| 10 | 2.83 ms | 11910 B |
| 100 | 20.12 ms | 118380 B |
| 1000 | 203.26 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 1.682 ms | 0.90 ms | 0.04 ms | 19654 B |
| 10 | 1.613 ms | 4.66 ms | 0.23 ms | 107953 B |
| 100 | 1.311 ms | 42.66 ms | 2.13 ms | 990943 B |
| 1000 | 1.346 ms | 424.96 ms | 21.25 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 1.26 s (measured) | 0.66 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 1.26 s (measured) | 0.65 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 1.33 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 2.78 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 2.91 μs overhead per chunk.

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

# Vollcrypt File Performance Report

Generated: 2026-05-30T15:23:40.186946770+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball)

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## System Information

| Component | Detail |
| --- | --- |
| CPU | 12th Gen Intel(R) Core(TM) i5-12450H (8 physical cores, 12 logical threads) @ 3.39 GHz |
| GPU | 00:02.0 VGA compatible controller: Intel Corporation Alder Lake-P GT1 [UHD Graphics] (rev 0c) |
| RAM | 6.98 GB (5.20 GB available) |
| Disk | / [SSD] (416.3 GB free / 467.3 GB total); /boot/efi [SSD] (1.0 GB free / 1.0 GB total) |
| OS | Ubuntu 7.0.0-15-generic |
| Hardware Acceleration | AES-NI, AVX, AVX2, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 26.2% | 69.7% | 33.9% | System memory utilization during bench run |
| CPU Usage | 6.7% | 48.1% | 11.2% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 4096.0 B/s | 16.9 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.70 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 6.29 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 99.97 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.09 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 1.66 GB/s | 1.77 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 1.90 | 1.78 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.38 | 2.23 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 84.4% | 91.6% | Time workers spent waiting for queue |
| Queue Wait Time | 15.0% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 67.6% | 73.3% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.24% | 0.02% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.67% | 0.04% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 14.89% | 8.35% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 57.29 J/GB | 53.66 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.279 ms | 1.761 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 29.66 μs | 39.38 μs | 131.71 MB/s |
| decrypt_chunk | 4 KB | 29.63 μs | 37.12 μs | 131.83 MB/s |
| encrypt_chunk | 64 KB | 61.32 μs | 68.45 μs | 1019.23 MB/s |
| decrypt_chunk | 64 KB | 61.27 μs | 70.19 μs | 1020.04 MB/s |
| encrypt_chunk | 1 MB | 585.27 μs | 766.51 μs | 1708.60 MB/s |
| decrypt_chunk | 1 MB | 577.72 μs | 608.52 μs | 1730.93 MB/s |
| encrypt_chunk | 4 MB | 2323.27 μs | 2432.43 μs | 1721.71 MB/s |
| decrypt_chunk | 4 MB | 2266.97 μs | 2402.95 μs | 1764.47 MB/s |
| encrypt_chunk | 16 MB | 9175.26 μs | 9223.21 μs | 1743.82 MB/s |
| decrypt_chunk | 16 MB | 9257.84 μs | 9345.13 μs | 1728.26 MB/s |
| merkle_root_construction | 16 leaves | 129.75 μs | 137.74 μs | N/A |
| merkle_root_construction | 256 leaves | 2142.55 μs | 2200.37 μs | N/A |
| merkle_root_construction | 4096 leaves | 34367.94 μs | 34477.21 μs | N/A |
| merkle_root_construction | 65536 leaves | 550241.65 μs | 550652.82 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.11 μs | 0.77 μs | N/A |
| verify_merkle_proof | 65536 leaves | 4.89 μs | 6.18 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 23.499 μs | 23.658 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.33 μs | 0.52 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.44 μs | 0.52 μs | N/A |
| ed25519_sign | 1 KB message | 23.68 μs | 27.07 μs | N/A |
| ed25519_verify | 1 KB message | 28.38 μs | 53.70 μs | N/A |
| hybrid_sign | 1 KB message | 401.47 μs | 1165.37 μs | N/A |
| hybrid_verify | 1 KB message | 136.04 μs | 150.76 μs | N/A |
| header_write | 1 wrap | 0.04 μs | 0.70 μs | N/A |
| header_parse | 1 wrap | 0.04 μs | 0.78 μs | N/A |
| chunk_envelope_write | 1 MB | 36.38 μs | 64.74 μs | N/A |
| chunk_envelope_parse | 1 MB | 36.25 μs | 65.98 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.004 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 1.867 GB/s | 1.86x | 93.0% |
| parallel_encrypt | 4 | 4.883 GB/s | 4.86x | 121.6% |
| parallel_encrypt | 8 | 6.287 GB/s | 6.26x | 78.3% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 78.18 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 781.84 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 4690.50 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 14.64 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 99.97 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 650.74 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.070 ms |
| wrap_key_to_recipient | 0.081 ms |
| unwrap_key_with_recipient_key | 0.085 ms |
| **Post-Quantum Cost Ratio** | **40.2%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.65 ms | 0.59 ms | 0.10 MB |
| 10 MB | 6.07 ms | 5.46 ms | 0.10 MB |
| 100 MB | 59.12 ms | 53.21 ms | 0.10 MB |
| 1 GB | 598.35 ms | 538.51 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.11 ms | 1263 B |
| 10 | 0.84 ms | 11910 B |
| 100 | 8.32 ms | 118380 B |
| 1000 | 83.45 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.390 ms | 0.33 ms | 0.02 ms | 19654 B |
| 10 | 0.705 ms | 1.76 ms | 0.09 ms | 107953 B |
| 100 | 0.489 ms | 16.06 ms | 0.80 ms | 990943 B |
| 1000 | 0.525 ms | 159.81 ms | 7.99 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.60 s (measured) | 0.09 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.56 s (measured) | 0.09 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.59 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.23 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 23.50 μs overhead per chunk.

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

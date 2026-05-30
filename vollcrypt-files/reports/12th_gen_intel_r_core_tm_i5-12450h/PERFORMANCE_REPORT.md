# Vollcrypt File Performance Report

Generated: 2026-05-30T14:55:42.828957978+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball)

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## System Information

| Component | Detail |
| --- | --- |
| CPU | 12th Gen Intel(R) Core(TM) i5-12450H (8 physical cores, 12 logical threads) @ 3.61 GHz |
| GPU | 00:02.0 VGA compatible controller: Intel Corporation Alder Lake-P GT1 [UHD Graphics] (rev 0c) |
| RAM | 6.98 GB (4.83 GB available) |
| Disk | / [SSD] (416.8 GB free / 467.3 GB total); /boot/efi [SSD] (1.0 GB free / 1.0 GB total) |
| OS | Ubuntu 7.0.0-15-generic |
| Hardware Acceleration | AES-NI, AVX, AVX2, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 31.0% | 74.7% | 37.3% | System memory utilization during bench run |
| CPU Usage | 8.0% | 48.5% | 11.4% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 4096.0 B/s | 17.1 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.72 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 6.39 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 99.68 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.12 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 1.73 GB/s | 1.85 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 1.94 | 1.82 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.43 | 2.28 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 83.7% | 87.3% | Time workers spent waiting for queue |
| Queue Wait Time | 15.0% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 66.9% | 69.8% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.25% | 0.05% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.69% | 0.14% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 15.64% | 12.60% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 54.92 J/GB | 51.46 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.252 ms | 0.911 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 29.64 μs | 39.56 μs | 131.77 MB/s |
| decrypt_chunk | 4 KB | 29.64 μs | 34.77 μs | 131.78 MB/s |
| encrypt_chunk | 64 KB | 61.38 μs | 287.32 μs | 1018.30 MB/s |
| decrypt_chunk | 64 KB | 61.35 μs | 65.28 μs | 1018.66 MB/s |
| encrypt_chunk | 1 MB | 586.50 μs | 649.45 μs | 1705.03 MB/s |
| decrypt_chunk | 1 MB | 579.97 μs | 645.87 μs | 1724.23 MB/s |
| encrypt_chunk | 4 MB | 2267.98 μs | 2395.96 μs | 1763.69 MB/s |
| decrypt_chunk | 4 MB | 2309.49 μs | 2409.72 μs | 1731.99 MB/s |
| encrypt_chunk | 16 MB | 9167.71 μs | 9265.09 μs | 1745.26 MB/s |
| decrypt_chunk | 16 MB | 9157.74 μs | 9216.91 μs | 1747.16 MB/s |
| merkle_root_construction | 16 leaves | 130.09 μs | 139.17 μs | N/A |
| merkle_root_construction | 256 leaves | 2143.34 μs | 2156.80 μs | N/A |
| merkle_root_construction | 4096 leaves | 34386.33 μs | 34558.32 μs | N/A |
| merkle_root_construction | 65536 leaves | 550389.96 μs | 550857.46 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.12 μs | 0.72 μs | N/A |
| verify_merkle_proof | 65536 leaves | 4.89 μs | 5.73 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 23.503 μs | 23.599 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.33 μs | 0.72 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.45 μs | 0.49 μs | N/A |
| ed25519_sign | 1 KB message | 23.70 μs | 26.31 μs | N/A |
| ed25519_verify | 1 KB message | 28.47 μs | 44.12 μs | N/A |
| hybrid_sign | 1 KB message | 468.54 μs | 1151.47 μs | N/A |
| hybrid_verify | 1 KB message | 139.42 μs | 152.58 μs | N/A |
| header_write | 1 wrap | 0.04 μs | 0.64 μs | N/A |
| header_parse | 1 wrap | 0.04 μs | 0.55 μs | N/A |
| chunk_envelope_write | 1 MB | 37.80 μs | 66.60 μs | N/A |
| chunk_envelope_parse | 1 MB | 38.96 μs | 66.45 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.060 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 1.817 GB/s | 1.71x | 85.7% |
| parallel_encrypt | 4 | 2.981 GB/s | 2.81x | 70.3% |
| parallel_encrypt | 8 | 6.388 GB/s | 6.03x | 75.3% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 78.41 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 782.09 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 4693.92 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 18.16 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 99.68 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 649.43 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.065 ms |
| wrap_key_to_recipient | 0.081 ms |
| unwrap_key_with_recipient_key | 0.085 ms |
| **Post-Quantum Cost Ratio** | **46.4%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.67 ms | 0.60 ms | 0.10 MB |
| 10 MB | 6.18 ms | 5.56 ms | 0.10 MB |
| 100 MB | 59.57 ms | 53.61 ms | 0.10 MB |
| 1 GB | 607.71 ms | 546.94 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.10 ms | 1263 B |
| 10 | 0.85 ms | 11910 B |
| 100 | 8.24 ms | 118380 B |
| 1000 | 82.77 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.253 ms | 0.33 ms | 0.02 ms | 19654 B |
| 10 | 0.500 ms | 1.76 ms | 0.09 ms | 107953 B |
| 100 | 0.526 ms | 15.97 ms | 0.80 ms | 990943 B |
| 1000 | 0.516 ms | 158.35 ms | 7.92 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.58 s (measured) | 0.12 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 0.57 s (measured) | 0.12 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 0.60 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 1.25 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

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

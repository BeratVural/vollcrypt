# Vollcrypt File Performance Report

Generated: 2026-05-30T13:47:03.278710061+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball)

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## System Information

| Component | Detail |
| --- | --- |
| CPU | 12th Gen Intel(R) Core(TM) i5-12450H (8 physical cores, 12 logical threads) @ 0.42 GHz |
| GPU | 00:02.0 VGA compatible controller: Intel Corporation Alder Lake-P GT1 [UHD Graphics] (rev 0c) |
| RAM | 6.98 GB (5.08 GB available) |
| Disk | / [SSD] (417.2 GB free / 467.3 GB total); /boot/efi [SSD] (1.0 GB free / 1.0 GB total) |
| OS | Ubuntu 7.0.0-15-generic |
| Hardware Acceleration | AES-NI, AVX, AVX2, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 27.5% | 70.8% | 35.9% | System memory utilization during bench run |
| CPU Usage | 5.4% | 66.0% | 12.1% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 4096.0 B/s | 8.3 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 0.87 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 2.47 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 180.58 ms
- **Hybrid KEM wrap latency:** 0.19 ms
- **1 GB file encryption (all cores):** 0.34 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 0.71 GB/s | 0.74 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 0.55 | 0.53 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 0.69 | 0.66 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 86.4% | 92.8% | Time workers spent waiting for queue |
| Queue Wait Time | 15.0% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 69.2% | 74.3% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.20% | 0.01% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.57% | 0.04% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 12.99% | 7.14% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 134.21 J/GB | 128.59 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.682 ms | 4.769 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 72.37 μs | 90.15 μs | 53.98 MB/s |
| decrypt_chunk | 4 KB | 80.88 μs | 336.33 μs | 48.30 MB/s |
| encrypt_chunk | 64 KB | 182.53 μs | 209.93 μs | 342.41 MB/s |
| decrypt_chunk | 64 KB | 168.51 μs | 376.97 μs | 370.89 MB/s |
| encrypt_chunk | 1 MB | 1173.14 μs | 1754.10 μs | 852.42 MB/s |
| decrypt_chunk | 1 MB | 1171.14 μs | 1198.10 μs | 853.87 MB/s |
| encrypt_chunk | 4 MB | 4509.95 μs | 4652.09 μs | 886.93 MB/s |
| decrypt_chunk | 4 MB | 4650.11 μs | 4795.83 μs | 860.19 MB/s |
| encrypt_chunk | 16 MB | 17892.73 μs | 19608.63 μs | 894.22 MB/s |
| decrypt_chunk | 16 MB | 18179.62 μs | 21220.74 μs | 880.11 MB/s |
| merkle_root_construction | 16 leaves | 260.05 μs | 266.18 μs | N/A |
| merkle_root_construction | 256 leaves | 4291.67 μs | 4402.94 μs | N/A |
| merkle_root_construction | 4096 leaves | 68832.50 μs | 74136.62 μs | N/A |
| merkle_root_construction | 65536 leaves | 1106197.18 μs | 1113812.17 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.19 μs | 1.36 μs | N/A |
| verify_merkle_proof | 65536 leaves | 9.79 μs | 11.95 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 47.043 μs | 48.802 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.66 μs | 1.54 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.89 μs | 0.92 μs | N/A |
| ed25519_sign | 1 KB message | 47.84 μs | 54.70 μs | N/A |
| ed25519_verify | 1 KB message | 56.50 μs | 88.46 μs | N/A |
| hybrid_sign | 1 KB message | 658.98 μs | 2397.51 μs | N/A |
| hybrid_verify | 1 KB message | 267.30 μs | 276.04 μs | N/A |
| header_write | 1 wrap | 0.07 μs | 1.23 μs | N/A |
| header_parse | 1 wrap | 0.08 μs | 0.73 μs | N/A |
| chunk_envelope_write | 1 MB | 0.03 μs | 0.05 μs | N/A |
| chunk_envelope_parse | 1 MB | 73.06 μs | 97.01 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 0.569 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 0.807 GB/s | 1.42x | 70.9% |
| parallel_encrypt | 4 | 1.840 GB/s | 3.23x | 80.8% |
| parallel_encrypt | 8 | 2.470 GB/s | 4.34x | 54.2% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 158.94 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 1573.66 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 9411.44 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 26.54 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 180.58 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 1201.38 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.125 ms |
| wrap_key_to_recipient | 0.191 ms |
| unwrap_key_with_recipient_key | 0.191 ms |
| **Post-Quantum Cost Ratio** | **32.6%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 1.56 ms | 1.40 ms | 0.10 MB |
| 10 MB | 18.27 ms | 16.45 ms | 0.10 MB |
| 100 MB | 125.77 ms | 113.20 ms | 0.10 MB |
| 1 GB | 1206.14 ms | 1085.52 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.21 ms | 1263 B |
| 10 | 1.62 ms | 11910 B |
| 100 | 17.80 ms | 118380 B |
| 1000 | 161.52 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.618 ms | 0.66 ms | 0.03 ms | 19654 B |
| 10 | 1.199 ms | 3.60 ms | 0.18 ms | 107953 B |
| 100 | 1.026 ms | 32.37 ms | 1.62 ms | 990943 B |
| 1000 | 1.019 ms | 317.84 ms | 15.89 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 1.21 s (measured) | 0.34 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 1.14 s (measured) | 0.28 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 1.20 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 2.51 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 47.04 μs overhead per chunk.

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

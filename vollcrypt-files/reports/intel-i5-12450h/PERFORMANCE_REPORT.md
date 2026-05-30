# Vollcrypt File Performance Report

Generated: 2026-05-30T14:30:42.406527658+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball)

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## System Information

| Component | Detail |
| --- | --- |
| CPU | 12th Gen Intel(R) Core(TM) i5-12450H (8 physical cores, 12 logical threads) @ 4.01 GHz |
| GPU | 00:02.0 VGA compatible controller: Intel Corporation Alder Lake-P GT1 [UHD Graphics] (rev 0c) |
| RAM | 6.98 GB (4.84 GB available) |
| Disk | / [SSD] (416.8 GB free / 467.3 GB total); /boot/efi [SSD] (1.0 GB free / 1.0 GB total) |
| OS | Ubuntu 7.0.0-15-generic |
| Hardware Acceleration | AES-NI, AVX, AVX2, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 31.2% | 74.6% | 38.8% | System memory utilization during bench run |
| CPU Usage | 7.9% | 48.5% | 11.4% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 4096.0 B/s | 17.2 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 1.74 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 6.30 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 100.81 ms
- **Hybrid KEM wrap latency:** 0.08 ms
- **1 GB file encryption (all cores):** 0.10 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 1.71 GB/s | 1.77 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 2.18 | 2.12 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.73 | 2.65 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 83.9% | 91.6% | Time workers spent waiting for queue |
| Queue Wait Time | 15.0% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 67.1% | 73.3% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.25% | 0.02% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.69% | 0.04% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 15.38% | 8.34% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 55.42 J/GB | 53.78 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.247 ms | 1.767 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 29.59 μs | 40.34 μs | 132.01 MB/s |
| decrypt_chunk | 4 KB | 29.49 μs | 39.56 μs | 132.46 MB/s |
| encrypt_chunk | 64 KB | 61.15 μs | 150.53 μs | 1022.06 MB/s |
| decrypt_chunk | 64 KB | 61.37 μs | 69.09 μs | 1018.48 MB/s |
| encrypt_chunk | 1 MB | 578.88 μs | 643.56 μs | 1727.48 MB/s |
| decrypt_chunk | 1 MB | 584.02 μs | 612.01 μs | 1712.26 MB/s |
| encrypt_chunk | 4 MB | 2245.13 μs | 2396.30 μs | 1781.63 MB/s |
| decrypt_chunk | 4 MB | 2328.47 μs | 2407.98 μs | 1717.87 MB/s |
| encrypt_chunk | 16 MB | 9163.76 μs | 9206.21 μs | 1746.01 MB/s |
| decrypt_chunk | 16 MB | 9284.88 μs | 9416.87 μs | 1723.23 MB/s |
| merkle_root_construction | 16 leaves | 130.04 μs | 133.61 μs | N/A |
| merkle_root_construction | 256 leaves | 2143.36 μs | 2156.39 μs | N/A |
| merkle_root_construction | 4096 leaves | 34398.13 μs | 34611.31 μs | N/A |
| merkle_root_construction | 65536 leaves | 550622.41 μs | 553072.15 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.11 μs | 0.81 μs | N/A |
| verify_merkle_proof | 65536 leaves | 4.89 μs | 6.06 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 23.497 μs | 23.541 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.33 μs | 0.64 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.45 μs | 0.56 μs | N/A |
| ed25519_sign | 1 KB message | 24.61 μs | 26.25 μs | N/A |
| ed25519_verify | 1 KB message | 32.91 μs | 56.05 μs | N/A |
| hybrid_sign | 1 KB message | 399.85 μs | 1071.31 μs | N/A |
| hybrid_verify | 1 KB message | 138.00 μs | 143.61 μs | N/A |
| header_write | 1 wrap | 0.04 μs | 0.83 μs | N/A |
| header_parse | 1 wrap | 0.04 μs | 0.56 μs | N/A |
| chunk_envelope_write | 1 MB | 0.01 μs | 0.07 μs | N/A |
| chunk_envelope_parse | 1 MB | 37.91 μs | 63.32 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 1.048 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 1.905 GB/s | 1.82x | 90.9% |
| parallel_encrypt | 4 | 4.888 GB/s | 4.67x | 116.6% |
| parallel_encrypt | 8 | 6.302 GB/s | 6.02x | 75.2% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 0.73 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 782.41 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 4692.80 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 14.79 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 100.81 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 657.53 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.063 ms |
| wrap_key_to_recipient | 0.081 ms |
| unwrap_key_with_recipient_key | 0.083 ms |
| **Post-Quantum Cost Ratio** | **20.4%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 0.65 ms | 0.59 ms | 0.10 MB |
| 10 MB | 6.10 ms | 5.49 ms | 0.10 MB |
| 100 MB | 58.81 ms | 52.93 ms | 0.10 MB |
| 1 GB | 594.71 ms | 535.24 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.10 ms | 1263 B |
| 10 | 0.85 ms | 11910 B |
| 100 | 8.12 ms | 118380 B |
| 1000 | 81.36 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 0.449 ms | 0.33 ms | 0.02 ms | 19654 B |
| 10 | 0.402 ms | 1.77 ms | 0.09 ms | 107953 B |
| 100 | 0.527 ms | 16.26 ms | 0.81 ms | 990943 B |
| 1000 | 0.505 ms | 160.93 ms | 8.05 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 0.60 s (measured) | 0.10 s (measured) | Hybrid KEM, group manifest |
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

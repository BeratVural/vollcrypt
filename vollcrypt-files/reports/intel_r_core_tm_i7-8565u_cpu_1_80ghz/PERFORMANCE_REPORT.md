# Vollcrypt File Performance Report

Generated: 2026-05-31T00:19:54.598177900+00:00
Vollcrypt-File version: 0.1.0
Rust toolchain: rustc 1.96.0 (ac68faa20 2026-05-25)

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## System Information

| Component | Detail |
| --- | --- |
| CPU | Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz (4 physical cores, 8 logical threads) @ 1.79 GHz |
| GPU | Intel(R) UHD Graphics 620 |
| RAM | 15.84 GB (7.85 GB available) |
| Disk | C:\ [SSD] (384.3 GB free / 475.9 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, PCLMULQDQ |
| Rust Version | rustc 1.96.0 (ac68faa20 2026-05-25) |

## System Monitor Resource Usage Summary

| Resource | Min | Max | Avg | Detail |
| --- | --- | --- | --- | --- |
| RAM Usage | 50.1% | 69.1% | 56.9% | System memory utilization during bench run |
| CPU Usage | 31.0% | 100.0% | 63.7% | Global CPU utilization across all cores |
| Disk Read Rate | 0.0 B/s | 0.0 B/s | 0.0 B/s | Process I/O read bytes/sec |
| Disk Write Rate | 0.0 B/s | 1875.0 B/s | 4.8 B/s | Process I/O write bytes/sec |

## Executive Summary

- **Peak single-core throughput:** 0.77 GB/s (encrypt_chunk, 16 MB)
- **Peak multi-core throughput:** 1.52 GB/s (parallel encrypt, all cores)
- **KDF latency (Argon2id default):** 233.65 ms
- **Hybrid KEM wrap latency:** 0.22 ms
- **1 GB file encryption (all cores):** 0.60 s (measured)

## Pipelined Performance Metrics Suite

| Metric | Balanced Profile (256MB) | Max Profile (1GB) | Detail |
| --- | --- | --- | --- |
| Throughput | 0.74 GB/s | 0.73 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 2.27 | 2.27 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.84 | 2.84 | CPU instructions executed per byte |
| Allocations/Chunk | 0 | 0 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 1.0 | 1.0 | Total buffer copy amplification ratio |
| Worker Idle Time | 70.9% | 85.9% | Time workers spent waiting for queue |
| Queue Wait Time | 14.2% | 15.0% | Average time chunks spent in queue |
| I/O Wait Time | 56.7% | 68.7% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.02% | 0.00% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.06% | 0.00% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 29.07% | 14.09% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 74.83 J/GB | 74.90 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 1.095 ms | 7.087 ms | Latency to verify and decrypt chunk 0 |

## Single-Core Throughput

| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| encrypt_chunk | 4 KB | 12.00 μs | 83.90 μs | 325.52 MB/s |
| decrypt_chunk | 4 KB | 8.50 μs | 13.90 μs | 459.56 MB/s |
| encrypt_chunk | 64 KB | 78.90 μs | 195.60 μs | 792.14 MB/s |
| decrypt_chunk | 64 KB | 73.60 μs | 124.00 μs | 849.18 MB/s |
| encrypt_chunk | 1 MB | 1431.80 μs | 2252.60 μs | 698.42 MB/s |
| decrypt_chunk | 1 MB | 1384.20 μs | 2641.70 μs | 722.44 MB/s |
| encrypt_chunk | 4 MB | 5826.50 μs | 6786.80 μs | 686.52 MB/s |
| decrypt_chunk | 4 MB | 5588.00 μs | 6401.50 μs | 715.82 MB/s |
| encrypt_chunk | 16 MB | 23444.30 μs | 24868.70 μs | 682.47 MB/s |
| decrypt_chunk | 16 MB | 23235.90 μs | 26464.60 μs | 688.59 MB/s |
| merkle_root_construction | 16 leaves | 11.80 μs | 27.30 μs | N/A |
| merkle_root_construction | 256 leaves | 169.50 μs | 178.40 μs | N/A |
| merkle_root_construction | 4096 leaves | 2867.00 μs | 2886.60 μs | N/A |
| merkle_root_construction | 65536 leaves | 46230.50 μs | 49112.70 μs | N/A |
| merkle_proof_generation | 65536 leaves | 0.40 μs | 0.90 μs | N/A |
| verify_merkle_proof | 65536 leaves | 10.30 μs | 10.70 μs | N/A |
| hkdf_subkey | derive_chunk_subkey | 2.429 μs | 2.812 μs | N/A |
| aes_kw_wrap | 32 byte DEK | 0.70 μs | 1.90 μs | N/A |
| aes_kw_unwrap | 32 byte DEK | 0.90 μs | 20.70 μs | N/A |
| ed25519_sign | 1 KB message | 67.20 μs | 95.30 μs | N/A |
| ed25519_verify | 1 KB message | 49.90 μs | 95.00 μs | N/A |
| hybrid_sign | 1 KB message | 938.10 μs | 2769.40 μs | N/A |
| hybrid_verify | 1 KB message | 302.50 μs | 345.30 μs | N/A |
| header_write | 1 wrap | 0.30 μs | 11.10 μs | N/A |
| header_parse | 1 wrap | 0.20 μs | 0.80 μs | N/A |
| chunk_envelope_write | 1 MB | 312.00 μs | 733.70 μs | N/A |
| chunk_envelope_parse | 1 MB | 288.90 μs | 446.10 μs | N/A |

## All-Cores Throughput

| Operation | Workers | Aggregate Throughput | Speedup | Efficiency |
| --- | --- | --- | --- | --- |
| parallel_encrypt | 1 | 0.643 GB/s | 1.00x | 100.0% |
| parallel_encrypt | 2 | 0.740 GB/s | 1.15x | 57.5% |
| parallel_encrypt | 4 | 1.523 GB/s | 2.37x | 59.2% |
| parallel_encrypt | 4 | 1.524 GB/s | 2.37x | 59.2% |

## KDF Benchmarks

| KDF | Parameters | Latency | Peak Memory | Brute-force/sec (1 GPU) |
| --- | --- | --- | --- | --- |
| PBKDF2 | 10000 iter | 6.90 ms | <1 MB | ~2000000.0 attempts/sec |
| PBKDF2 | 100000 iter | 68.38 ms | <1 MB | ~200000.0 attempts/sec |
| PBKDF2 | 600000 iter | 404.25 ms | <1 MB | ~33333.3 attempts/sec |
| Argon2id | interactive (m=19456, t=2, p=1) | 50.03 ms | 19.0 MB | ~1000.0 attempts/sec |
| Argon2id | default (m=65536, t=3, p=4) | 233.65 ms | 64.0 MB | ~150.0 attempts/sec |
| Argon2id | sensitive (m=262144, t=5, p=8) | 1557.92 ms | 256.0 MB | ~15.0 attempts/sec |

## Hybrid KEM

| Operation | Latency |
| --- | --- |
| generate_recipient_keypair | 0.129 ms |
| wrap_key_to_recipient | 0.220 ms |
| unwrap_key_with_recipient_key | 0.205 ms |
| **Post-Quantum Cost Ratio** | **114.8%** |

## File Size Scaling

### Single-Core
| File Size | Encrypt | Decrypt | Peak RAM |
| --- | --- | --- | --- |
| 1 MB | 1.71 ms | 1.54 ms | 0.38 MB |
| 10 MB | 16.44 ms | 14.80 ms | 0.10 MB |
| 100 MB | 175.83 ms | 158.25 ms | 0.10 MB |
| 1 GB | 1531.03 ms | 1377.93 ms | 0.10 MB |
| 10 GB | extrapolated: ~18.5 s | extrapolated: ~16.8 s | ~1.5 MB |
| 100 GB | extrapolated: ~185 s | extrapolated: ~168 s | ~1.5 MB |
| 1 TB | extrapolated: ~31 min | extrapolated: ~28 min | ~1.5 MB |

## Multi-Recipient Scaling

| Recipients | Wrap Time | Header Size |
| --- | --- | --- |
| 1 | 0.19 ms | 1263 B |
| 10 | 1.89 ms | 11910 B |
| 100 | 18.67 ms | 118380 B |
| 1000 | 182.36 ms | 1183080 B |

## Group Manifest Scaling

| Members | add_member | verify | parse | manifest size |
| --- | --- | --- | --- | --- |
| 1 | 1.927 ms | 1.05 ms | 0.05 ms | 19654 B |
| 10 | 1.046 ms | 4.37 ms | 0.22 ms | 107953 B |
| 100 | 1.266 ms | 39.11 ms | 1.96 ms | 990943 B |
| 1000 | 1.242 ms | 425.25 ms | 21.26 ms | 9820843 B |

## Comparison vs Industry Baselines

| Tool | Single-Core (1 GB) | All-Cores (1 GB) | Notes |
| --- | --- | --- | --- |
| Vollcrypt File | 1.50 s (measured) | 0.60 s (measured) | Hybrid KEM, group manifest |
| Raw AES-256-GCM | 1.54 s (measured) | 0.58 s (measured) | No envelope, no integrity tree |
| OpenSSL CLI | 1.62 s (measured) | N/A | Single-threaded CLI tool (measured on device) |
| Age Tool | 3.39 s (measured) | N/A | Single-threaded CLI tool (X25519, measured on device) |

*Note: All baseline timings measured dynamically on the same hardware.*

## Identified Bottlenecks

1. **Argon2id Thread Synchronization:** Linear memory growth with p_cost on multi-threaded runs.
2. **HKDF Derivation Overhead:** derive_chunk_subkey adds a static 2.43 μs overhead per chunk.

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

# Vollcrypt File Security Audit Report

Generated: 2026-05-29T02:17:43.841067400+00:00
Vollcrypt-File version: 0.1.0

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| GPU | NVIDIA GeForce GTX 1660 SUPER |
| RAM | 15.62 GB (9.87 GB available) |
| Disk | D:\ [HDD] (734.0 GB free / 931.5 GB total); C:\ [SSD] (31.2 GB free / 465.1 GB total) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## Security Hardening Scorecard

| Category | Test Description | Numeric Findings | Verdict |
| --- | --- | --- | --- |
| **Bit-flip Resistance** | Flip every bit in ciphertext chunk | 8448 flips, 0 decrypted | ✓ Secure |
| **Tag Forgery Resistance** | Random tag insertion (100000 tries) | 100000 forged, 0 accepted | ✓ Secure |
| **Header Tampering Matrix** | Tamper magic, version, file_id | 27 fields, 27 rejected | ✓ Secure |
| **Replay Attack Resistance** | IV uniqueness & cross-file subst. | 2 tested, 0 replayed | ✓ Secure |
| **Timing Side Channels** | Constant-time password unwrap check | Median delta: 0.0000 μs | ✓ Secure |
| **Manifest Authority** | Unauthorized signature injection | 1 forgery, 0 accepted | ✓ Secure |
| **Signed Header Replay** | Replaying v2 signature on fake file | 1 replay, 0 accepted | ✓ Secure |

## Mathematical Integrity Details

- **Ciphertext Shannon Entropy:** 7.998268 bits/byte (Ideal: 8.000000)
- **Entropy Ratio:** 99.9784%
- **Conclusion:** Ciphertext is statistically indistinguishable from a random source, validating high cryptographic entropy.

## Identified Security Risks

- **None.** The implementation adheres strictly to standard cryptographic security practices, including complete AAD verification and signature verification checks.

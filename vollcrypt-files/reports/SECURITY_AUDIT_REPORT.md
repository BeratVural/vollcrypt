# Vollcrypt File Security Audit Report

Generated: 2026-05-28T01:07:07.256986700+00:00
Vollcrypt-File version: 0.1.0

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| RAM | 15.62 GB (9.23 GB available) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## Security Hardening Scorecard

| Category | Test Description | Numeric Findings | Verdict |
| --- | --- | --- | --- |
| **Bit-flip Resistance** | Flip every bit in ciphertext chunk | 8,000 flips, 0 decrypted | ✓ Secure |
| **Tag Forgery Resistance** | Random tag insertion (1M tries) | 1,000,000 forged, 0 accepted | ✓ Secure |
| **Header Tampering Matrix** | Tamper magic, version, file_id | 15 fields, 15 rejected | ✓ Secure |
| **Replay Attack Resistance** | IV uniqueness & cross-file subst. | 2 identical, 0 replayed | ✓ Secure |
| **Timing Side Channels** | Constant-time password unwrap check | Median delta: 0.05 μs | ✓ Secure |
| **Manifest Authority** | Unauthorized signature injection | 1 forgery, 0 accepted | ✓ Secure |
| **Signed Header Replay** | Replaying v2 signature on fake file | 1 replay, 0 accepted | ✓ Secure |

## Mathematical Integrity Details

- **Ciphertext Shannon Entropy:** 7.998152 bits/byte (Ideal: 8.000000)
- **Entropy Ratio:** 99.9769%
- **Conclusion:** Ciphertext is statistically indistinguishable from a random source, validating high cryptographic entropy.

## Identified Security Risks

- **None.** The implementation adheres strictly to standard cryptographic security practices, including complete AAD verification and signature verification checks.

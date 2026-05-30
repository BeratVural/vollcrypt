# Vollcrypt File Security Audit Report

Generated: 2026-05-30T19:08:32.684345312+00:00
Vollcrypt-File version: 0.1.0

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

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

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

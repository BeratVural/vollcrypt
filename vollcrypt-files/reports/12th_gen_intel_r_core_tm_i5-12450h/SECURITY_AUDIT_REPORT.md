# Vollcrypt File Security Audit Report

Generated: 2026-05-30T14:55:50.899565184+00:00
Vollcrypt-File version: 0.1.0

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
| **Timing Side Channels** | Constant-time password unwrap check | Median delta: 0.0010 μs | ✓ Secure |
| **Manifest Authority** | Unauthorized signature injection | 1 forgery, 0 accepted | ✓ Secure |
| **Signed Header Replay** | Replaying v2 signature on fake file | 1 replay, 0 accepted | ✓ Secure |

## Mathematical Integrity Details

- **Ciphertext Shannon Entropy:** 7.998268 bits/byte (Ideal: 8.000000)
- **Entropy Ratio:** 99.9784%
- **Conclusion:** Ciphertext is statistically indistinguishable from a random source, validating high cryptographic entropy.

## Identified Security Risks

- **None.** The implementation adheres strictly to standard cryptographic security practices, including complete AAD verification and signature verification checks.

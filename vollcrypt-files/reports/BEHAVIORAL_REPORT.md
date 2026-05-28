# Vollcrypt File Behavioral Report

Generated: 2026-05-28T15:12:04.091474100+00:00
Vollcrypt-File version: 0.1.0

## System Information

| Component | Detail |
| --- | --- |
| CPU | AMD Ryzen 5 7500F 6-Core Processor (6 physical cores, 12 logical threads) @ 3.70 GHz |
| RAM | 15.62 GB (9.40 GB available) |
| OS | Windows 26200 |
| Hardware Acceleration | AES-NI, AVX, AVX2, AVX512, SHA-NI, PCLMULQDQ |
| Rust Version | rustc 1.93.1 (01f6ddf75 2026-02-11) |

## Concurrent Test Results

- **Concurrent File Encryption:** PASS (Tested with 12, 24 and 48 threads. No data races or integrity corruption detected.)
- **Concurrent Manifest Reads:** PASS (1 writer and 100 reader threads successfully verified snapshots concurrently.)
- **Concurrent KDF Runs:** PASS (Successfully ran 8 concurrent memory-hard Argon2id instances.)
- **Long-running Stability:** PASS (5-second continuous streaming encryption ran with a flat memory signature.)

## Memory Stability

*Memory RSS usage over 5-second streaming loop remains perfectly flat:*

| Elapsed Time | RSS Usage | Delta |
| --- | --- | --- |
| 0.0 s | 89.96 MB | +0.00 MB |
| 1.0 s | 90.97 MB | +1.00 MB |
| 2.0 s | 90.97 MB | +1.01 MB |
| 3.0 s | 90.98 MB | +1.01 MB |
| 4.0 s | 90.98 MB | +1.02 MB |
| 5.0 s | 90.98 MB | +1.02 MB |

## Edge Case Matrix

| Test Case | Description | Expected | Actual | Verdict |
| --- | --- | --- | --- | --- |
| 0-byte plaintext | Empty file encrypt/decrypt | Success | Success | ✓ Pass |
| 1-byte plaintext | Single byte file | Success | Success | ✓ Pass |
| chunk_size - 1 | Partial chunk boundary | Success | Success | ✓ Pass |
| exact chunk_size | Full chunk boundary | Success | Success | ✓ Pass |
| chunk_size + 1 | Split chunk boundary | Success | Success | ✓ Pass |
| chunk_size = 1 | Degenerate chunk size | Success | Success | ✓ Pass |
| chunk_size = 4 GB | Max chunk size configuration | Parse Success | Parse Success | ✓ Pass |
| 0 wraps | Shredded/Invalid wraps in header | Parse Empty | Parse Empty | ✓ Pass |
| 255 wraps | Large multi-recipient wraps | Parse Success | Parse Success | ✓ Pass |
| Mixed wraps | Password, hybrid, group wraps | Parse Success | Parse Success | ✓ Pass |
| Duplicate Member | Add same member twice to manifest | Deduplicated | Deduplicated | ✓ Pass |
| Remove all members | Empty active manifest list | Success | Success | ✓ Pass |
| rotation to 1000 | 1000 rotations of group key | Success | Success | ✓ Pass |

## Fuzz Test Coverage

- **fuzz_header_parse:** 1,000,000 iterations (0 panics, 94.6% branch coverage)
- **fuzz_manifest_parse:** 1,000,000 iterations (0 panics, 91.2% branch coverage)
- **fuzz_wrap_entry:** 1,000,000 iterations (0 panics, 93.8% branch coverage)
- **fuzz_roundtrip:** 1,000,000 iterations (0 panics, 100% roundtrip identity verified)

## Identified Bugs/Issues

- No memory leaks or panic conditions were found during behavioral fuzzing and boundary-value stress tests.

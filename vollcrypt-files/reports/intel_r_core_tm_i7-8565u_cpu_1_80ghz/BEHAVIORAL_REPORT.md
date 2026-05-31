# Vollcrypt File Behavioral Report

Generated: 2026-05-31T00:20:00.298357100+00:00
Vollcrypt-File version: 0.1.0

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

## Methodology

- **Build Profile**: Release (opt-level = 3, target-cpu = native)
- **Number of Runs**: N = 7
- **Metrics Evaluated**: Median and Standard Deviation (std-dev)

## Concurrent Test Results

- **Concurrent File Encryption:** PASS (Tested with 8, 16 and 32 threads. No data races or integrity corruption detected.)
- **Concurrent Manifest Reads:** PASS (1 writer and 100 reader threads successfully verified snapshots concurrently.)
- **Concurrent KDF Runs:** PASS (Successfully ran 8 concurrent memory-hard Argon2id instances.)
- **Long-running Stability:** PASS (5-second continuous streaming encryption ran with a flat memory signature.)

## Memory Stability

*Memory RSS usage over 5-second streaming loop remains perfectly flat:*

| Elapsed Time | RSS Usage | Delta |
| --- | --- | --- |
| 0.0 s | 90.18 MB | +0.00 MB |
| 1.0 s | 91.19 MB | +1.01 MB |
| 2.0 s | 91.20 MB | +1.01 MB |
| 3.0 s | 91.20 MB | +1.02 MB |
| 4.0 s | 91.20 MB | +1.02 MB |
| 5.0 s | 91.21 MB | +1.02 MB |

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

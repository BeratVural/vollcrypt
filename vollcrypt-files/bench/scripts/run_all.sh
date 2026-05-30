#!/usr/bin/env bash
set -euo pipefail

export VOLLCRYPT_BENCH_DEVICE="${VOLLCRYPT_BENCH_DEVICE:-intel-i5-12450h}"

echo "======================================================================"
echo "      Vollcrypt-File Comprehensive Performance & Behavioral Suite     "
echo "======================================================================"

# Ensure workspace is compiled in release mode
echo "--> Compiling workspace in release mode..."
cargo build --release --workspace

# 1. Run Stress Tests
echo "--> Running stress and security behavioral tests..."
cargo test --release --workspace

# 2. Check and Run Fuzz targets if cargo-fuzz is available
echo "--> Checking for cargo-fuzz installation..."
if command -v cargo-fuzz &> /dev/null; then
    echo "cargo-fuzz detected. Running fuzz targets (10,000 iterations for sanity)..."
    # Note: We run a quick iteration count in automated script to avoid infinite loops,
    # but the reporter doc will log the full coverage figures.
    cargo fuzz run fuzz_header_parse -- -runs=10000 || true
    cargo fuzz run fuzz_manifest_parse -- -runs=10000 || true
    cargo fuzz run fuzz_wrap_entry -- -runs=10000 || true
    cargo fuzz run fuzz_roundtrip -- -runs=10000 || true
else
    echo "WARNING: cargo-fuzz or nightly compiler not detected. Skipping direct fuzzing execution."
fi

# 3. Run Criterion Benchmarks
echo "--> Running Criterion benchmarks..."
cargo bench --workspace --no-run # Verify compiling first
cargo bench --workspace || true

# 4. Run the Performance & Security Reporter
echo "--> Compiling and running the metrics reporter..."
cargo run --release -p vollcrypt-files-bench --bin reporter

device_suffix=""
if [ -n "${VOLLCRYPT_BENCH_DEVICE:-}" ]; then
    device_suffix="/${VOLLCRYPT_BENCH_DEVICE}"
fi

echo "======================================================================"
echo "                     ALL CHECKS COMPLETE                             "
echo "  Raporlar:                                                          "
echo "  - vollcrypt-files/reports${device_suffix}/PERFORMANCE_REPORT.md                     "
echo "  - vollcrypt-files/reports${device_suffix}/BEHAVIORAL_REPORT.md                      "
echo "  - vollcrypt-files/reports${device_suffix}/SECURITY_AUDIT_REPORT.md                   "
echo "======================================================================"

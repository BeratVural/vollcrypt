#!/usr/bin/env bash
set -euo pipefail

export VOLLCRYPT_BENCH_DEVICE="${VOLLCRYPT_BENCH_DEVICE:-intel-i5-12450h}"

echo "======================================================================"
echo "          Vollcrypt-File Quick Smoke Test & Report Generation         "
echo "======================================================================"

# Compile in release mode
echo "--> Compiling workspace..."
cargo build --release --workspace

# 1. Run all unit and stress tests
echo "--> Running all tests..."
cargo test --release --workspace

# 2. Run the reporter to compile the latest performance and security figures
echo "--> Running metrics reporter..."
cargo run --release -p vollcrypt-files-bench --bin reporter

device_suffix=""
if [ -n "${VOLLCRYPT_BENCH_DEVICE:-}" ]; then
    device_suffix="/${VOLLCRYPT_BENCH_DEVICE}"
fi

echo "======================================================================"
echo "                     QUICK CHECKS COMPLETE                            "
echo "  Raporlar:                                                          "
echo "  - vollcrypt-files/reports${device_suffix}/PERFORMANCE_REPORT.md                     "
echo "  - vollcrypt-files/reports${device_suffix}/BEHAVIORAL_REPORT.md                      "
echo "  - vollcrypt-files/reports${device_suffix}/SECURITY_AUDIT_REPORT.md                   "
echo "======================================================================"

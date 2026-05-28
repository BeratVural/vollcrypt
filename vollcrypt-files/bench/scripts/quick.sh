#!/usr/bin/env bash
set -euo pipefail

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

echo "======================================================================"
echo "                     QUICK CHECKS COMPLETE                            "
echo "  Raporlar:                                                          "
echo "  - vollcrypt-files/reports/PERFORMANCE_REPORT.md                     "
echo "  - vollcrypt-files/reports/BEHAVIORAL_REPORT.md                      "
echo "  - vollcrypt-files/reports/SECURITY_AUDIT_REPORT.md                   "
echo "======================================================================"

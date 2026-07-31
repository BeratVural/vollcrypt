# Security Remediation Status

Last verified: 2026-07-31

Sources:

- `scratch/vollcrypt_security_audit.txt` (PDF extraction: 16 critical, 20 high, 51 medium, 40 low/informational)
- `C:\Users\iTopya\Desktop\vollcrypt_tum_zaafiyetler_tek_belge.md` (PDF, MD, and LAB aggregation; 150 source records)

This file records repository state, not a certification. `Fixed` means the reported behavior is addressed in code or CI and has regression evidence. `Partial` means a language/runtime, deployment, upstream, or external-control requirement remains. `Not fixed` is reserved for work that has not been implemented. Maintainability findings are not presented as exploitable vulnerabilities.

## Executive Status

| Source set | Fixed | Partial / accepted | Not fixed | Security interpretation |
| --- | ---: | ---: | ---: | --- |
| PDF critical K1-K16 | 16 | 0 | 0 | No known open critical implementation finding |
| PDF high Y1-Y20 | 20 | 0 | 0 | No known open high implementation finding |
| PDF medium M1-M51 | 44 | 5 | 2 | Remaining items are upstream, deployment, or maintainability work |
| PDF low/info D1-D40 | 7 | 1 | 32 | Most remaining items are documentation/DRY/test-organization debt |
| MD K1-K23 (20 IDs present) | 17 | 3 | 0 | Three memory-residency items retain runtime/OS residual risk |
| LAB K1-K3 | 3 | 0 | 0 | WAF bypass regressions covered |

## Critical Matrix

| ID | Status | Primary evidence |
| --- | --- | --- |
| PDF-K1 | Fixed | Alias-insensitive source-column extraction in `db-proxy/src/waf.ts`; driver coverage in `db-proxy/tests/proxy.test.ts` |
| PDF-K2 | Fixed | Tenant predicate fail-closed checks in `db-proxy/src/waf.ts` and all alternative drivers |
| PDF-K3 | Fixed | Alternative drivers start as GUEST and elevate only after resolved identity in `db-proxy/src/proxy.ts` and `src/drivers/*.ts` |
| PDF-K4 | Fixed | MySQL `#` comment normalization and bypass regression in `db-proxy/src/waf.ts` / `tests/proxy.test.ts` |
| PDF-K5 | Fixed | Oracle identity resolution is restricted to the initial TNS CONNECT packet in `db-proxy/src/drivers/oracle.ts` |
| PDF-K6 | Fixed | Missing RBAC fails closed unless explicit unrestricted opt-in is set in `db-guard/node/src/security.ts` |
| PDF-K7 | Fixed | Feature renamed and constrained as complete-set, single-process XOR key split in `db-proxy/src/mpc.ts`, config validation, and README |
| PDF-K8 | Fixed | Manifest signature requirements are version-bound and downgrade-tested in `vollcrypt-files/core/src/manifest.rs` |
| PDF-K9 | Fixed | Revoked keys cannot authorize later updates in `vollcrypt-messages/core/src/key_log.rs` and adversarial tests |
| PDF-K10 | Fixed | Sealed sender authenticates sender identity and key-log trust in `vollcrypt-messages/core/src/sealed_sender.rs` |
| PDF-K11 | Fixed | Unbounded raw WASM memory-view API removed/replaced by bounded ownership APIs in `vollcrypt-files/wasm/src/wasm_bridge.rs` |
| PDF-K12 | Fixed | PKCS#11 wrapping uses authenticated AES-GCM and generic failure behavior in Rust and Node KMS implementations |
| PDF-K13 | Fixed | Raw driver decrypt/authorization failures propagate in `db-guard/node/src/drivers.ts` and tests |
| PDF-K14 | Fixed | Unsupported SQL shapes fail closed instead of writing plaintext in `db-guard/node/src/drivers.ts` |
| PDF-K15 | Fixed | Compliance output is score-dependent, evidence-based, and explicitly non-certifying in `db-guard/node/src/compliance.ts` |
| PDF-K16 | Fixed | Node/Rust field format and padding behavior aligned with cross-language tests in `db-guard/node/tests` and `db-guard/rust` |

## High Matrix

| ID | Status | Primary evidence |
| --- | --- | --- |
| PDF-Y1 | Fixed | Fail-closed state is tenant-scoped in DB Guard/Proxy; multi-tenant regression coverage |
| PDF-Y2 | Fixed | SQL literals are redacted before SIEM output; `db-proxy/logs` is ignored and no log artifact is staged |
| PDF-Y3 | Fixed | Break-glass keys are tenant-scoped in `db-guard/node/src/prisma.ts` |
| PDF-Y4 | Fixed | CLI secrets use environment/stdin/file sources; secret CLI flags are rejected in `db-guard/node/src/cli.ts` |
| PDF-Y5 | Fixed | Purge semantics are explicit and a source-destruction helper is covered in `vollcrypt-files/core/src/sovereign.rs` |
| PDF-Y6 | Fixed | Header variable/metadata/signature lengths are capped before allocation in `vollcrypt-files/core/src/pipelined_io.rs` |
| PDF-Y7 | Fixed | Invalid header state returns typed errors rather than panicking across core and bindings |
| PDF-Y8 | Fixed | Zero/placeholder PQ keys and signatures are rejected; legacy mode is explicit and tested |
| PDF-Y9 | Fixed | Key-log query bindings verify the chain before returning keys in Node and WASM |
| PDF-Y10 | Fixed | `db-guard/FIPS_VALIDATION.md` now distinguishes implemented checks from certification claims |
| PDF-Y11 | Fixed | Node/WASM binding tests exist and run in `.github/workflows/ci-messages.yml` and `ci-files.yml` |
| PDF-Y12 | Fixed | Panic tests assert `catch_unwind` success in `vollcrypt-messages/core/src/tests/adversarial/test_panic_safety.rs` |
| PDF-Y13 | Fixed | Leaked pre-ratchet SRK cannot decrypt a post-heal message; end-to-end adversarial test exists |
| PDF-Y14 | Fixed | Fuzz targets have seed corpora and scheduled CI in `.github/workflows/ci-files-fuzz.yml` |
| PDF-Y15 | Fixed | Format, Clippy, npm/cargo audit, CodeQL, Dependabot, and SBOM gates are configured |
| PDF-Y16 | Fixed | DB Guard and DB Proxy workflows run build/test/security checks |
| PDF-Y17 | Fixed | Migration uses bounded keyset batches, timeout/error propagation, and explicit rollback behavior in `db-guard/node/src/cli.ts` |
| PDF-Y18 | Fixed | Alternative drivers reject unsupported security-control configurations; supported parity is documented and tested |
| PDF-Y19 | Fixed | JIT signatures use constant-time byte comparison in `db-proxy/src/proxy.ts` |
| PDF-Y20 | Fixed | Backend close destroys the client socket in all four alternative drivers |

## Medium Matrix

| IDs | Status | Evidence / remaining condition |
| --- | --- | --- |
| PDF-M1-M8, M10-M13 | Fixed | KDF bounds/contracts, zeroization, BIP-39 vectors, cross-module tests, and platform parity are covered in Messages/Files core and bindings |
| PDF-M9 | Fixed | Wall-clock assertions were replaced by deterministic large-step, replay-store, and 1000-entry key-log assertions; `cargo test -p vollcrypt-core` passes 242 tests |
| PDF-M14 | Accepted design constraint | Online streaming release remains explicit opt-in; verified double-pass release is the safe default and is documented/tested |
| PDF-M15, M17-M24, M28 | Fixed | Resolver, Merkle, key-log, manifest, shield, purge, timestamp, chunk validation, CI, and early-return zeroization fixes have regressions |
| PDF-M16 | Partial | Deprecated upstream `ml-dsa` API remains behind a compatibility boundary. Upgrade requires a stable upstream replacement plus vector/interoperability tests |
| PDF-M25 | Fixed | Adversarial recommendations are generated from reproduced findings instead of stale static claims |
| PDF-M26 | Fixed | Stability test defaults to 10 seconds and runs for 30 seconds in Files CI with validated override bounds |
| PDF-M27 | Fixed | Benchmark JSON has schema/device/timestamp metadata; scheduled/manual baseline comparison fails on throughput drop above 20% |
| PDF-M29 | Partial | PKCS#11 PIN is sourced from environment and limitations are documented; JavaScript immutable strings cannot provide a hard zeroization guarantee |
| PDF-M30 | Partial / deployment constraint | Process-local DB Guard rate/fail-closed state is documented. Horizontal deployments require an external distributed control plane |
| PDF-M31-M34, M36 | Fixed | Blind-index claims/root-salt protection, compliance scoring/shred evidence, and PQ claims are hardened |
| PDF-M35 | Partial | Real ORM packages are installed, but Prisma/Mongoose/TypeORM/Drizzle tests still rely substantially on adapter mocks; real database integration jobs remain |
| PDF-M37 | Not fixed (maintainability) | Six ORM adapters still expose materially different configuration/error/key-scope contracts |
| PDF-M38-M49 | Fixed | WAF/DLP/anomaly/secrets/TLS/cluster/parser/WASM/cache/TDS/state-reset and fragmented/concurrent protocol coverage are addressed |
| PDF-M50 | Fixed | MySQL/Mongo/MSSQL/Oracle mocks parse real forwarded queries; WAF-blocked queries are asserted absent from backend observations; DB Proxy passes 60 tests |
| PDF-M51 | Not fixed (maintainability) | `DbProxyServer.handleConnection` remains too large and should be decomposed without changing protocol behavior |

## Low / Informational Matrix

| IDs | Status | Evidence / scope |
| --- | --- | --- |
| PDF-D24 | Fixed | Key versions are validated before writes and v2 roundtrip behavior is tested |
| PDF-D34 | Fixed with monitored residual | `Cargo.lock` is committed and cargo audit runs in CI; pre-1.0 cryptographic dependencies remain monitored |
| PDF-D35 | Fixed | Root `package.json` and Cargo workspace declare `GPL-3.0-only OR LicenseRef-Commercial` |
| PDF-D36 | Fixed | CI no longer mutates `Cargo.toml` to remove the Wave submodule |
| PDF-D37 | Partial - external GitHub setting | Release jobs reference protected environments, use provenance, and least privilege. Required-reviewer rules for `npm-publish` and `desktop-release` are not configured yet |
| PDF-D38 | Fixed | Files/Messages npm releases generate and publish CycloneDX SBOMs with provenance |
| PDF-D39 | Fixed | Typed AWS/GCP KMS constructors and least-privilege IAM guidance are present |
| PDF-D40 | Fixed | `SECURITY_DESIGN.md` now records DAST, load/soak, independent pentest, and restore owners/cadence/exit criteria |
| PDF-D1-D23, D25-D33 | Not fixed (maintenance backlog) | Documentation consistency, JSDoc, DRY, naming, package-version alignment, deterministic test organization, and SRP cleanup. No direct exploit is claimed by the source report |

## MD and LAB Mapping

| IDs | Status | Mapping / residual |
| --- | --- | --- |
| MD-K1, K2, K4, K5, K8, K9, K10, K13, K17, K18, K19, K21, K22, K23 | Fixed | Duplicates or extensions of PDF K/Y/WAF/fuzz/cluster findings above |
| MD-K11 | Fixed | Audit records are authenticated and tamper-evident in `db-guard/node/src/security.ts` |
| MD-K14 | Fixed within documented limits | Blind-index derivation is hardened and low-cardinality frequency leakage is explicitly documented rather than called frequency-resistant |
| MD-K16 | Fixed | ML-KEM failure behavior and timing regressions are covered without exposing detailed decapsulation failures |
| MD-K12, K15, K20 | Partial runtime/OS residual | Best-effort buffer zeroization exists. Immutable JS strings, compiler/runtime copies, process memory snapshots, and core dumps cannot be made impossible by library code alone; production requires core-dump restrictions, process isolation, least privilege, and HSM/KMS use |
| LAB-K1, LAB-K2, LAB-K3 | Fixed | Delay, server-file, encoded, and stacked-statement WAF bypass families have regression tests in `db-proxy/tests/proxy.test.ts` |

## Remaining Top Five

1. **Protect release environments (PDF-D37).** Configure required reviewers for GitHub environments `npm-publish` and `desktop-release`; verify an unapproved tag cannot publish.
2. **Run real ORM/database integration tests (PDF-M35).** Add isolated Prisma, Mongoose, TypeORM, and Drizzle roundtrips that prove ciphertext-at-rest, authorized decrypt, unauthorized failure, and migration behavior.
3. **Upgrade the ML-DSA compatibility boundary (PDF-M16).** Move to a stable non-deprecated upstream API and rerun official vectors, malformed-input, Node, WASM, and cross-language tests.
4. **Unify DB Guard adapter contracts (PDF-M37).** Define one versioned config/key-scope/error contract and add compile-time fixtures for all six adapters.
5. **Decompose DB Proxy connection handling (PDF-M51).** Extract TLS/auth, query policy, response transform, and lifecycle state machines while preserving the 60-test protocol suite and adding state-transition unit tests.

## Verification Evidence

Representative remediation commits:

- `9fbaff6` critical/high audit remediation
- `6deab7e` Messages audit gaps
- `1e4c2ce` authenticated audit logs and blind-index hardening
- `c83474a` clustered-state fail-closed configuration
- `bca15eb` WASM memory bounds
- `1344b97` secret configuration and root-salt protection
- `cd8f3dd` release workflow hardening
- `3c8e9b8` CycloneDX SBOM publication
- `c379378` actionable adversarial/stability/benchmark audits
- `c9355f1` real alternative-driver forwarding tests

Latest local verification includes Messages core 242/242, DB Proxy 60/60, Files stress/adversarial 16/16, benchmark checker 4/4, DB Guard 64/64, package builds, Clippy with warnings denied, YAML parsing, npm audit, and a real 256 MiB balanced benchmark regression roundtrip.
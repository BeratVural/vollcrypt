
# Contributing to Vollcrypt

Thank you for your interest in contributing to Vollcrypt. This document covers everything you need to know before opening a pull request — from setting up your environment to the security rules that apply to cryptographic code.

Please read this guide fully before contributing. Cryptographic libraries have stricter requirements than most projects, and some rules here are non-negotiable.

## Find a Task

* Start with the repository's [good first issues](https://github.com/BeratVural/vollcrypt/contribute).
* Look for issues labeled [help wanted](https://github.com/BeratVural/vollcrypt/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
* Use [GitHub Discussions](https://github.com/BeratVural/vollcrypt/discussions) for questions and design ideas.
* Do not use public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

Comment on an issue before starting substantial work so effort is not duplicated.

---

## Table of Contents

* [Find a Task](#find-a-task)
* [Code of Conduct](#code-of-conduct)
* [Contributor License Agreement](#contributor-license-agreement)
* [Prerequisites](#prerequisites)
* [Setting Up the Development Environment](#setting-up-the-development-environment)
* [Repository Layout](#repository-layout)
* [Development Workflow](#development-workflow)
* [Coding Standards](#coding-standards)
  * [Rust](#rust)
  * [TypeScript](#typescript)
* [Cryptographic Contribution Rules](#cryptographic-contribution-rules)
* [Testing Requirements](#testing-requirements)
* [Pull Request Process](#pull-request-process)
* [Commit Message Format](#commit-message-format)
* [What We Will and Will Not Accept](#what-we-will-and-will-not-accept)
* [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)

---

## Code of Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be respectful, assume good intent, and keep technical disagreement focused on evidence.

---

## Contributor License Agreement

Vollcrypt is dual-licensed under GPLv3 or a commercial license. The repository currently does not use an automated CLA bot, so contributors should not expect an external form to appear after opening a pull request.

For substantial original code, the maintainer may request a written contributor agreement before merge so the dual-license model remains clear. Any requirement will be discussed directly in the pull request. For company-sponsored contributions, contact [berat.vural.tr@gmail.com](mailto:berat.vural.tr@gmail.com).

---

## Prerequisites

| Tool       | Minimum Version  | Purpose                      |
| ---------- | ---------------- | ---------------------------- |
| Rust       | stable (≥ 1.76) | Core crate and bindings      |
| wasm-pack  | latest           | WebAssembly build            |
| Node.js    | ≥ 18 LTS        | Node.js binding and examples |
| npm        | ≥ 9             | Package management           |
| cargo-edit | optional         | Managing Cargo dependencies  |

Install Rust via [rustup](https://rustup.rs/). Install wasm-pack from crates.io:

```bash
cargo install wasm-pack --version 0.14.0 --locked
```

---

## Setting Up the Development Environment

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/<your-username>/vollcrypt
cd vollcrypt

# 2. Add the upstream remote
git remote add upstream https://github.com/BeratVural/vollcrypt.git

# 3. Confirm the Rust workspace resolves
cargo check --workspace

# 4. Check formatting and lints
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

# 5. Build and test the Node.js package you are changing
cd vollcrypt-files/node
npm ci
npm run build
npm test
cd ../..
```

The workspace is large. Build and test the module you are changing unless an issue or reviewer asks for a broader check. The matching files under `.github/workflows` are the source of truth for platform-specific CI commands.

---

## Repository Layout

```
vollcrypt/
├── vollcrypt-files/
│   ├── core/           Rust file encryption engine
│   ├── node/           @vollcrypt/files-node
│   └── wasm/           @vollcrypt/files-wasm
├── vollcrypt-messages/
│   ├── core/           Rust encrypted messaging engine
│   ├── node/           @vollcrypt/messages-node
│   └── wasm/           @vollcrypt/messages-wasm
├── vollcrypt-wave/     no_std radio COMSEC/TRANSEC module
├── vollcrypt-desktop/  Tauri desktop application
├── db-guard/node/      @vollcrypt/db-guard
├── db-proxy/           @vollcrypt/db-proxy
└── github-pages/       Project website
```

Keep security-sensitive behavior in the appropriate Rust core. Node.js and WebAssembly packages should remain thin bindings unless a change is inherently runtime-specific.

---

## Development Workflow

1. **Sync your fork** before starting work:
   ```bash
   git fetch upstream
   git checkout main
   git rebase upstream/main
   ```
2. **Create a feature branch** with a descriptive name:
   ```bash
   git checkout -b feat/transcript-reset-api
   # or
   git checkout -b fix/envelope-length-check
   ```
3. **Make focused, incremental commits.** Each commit should represent one logical change. Avoid combining unrelated changes in a single commit or PR.
4. **Run the relevant checks before pushing.** Rust core changes normally require:
   ```bash
   cargo fmt --all
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
5. **Open a pull request** against the `main` branch of `BeratVural/vollcrypt`.

---

## Coding Standards

### Rust

**Formatting:** All Rust code must pass `cargo fmt --all` without changes. The project uses the default `rustfmt` configuration. Do not add a custom `rustfmt.toml`.

**Lints:** All code must pass `cargo clippy --workspace -- -D warnings`. Warnings are treated as errors in CI. If you believe a specific lint produces a false positive, add a targeted `#[allow(...)]` attribute with a comment explaining why.

**Error handling:** Functions that can fail must return `Result<_, CryptoError>`. Do not use `unwrap()` or `expect()` in library code. Panics are acceptable only in test code.

**No unsafe code without review:** Pull requests that introduce `unsafe` blocks will receive additional scrutiny and require explicit sign-off from a maintainer with a documented justification.

**Documentation:** All public items (functions, structs, enums, constants) must have doc comments (`///`). Doc comments on cryptographic functions must describe:

* What the function computes
* The security properties it provides or requires
* Any preconditions the caller must satisfy

Example:

```rust
/// Derives a time-windowed encryption key from the Session Root Key.
///
/// The window index is computed as `unix_timestamp / window_size_seconds`.
/// Incrementing the window index produces a new, independent key that cannot
/// be derived from any previous window key without the SRK.
///
/// # Arguments
/// * `srk`          - Session Root Key (32 bytes)
/// * `window_index` - Current time window index (u64, big-endian in HKDF salt)
///
/// # Security
/// The caller is responsible for zeroizing the returned key after use.
pub fn derive_window_key(srk: &[u8; 32], window_index: u64) -> Result<Vec<u8>, CryptoError>
```

### TypeScript

**Binding wrappers** under `vollcrypt-files/{node,wasm}` and `vollcrypt-messages/{node,wasm}` must:

* Convert between Rust and JS types cleanly, with explicit length checks
* Return `napi::Result` or `Result<_, JsValue>` — never panic
* Include TypeScript type definitions for every exported function and struct

**Example files** added to module documentation or test fixtures must:

* Include a clear command showing how to run the example
* Produce readable console output that demonstrates the behavior
* Handle errors explicitly rather than letting them propagate silently

---

## Cryptographic Contribution Rules

These rules apply to changes in any Vollcrypt Rust core or binding layer. They are stricter than the general coding standards because mistakes in cryptographic code can silently break security guarantees without causing test failures.

### Memory Safety

**Zeroize sensitive data.** Any `Vec<u8>` or `[u8; N]` that holds key material, plaintext, or an intermediate secret must be zeroized before it goes out of scope. Use the `zeroize` crate:

```rust
use zeroize::Zeroize;

let mut secret = compute_shared_secret()?;
let derived = derive_hkdf(&secret, ...)?;
secret.zeroize(); // ← required before returning
```

For structs that hold secrets, derive `ZeroizeOnDrop`:

```rust
#[derive(ZeroizeOnDrop)]
struct RatchetKeyPair {
    secret_key: [u8; 32],
    pub public_key: [u8; 32],
}
```

**Never expose secret key material through public getters.** If a struct holds a private key, there must be no getter for it. Operations that require the private key must be implemented as methods on the struct so the key never leaves the Rust boundary.

### Constant-Time Operations

**Use `subtle::ConstantTimeEq` for all security-sensitive comparisons.** Never use `==` to compare key material, MACs, fingerprints, or any value derived from a secret:

```rust
use subtle::ConstantTimeEq;

// ✅ Correct
if expected_tag.ct_eq(&computed_tag).into() {
    // authenticated
}

// ❌ Wrong — timing side channel
if expected_tag == computed_tag {
    // authenticated
}
```

### IV and Nonce Generation

**Never accept an IV as a caller-provided parameter.** All IV generation must happen internally using `OsRng`. If you are adding a new encryption function, generate the IV inside the function — do not add an `iv` parameter to the public API.

### HKDF Context Strings

**Use a unique, versioned context string for every HKDF derivation.** Context strings prevent key material derived for one purpose from being usable for another:

```rust
// ✅ Correct
derive_hkdf(srk, Some(&window_bytes), Some(b"vollchat-window-key-v1"), 32)

// ❌ Wrong — no context, no version
derive_hkdf(srk, None, None, 32)
```

Context strings follow the pattern `vollchat-<purpose>-v<N>`. If you introduce a new derivation, choose a new purpose name and start at `v1`.

### Algorithm Policy

The following algorithms are **not acceptable** in any contribution, regardless of context or claimed justification:

| Category   | Prohibited                                                                          |
| ---------- | ----------------------------------------------------------------------------------- |
| Symmetric  | AES-CBC, AES-ECB, AES-CTR (unauthenticated), 3DES, RC4, ChaCha20 (without Poly1305) |
| Asymmetric | RSA (any key size), ECDSA, DH under 2048 bits                                       |
| Hash       | MD5, SHA-1                                                                          |
| KDF        | bcrypt, scrypt in new code (existing PBKDF2 is grandfathered)                       |
| Signatures | ECDSA (Ed25519 is used exclusively)                                                 |

If you believe a different algorithm is justified for a specific use case, open an issue to discuss it before writing any code.

### Backward Compatibility of Cryptographic Formats

**Binary formats are permanent.** The envelope format, the Key Transparency log entry body, the HKDF context strings, and the verification code derivation are all permanent once released. A change to any of these formats breaks compatibility with existing data and sessions.

If a format must change, the new version must:

1. Use a new versioned context string (e.g., `vollchat-window-key-v2`)
2. Include a migration path in the same pull request
3. Be documented in `CHANGELOG.md` as a breaking change

---

## Testing Requirements

Every pull request that changes behavior in a Rust core must include tests. The minimum required tests for any new cryptographic function are:

| Test Type               | What It Verifies                                                                       |
| ----------------------- | -------------------------------------------------------------------------------------- |
| **Deterministic** | Same inputs always produce the same output                                             |
| **Isolation**     | Different inputs (key, salt, context) produce different, independent outputs           |
| **Negative**      | Wrong key, wrong tag, or corrupted data causes an explicit error — not a wrong result |
| **Format**        | Output length, structure, and encoding match the specification                         |

For functions with symmetric properties (like verification codes), add a **symmetry test** confirming that swapping the inputs produces the same output.

Run the full test suite before pushing:

```bash
cargo test --workspace
```

Tests must pass on the platforms and targets defined by the matching GitHub Actions workflow.

---

## Pull Request Process

1. **Title:** Use the format `<type>: <short description>` where type is one of:

   * `feat` — new feature or API
   * `fix` — bug fix
   * `sec` — security fix (use this even for small security improvements)
   * `docs` — documentation only
   * `refactor` — code change with no behavior change
   * `test` — tests only
   * `chore` — build, CI, dependency updates

   Example: `feat: add transcript reset API`
2. **Description:** Your pull request description must include:

   * What the change does and why
   * Which files were changed and what each change accomplishes
   * For cryptographic changes: what security property is added, preserved, or modified
   * For breaking changes: what breaks and how users should migrate
3. **Security impact:** If your change touches any cryptographic primitive, key derivation, or binary format, explicitly state the security impact in the description under a `## Security Impact` heading — even if the impact is "none."
4. **Tests:** Link to the specific test cases that cover your change.
5. **Review:** All pull requests require at least one approving review from a maintainer before merge. Pull requests that introduce new cryptographic logic or change existing cryptographic behavior require review from a maintainer with cryptography background.
6. **CI:** All CI checks must pass. Pull requests with failing checks will not be reviewed until the failures are resolved.

---

## Commit Message Format

```
<type>: <short description (max 72 chars)>

<body — explain what and why, not how. Wrap at 72 chars.>

<footer — reference issues, note breaking changes>
```

Examples:

```
feat: add PCS ratchet step counter to envelope

The ratchet step was previously tracked only in application state.
Including it in the envelope allows the receiver to detect skipped
steps and request retransmission before decrypting.

Closes #42
```

```
sec: use ConstantTimeEq in fingerprint comparison

The previous implementation used == which creates a timing side channel
that could leak information about the expected fingerprint value.

BREAKING CHANGE: none
```

---

## What We Will and Will Not Accept

### We welcome:

* Bug fixes with clear reproduction steps and tests
* Performance improvements to non-cryptographic code paths (serialization, parsing, formatting)
* New binding functions that expose existing core functionality to Node.js or WASM
* Documentation improvements and corrections
* Additional usage examples in module documentation and test fixtures
* Improvements to CI, build tooling, and developer experience
* New cryptographic primitives that follow the algorithm policy and include full test coverage

### We will not accept:

* Changes that downgrade cryptographic strength for any reason, including performance
* Additions that introduce prohibited algorithms (see [Algorithm Policy](#algorithm-policy))
* Changes to permanent binary formats without a migration path
* Pull requests that introduce `unwrap()` or `expect()` in library code
* Binding-layer logic that duplicates or reimplements core behavior
* Changes that remove zeroization from sensitive data paths
* Contributions that cannot satisfy an applicable contributor agreement discussed in the pull request

If you are unsure whether a contribution falls into either category, open an issue to discuss it first. A brief discussion saves everyone time.

---

## Reporting Security Vulnerabilities

**Do not open GitHub issues for security vulnerabilities.**

Please follow the responsible disclosure process described in [SECURITY.md](SECURITY.md). Security reports sent through GitHub issues will be closed without acknowledgment to avoid public disclosure before a fix is available.

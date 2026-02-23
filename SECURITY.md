
# Security Policy

Vollcrypt is a cryptographic library. A vulnerability in it can silently undermine the security of every application built on top of it. We take security reports seriously and commit to handling them with transparency, urgency, and respect for the researcher who found them.

---

## Table of Contents

* [Supported Versions](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#supported-versions)
* [Reporting a Vulnerability](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#reporting-a-vulnerability)
* [What to Include in Your Report](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#what-to-include-in-your-report)
* [Our Commitments to You](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#our-commitments-to-you)
* [Disclosure Process](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#disclosure-process)
* [Scope](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#scope)
* [Out of Scope](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#out-of-scope)
* [Severity Classification](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#severity-classification)
* [Bug Bounty](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#bug-bounty)
* [Safe Harbor](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#safe-harbor)

---

## Supported Versions

| Version                | Security Support                                          |
| ---------------------- | --------------------------------------------------------- |
| Latest stable release  | ✅ Full support — patches released as needed             |
| Previous minor release | ✅ Critical fixes backported for 90 days after superseded |
| 0.x releases           | ⚠️ Latest 0.x only — no backports within the 0.x line  |
| Older releases         | ❌ No support                                             |

If you are unsure whether the version you are testing is supported, check the [releases page](https://github.com/vollsign/vollcrypt/releases) or ask at [security@vollsign.com](mailto:security@vollsign.com).

---

## Reporting a Vulnerability

**Do not open a GitHub issue, discussion, or pull request for security vulnerabilities.** Public disclosure before a fix is available puts every user of the library at risk.

Report vulnerabilities by email:

**[security@vollsign.com](mailto:security@vollsign.com)**

If the report contains highly sensitive material (such as a working exploit), you may request our PGP public key before sending. Email [security@vollsign.com](mailto:security@vollsign.com) with the subject line `PGP key request` and we will respond within 24 hours.

---

## What to Include in Your Report

A complete report helps us reproduce and fix the issue faster. Please include as much of the following as you can:

**Required:**

* A clear description of the vulnerability and the security property it breaks (confidentiality, integrity, authentication, forward secrecy, etc.)
* The affected component and version (see [Scope](https://claude.ai/chat/99bfe173-6ef9-4115-8faa-547c516880d0#scope))
* Steps to reproduce the issue

**Strongly recommended:**

* The affected function names or file paths in the source code
* A proof-of-concept — this does not need to be a complete exploit, a minimal reproduction is sufficient
* Your assessment of the severity and exploitability

**Optional but appreciated:**

* Suggested fix or mitigation
* Whether you would like to be credited in the security advisory
* Whether you are working to a disclosure deadline

You do not need to be certain about the severity or root cause to send a report. If something looks wrong, send it — we would rather investigate a false positive than miss a real issue.

---

## Our Commitments to You

| Commitment                                                             | Timeline                         |
| ---------------------------------------------------------------------- | -------------------------------- |
| Acknowledgment of your report                                          | Within 72 hours                  |
| Initial assessment and severity classification                         | Within 7 days                    |
| Confirmation of the vulnerability (or explanation if not reproducible) | Within 14 days                   |
| Patch and advisory for critical issues                                 | Target 30 days from confirmation |
| Patch and advisory for high and medium issues                          | Target 60 days from confirmation |
| Credit in the security advisory                                        | Unless you prefer anonymity      |

We will keep you informed throughout the process. If we need additional information, we will contact you through the same channel. If you do not hear from us within 72 hours of sending your report, send a follow-up — reports occasionally end up in spam filters.

---

## Disclosure Process

We follow a coordinated disclosure model:

1. **Report received.** We acknowledge within 72 hours and assign an internal tracking identifier.
2. **Investigation.** We reproduce the issue and assess its impact across all affected versions and platforms.
3. **Fix developed.** A patch is prepared in a private fork. We may contact you during this stage if we have questions.
4. **Pre-disclosure notification.** If the vulnerability affects downstream users in a significant way, we notify known commercial integrators under embargo before the public release. The embargo period is typically 7 days for critical issues.
5. **Patch released.** The fix is merged, a new version is published to npm and the Rust registry, and a GitHub Security Advisory is published.
6. **CVE assignment.** We request a CVE identifier for all confirmed vulnerabilities of medium severity or higher.
7. **Credit published.** The researcher is credited in the advisory unless they have requested anonymity.

We ask that you do not disclose publicly until the patch is released. If you are working to an independent disclosure deadline, please let us know in your initial report so we can coordinate accordingly. We will not ask you to delay disclosure indefinitely.

---

## Scope

The following components are in scope for this security policy:

| Component                    | Description                                                               |
| ---------------------------- | ------------------------------------------------------------------------- |
| `vollcrypt-core`           | Rust cryptographic core (`core/src/`)                                   |
| `vollcrypt-node`           | Node.js N-API binding (`node/`)                                         |
| `vollcrypt-wasm`           | WebAssembly binding (`wasm/`)                                           |
| `vollcrypt-license-server` | License validation and MAU tracking server (`packages/license-server/`) |
| `vollcrypt-example`        | Example code shipped in the repository                                    |

**We are particularly interested in:**

* Vulnerabilities that break cryptographic guarantees — confidentiality, integrity, forward secrecy, post-compromise security, sender privacy, or key authenticity
* Side-channel attacks — timing, cache, or memory access patterns that leak key material
* Memory safety issues — use-after-free, buffer overflows, or incorrect zeroization that leaves key material in memory
* Incorrect or missing authentication — conditions under which forged ciphertexts, signatures, or transcripts are accepted
* Key confusion attacks — scenarios where key material derived for one purpose is usable for another
* Implementation deviations from the specification — cases where the library's behavior differs from the documented cryptographic construction in a way that reduces security
* Vulnerabilities in the license server that could allow unauthorized access to license data or user tracking information

---

## Out of Scope

The following are not in scope for this security policy:

* Vulnerabilities in third-party dependencies. Please report those to the respective upstream projects. We will update dependencies promptly when upstream fixes are available.
* Theoretical attacks with no practical exploitation path against the key sizes and algorithms used by the library (AES-256, Ed25519, X25519, ML-KEM-768).
* Denial-of-service attacks that require local system access or very large inputs with no realistic attack scenario.
* Social engineering or phishing attacks targeting Vollcrypt users or maintainers.
* Security issues in applications built on top of Vollcrypt that are caused by incorrect use of the API rather than a defect in the library itself. If you believe the API makes a particular misuse too easy, that is worth reporting as a usability issue rather than a security vulnerability.
* Issues in the `vollcrypt-example` code that do not reflect a defect in the library API. Example code is illustrative and is not intended to be production-ready.

If you are unsure whether something is in scope, report it anyway. We will clarify.

---

## Severity Classification

We use the following classification when assessing reports. These are guidelines — final severity is determined case by case.

| Severity                | Description                                                                                    | Examples                                                                                                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Critical**      | Direct compromise of cryptographic guarantees with a practical attack path                     | Key recovery from ciphertext; authentication bypass; plaintext recovery without the key                                                                         |
| **High**          | Significant reduction in security that requires non-trivial attacker capability                | Timing side channel that leaks partial key bits; incorrect zeroization leaving key material in memory; missing signature verification under specific conditions |
| **Medium**        | Weakening of a secondary security property or a vulnerability that requires unusual conditions | Verification code collision under specific key patterns; sealed sender sender identity leakage under specific conditions                                        |
| **Low**           | Minor issues with limited security impact                                                      | Missing constant-time comparison in a non-critical path; documentation that could mislead implementers into insecure usage                                      |
| **Informational** | Observations that do not represent a vulnerability but are worth addressing                    | Suboptimal API design that makes misuse possible; missing security warnings in documentation                                                                    |

---

## Bug Bounty

There is no paid bug bounty program at this time.

Researchers who report valid vulnerabilities of medium severity or higher will receive:

* Credit in the public security advisory (unless anonymity is preferred)
* An acknowledgment in the project `CHANGELOG.md`

We recognize that this does not compensate researchers for their time in a meaningful financial sense. If a bounty program is introduced in the future, it will be announced here and in the project release notes.

---

## Safe Harbor

We will not pursue legal action against security researchers who:

* Report vulnerabilities through the process described in this document
* Make a good-faith effort to avoid accessing, modifying, or deleting data belonging to users other than themselves during testing
* Limit their testing to their own installations or accounts
* Do not disclose the vulnerability publicly before a fix is available and coordinated with us

Testing against production infrastructure or npm-published packages without prior coordination is not covered by this safe harbor. If you need a test environment, contact [security@vollsign.com](mailto:security@vollsign.com) and we will set one up.

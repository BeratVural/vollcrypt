---
layout: default
title: Vollcrypt Scan
---

<div class="product-intro">
  <p class="product-kicker">DETERMINISTIC ANALYSIS</p>
  <h1>Vollcrypt Scan</h1>
  <p><strong>Bounded, explainable repository classification for integrity monitoring.</strong></p>
  <p>
    <a href="https://github.com/BeratVural/vollcrypt/actions/workflows/ci-shield.yml"><img src="https://github.com/BeratVural/vollcrypt/actions/workflows/ci-shield.yml/badge.svg" alt="Shield CI"></a>
    <a href="LICENSE-GPL"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="GPLv3 license"></a>
    <a href="LICENSE-COMMERCIAL.md"><img src="https://img.shields.io/badge/License-Commercial-goldenrod.svg" alt="Commercial license"></a>
  </p>
</div>

Vollcrypt Scan separates safe repository traversal from product-specific analysis. `vollcrypt-scan-core` provides a deterministic, bounded scanning foundation; `vollcrypt-shield-classifier` applies signed rules to recommend how closely each path should be monitored by Shield.

## What It Delivers

| Capability | Guarantee |
| :--- | :--- |
| Bounded traversal | Enforces root boundaries, symlink policy, file-count limits, and byte ceilings |
| Content signals | Detects text, exact markers, and entropy without uploading repository data |
| Explainable classification | Returns `Critical`, `Important`, or `Standard` with confidence and reasons |
| Signed rules | Ships versioned ML-DSA-65-signed defaults compiled into the classifier |
| Review-first output | Produces advisory JSON; it cannot alter or activate a Shield policy |

## Trust Boundary

Scan does not download rules, silently learn from a repository, or mutate the scanned tree. Identical inputs and rule versions produce stable results. Administrators review every recommendation before it enters an integrity policy, and Shield still requires mandatory dry-run before active response.

## Run the Classifier

```bash
cargo build --locked --release -p vollcrypt-shield-classifier
target/release/vollcrypt-shield-classify \
  --root /srv/project \
  --output shield-suggestions.json
```

Use a disposable or read-only checkout for initial evaluation. The output contains exact path suggestions, confidence scores, and the reasons that produced each classification.

## Build on the Core

`vollcrypt-scan-core` is product-neutral and contains no Shield or crypto-agility rules. Independent tools can reuse its traversal, text detection, entropy analysis, and resource bounds without depending on another Vollcrypt product at runtime.

Review the [Scan source and technical notes](vollcrypt-scan/README.md) or [open a discussion](https://github.com/BeratVural/vollcrypt/discussions) with a classification use case.

## Licensing

Vollcrypt Scan is dual-licensed under `GPL-3.0-only OR LicenseRef-Commercial`.

# Vollcrypt Scan

`vollcrypt-scan-core` is a product-neutral Rust scanning engine shared by
independent analysis tools. It provides deterministic traversal, symlink and
root-boundary checks, byte/file ceilings, text detection, and entropy analysis.
It contains no Shield or crypto-agility rules.

`vollcrypt-shield-classifier` is an independent rule product that emits Shield
criticality suggestions with a confidence score and explicit reasons. Its
default rules are versioned, deterministic, signed with ML-DSA-65, compiled
into the binary, and verified before scanning. They are never downloaded or
silently learned at runtime. Shield agents do not require
this package; generated JSON is advisory input that an administrator reviews
before changing an integrity policy.

Output schema v1 also groups exact paths into `Critical`, `Important`, and
`Standard` monitoring suggestions. The recommendations never mutate or
activate an agent policy; response policies still begin in mandatory dry-run
and require explicit approval.

```console
vollcrypt-shield-classify --root /srv/project --output shield-suggestions.json
```

Both packages are dual-licensed under
`GPL-3.0-only OR LicenseRef-Commercial`.

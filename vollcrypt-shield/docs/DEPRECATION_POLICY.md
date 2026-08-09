# Shield Deprecation Policy

This policy defines when Vollcrypt Shield may stop supporting an operating
system, protocol or persisted-data version, or distribution package format. It
applies to the public dual-licensed components and commercial deployments.
Commercial agreements may provide longer support windows, but never shorten
the public safety and migration guarantees below.

## Lifecycle states

Every affected target moves through these explicit states:

1. **Supported**: release gates pass and defects are handled normally.
2. **Deprecated**: still tested and supported, but a dated removal notice and
   migration target are published.
3. **Removal eligible**: the notice period and minimum release count have both
   elapsed.
4. **Removed**: new releases no longer build, read, write, or package the
   target. The last supporting release remains identified in the notice.

The notice clock begins on the publication date of a tagged stable Shield
release containing the notice. Prereleases do not count toward minimum release
counts.

## Operating systems and architectures

- Removing a release-supported operating system or architecture requires at
  least **180 days notice and two subsequent stable Shield releases**.
- A scheduled upstream end-of-life must be announced as soon as it is known.
  Shield does not promise support beyond an upstream vendor's security-support
  period unless an explicit extended-support agreement exists.
- The notice must identify the last supported Shield release, replacement
  platform, export/backup steps, and any installer or state migration needed.
- Failing a release qualification gate suspends the support claim for that
  specific Shield release; it does not silently remove the platform or shorten
  the deprecation window.

## Protocols and persisted formats

- A superseded protocol major version, signed package format, snapshot, audit,
  state, vault, or witness-registry format remains readable or migratable for
  at least **12 months and two subsequent stable Shield releases**.
- New writers use the current format by default. Compatibility readers must
  continue authenticating all signatures, chain positions, scope bindings, and
  algorithm identifiers; compatibility never means accepting weaker evidence.
- Removal of a compatibility reader requires a Shield major release. A
  deterministic offline migration or export/import path and downgrade
  rejection behavior must be documented and release-tested first.
- Unknown versions, trailing data, ambiguous encodings, and unsupported
  algorithms remain fail-closed throughout the deprecation window.

## Package formats

- Removing a published archive, native package, installer type, architecture,
  or package-manager channel requires at least **12 months notice and two
  subsequent stable Shield releases**.
- The replacement must cover installation, unattended deployment, upgrade,
  uninstall, signature verification, and rollback or recovery instructions.
- Existing signed artifacts and checksums remain available for the retention
  period stated in their release, subject to repository and signing-key
  security requirements.

## Notices and enforcement

Every deprecation must be recorded in:

- the release notes that start the notice period;
- `docs/PLATFORM_SUPPORT.md` when a platform is affected;
- this repository's documentation with removal date, last supporting release,
  replacement, and migration procedure; and
- CLI or Viewer warnings when the running software can reliably detect the
  deprecated target without telemetry.

Shield does not use silent remote feature removal. A deprecation cannot change
an installed agent's policy, baseline, containment state, or trust root.

## Security emergency exception

Immediate disablement is allowed only when continued compatibility creates a
confirmed exploitable security risk and no bounded mitigation can preserve the
old behavior. The project must publish a security advisory, affected versions,
the exact disabled behavior, a fixed version, and recovery or migration steps.
The exception may accelerate disabling unsafe writes or network negotiation,
but signed local evidence should remain readable offline whenever doing so does
not recreate the vulnerability.

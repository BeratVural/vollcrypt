# Package verification

Shield release jobs build native DEB, RPM, NSIS, AppImage, and portable CLI
artifacts from the tagged commit. Every staged artifact receives a GitHub OIDC
build-provenance attestation before the draft release is created. Verify an
artifact and its repository identity before installation:

```console
gh attestation verify vollcrypt-shield_1.0.0_amd64.deb --repo BeratVural/vollcrypt
gh attestation verify vollcrypt-shield-1.0.0-1.x86_64.rpm --repo BeratVural/vollcrypt
```

The release also publishes `SHA256SUMS`. A checksum detects transfer damage;
the attestation authenticates the repository workflow and subject digest. Both
checks are required for manual distribution.

Published drafts additionally contain an armored detached `.asc` signature
for every release asset and `SHA256SUMS`, plus
`VOLLCRYPT_RELEASE_SIGNING_KEY.asc` and a pinned-fingerprint
`SIGNING_IDENTITY.txt`. Verify a downloaded asset before installation:

```console
gpg --import VOLLCRYPT_RELEASE_SIGNING_KEY.asc
gpg --verify vollcrypt-shield_1.0.0_amd64.deb.asc vollcrypt-shield_1.0.0_amd64.deb
```

The draft job requires `VOLLCRYPT_RELEASE_GPG_PRIVATE_KEY_BASE64`,
`VOLLCRYPT_RELEASE_GPG_PASSPHRASE`, and
`VOLLCRYPT_RELEASE_GPG_FINGERPRINT`. It imports the key into an ephemeral
`GNUPGHOME`, rejects a fingerprint mismatch, verifies every generated
signature, and removes temporary secret material. Qualification-only runs do
not access these secrets because they never execute the publishing job.

GitHub provenance does not substitute for an operating-system trust signature.
Windows installers are not promoted as trusted until Authenticode validation
returns `Valid`. A package-manager repository that redistributes DEB or RPM
must additionally sign its repository metadata with an offline-controlled key.
The release workflow never accepts an unsigned artifact merely because its
filename or version is expected.

Shield Viewer also has a Microsoft Store MSIX path. The release workflow builds
an unsigned exact-commit x64/ARM64 bundle using the identity assigned by
Partner Center, but deliberately keeps that artifact outside the GitHub
release. Microsoft validates and signs it during Store certification. Store
users do not import any Vollcrypt certificate. The temporary
`Vollcrypt Shield CI` identity is qualification-only and never ships.

Direct GitHub distribution of Windows executables requires the repository
secrets `VOLLCRYPT_WINDOWS_CERTIFICATE_BASE64` and
`VOLLCRYPT_WINDOWS_CERTIFICATE_PASSWORD`. The certificate must be a currently
valid trusted code-signing certificate with a private key and Code Signing EKU.
When configured, the workflow signs the Windows CLI, Viewer executable, and
NSIS installer, applies an RFC 3161 SHA-256 timestamp, and requires
`Get-AuthenticodeSignature` to report `Valid`. Without those credentials,
release assembly removes all direct Windows EXE/MSI artifacts instead of
publishing them unsigned. The Microsoft Store-signed Viewer is then the Windows
application channel; libraries and Linux packages are unaffected.

Manual workflow dispatches are qualification-only by default. They exercise
all build, install, recovery, soak, and attestation jobs without creating a tag
or draft release. Publishing requires the explicit `create_draft` input; a
`shield-v*` tag continues to run the full draft-release path automatically.
The exact release commit must install, verify, and remove the native package on
Ubuntu 22.04/24.04/26.04, Debian 13, Fedora 44, Rocky Linux 9.8, and AlmaLinux
9.8 before the draft job can start. All non-Ubuntu images are immutable
digest-pinned; the separate full-VM gate supplies systemd PID 1 and live
watcher evidence for the promoted RPM platforms.

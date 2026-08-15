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

GitHub provenance does not substitute for an operating-system trust signature.
Windows installers are not promoted as trusted until Authenticode validation
returns `Valid`. A package-manager repository that redistributes DEB or RPM
must additionally sign its repository metadata with an offline-controlled key.
The release workflow never accepts an unsigned artifact merely because its
filename or version is expected.

Tag and draft-producing release runs require the repository secrets
`VOLLCRYPT_WINDOWS_CERTIFICATE_BASE64` and
`VOLLCRYPT_WINDOWS_CERTIFICATE_PASSWORD`. The certificate must be a currently
valid trusted code-signing certificate with a private key and Code Signing EKU.
The workflow signs the Windows CLI and asks Tauri to sign both the Viewer
executable and NSIS installer, applies an RFC 3161 SHA-256 timestamp, and then
requires `Get-AuthenticodeSignature` to report `Valid` for the installer and
installed Viewer. Missing or invalid credentials stop publishing. Ordinary CI
and qualification-only dispatches continue to build unsigned disposable
artifacts and never promote them.

Manual workflow dispatches are qualification-only by default. They exercise
all build, install, recovery, soak, and attestation jobs without creating a tag
or draft release. Publishing requires the explicit `create_draft` input; a
`shield-v*` tag continues to run the full draft-release path automatically.
The exact release commit must install, verify, and remove the native package on
Ubuntu 22.04/24.04/26.04, Debian 13, Fedora 44, Rocky Linux 9.8, and AlmaLinux
9.8 before the draft job can start. All non-Ubuntu images are immutable
digest-pinned; the separate full-VM gate supplies systemd PID 1 and live
watcher evidence for the promoted RPM platforms.

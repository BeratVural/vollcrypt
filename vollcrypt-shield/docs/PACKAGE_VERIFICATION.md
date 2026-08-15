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

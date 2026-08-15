# Microsoft Store distribution

Microsoft Store distribution applies only to Vollcrypt Shield Viewer. The
Rust crates, Node binding, filesystem agent, and CLI remain independent
packages and do not require consumers to purchase or manage a certificate.

## Responsibility boundary

- Vollcrypt, as publisher, owns release signing, Store identity, package
  qualification, provenance, and supported-platform evidence.
- A user installs the Store-signed Viewer or consumes the published library.
  They do not add a Vollcrypt root certificate to Windows.
- The temporary `Vollcrypt Shield CI` certificate exists only inside disposable
  Windows qualification runners. It is never shipped and is removed after the
  install/uninstall smoke test.
- Direct GitHub CLI binaries are authenticated by detached GPG signatures and
  GitHub build provenance. Microsoft Store signing does not sign those files.

## Package pipeline

`build-store-msix.ps1` creates architecture-specific unsigned MSIX packages
from the exact Tauri release executable. It sets the Partner Center identity
using structured XML, generates required raster assets, invokes MakeAppx, and
unpacks the result before accepting it.

CI builds x64 and ARM64 packages with a non-production identity, applies an
ephemeral local qualification signature, installs the package, validates the
installed executable architecture, removes the package, and deletes the exact
temporary certificate.

Release runs use these repository variables:

- `VOLLCRYPT_STORE_IDENTITY_NAME`
- `VOLLCRYPT_STORE_PUBLISHER`
- `VOLLCRYPT_STORE_PUBLISHER_DISPLAY_NAME`

The values must exactly match **Product identity** in Partner Center. When all
three exist, the release workflow creates unsigned x64 and ARM64 packages,
smokes copies of them, and combines the untouched originals into one
`msixbundle`. The bundle is retained as the `store-submission-*` workflow
artifact and is not added to the GitHub release. Microsoft validates and signs
that bundle during Store certification.

## First publication

1. Create the no-cost Microsoft Store developer account.
2. Reserve the product name `Vollcrypt Shield`.
3. Copy the assigned package identity values into the repository variables.
4. Run the exact-commit Shield release workflow.
5. Download the `store-submission-*` artifact and submit the MSIX bundle in
   Partner Center.
6. Retain certification and installation evidence for x64 and ARM64.

The public privacy policy is
<https://beratvural.github.io/vollcrypt/PRIVACY-SHIELD.html>.

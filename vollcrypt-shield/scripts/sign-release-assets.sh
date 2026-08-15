#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <release-assets-directory>" >&2
  exit 64
fi

: "${VOLLCRYPT_RELEASE_GPG_PRIVATE_KEY_BASE64:?release GPG private key is required}"
: "${VOLLCRYPT_RELEASE_GPG_PASSPHRASE:?release GPG passphrase is required}"
: "${VOLLCRYPT_RELEASE_GPG_FINGERPRINT:?release GPG fingerprint is required}"

ASSETS=$(realpath "$1")
test -d "$ASSETS"
GNUPGHOME=$(mktemp -d)
KEY_FILE=$(mktemp)
PASS_FILE=$(mktemp)
export GNUPGHOME

cleanup() {
  chmod -R u+rwX "$GNUPGHOME" 2>/dev/null || true
  rm -rf -- "$GNUPGHOME"
  rm -f -- "$KEY_FILE" "$PASS_FILE"
}
trap cleanup EXIT INT TERM

chmod 0700 "$GNUPGHOME"
chmod 0600 "$KEY_FILE" "$PASS_FILE"
printf '%s' "$VOLLCRYPT_RELEASE_GPG_PRIVATE_KEY_BASE64" | base64 --decode > "$KEY_FILE"
printf '%s' "$VOLLCRYPT_RELEASE_GPG_PASSPHRASE" > "$PASS_FILE"
gpg --batch --quiet --import "$KEY_FILE"

EXPECTED=$(printf '%s' "$VOLLCRYPT_RELEASE_GPG_FINGERPRINT" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
ACTUAL=$(gpg --batch --with-colons --list-secret-keys "$EXPECTED" |
  awk -F: '$1 == "fpr" { print toupper($10); exit }')
if [ -z "$ACTUAL" ] || [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "imported release key fingerprint does not match the pinned fingerprint" >&2
  exit 65
fi

gpg --batch --armor --export "$EXPECTED" > "$ASSETS/VOLLCRYPT_RELEASE_SIGNING_KEY.asc"
cat > "$ASSETS/SIGNING_IDENTITY.txt" <<EOF
Repository: https://github.com/BeratVural/vollcrypt
Release signing fingerprint: $EXPECTED
EOF

mapfile -d '' FILES < <(find "$ASSETS" -maxdepth 1 -type f ! -name '*.asc' -print0 | sort -z)
test "${#FILES[@]}" -gt 0
for file in "${FILES[@]}"; do
  gpg --batch --yes --armor --detach-sign +    --pinentry-mode loopback +    --passphrase-file "$PASS_FILE" +    --local-user "$EXPECTED" +    --output "$file.asc" +    "$file"
  gpg --batch --verify "$file.asc" "$file"
done

#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <release-binary> <output-directory> <deb|rpm>" >&2
  exit 64
fi

BINARY=$(realpath "$1")
OUTPUT=$(realpath -m "$2")
FORMAT=$3
case "$FORMAT" in
  deb|rpm) ;;
  *) echo "package format must be deb or rpm" >&2; exit 64 ;;
esac
test -x "$BINARY"
mkdir -p "$OUTPUT"
test -d "$OUTPUT"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ASSETS=$(realpath "$SCRIPT_DIR/../packaging/linux")
VERSION=$($BINARY --version | awk '{print $NF}')
case "$VERSION" in
  ''|*[!0-9.]*|.*|*.) echo "binary reported an invalid package version: $VERSION" >&2; exit 65 ;;
esac

WORK=$(mktemp -d /tmp/vollcrypt-shield-package.XXXXXX)
cleanup() {
  rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

install_payload() {
  root=$1
  install -D -m 0755 "$BINARY" "$root/usr/bin/vollcrypt-shield"
  install -D -m 0644 "$ASSETS/vollcrypt-shield@.service" "$root/usr/lib/systemd/system/vollcrypt-shield@.service"
  install -D -m 0644 "$ASSETS/vollcrypt-shield.sysusers" "$root/usr/lib/sysusers.d/vollcrypt-shield.conf"
  install -D -m 0644 "$ASSETS/vollcrypt-shield.tmpfiles" "$root/usr/lib/tmpfiles.d/vollcrypt-shield.conf"
  install -D -m 0644 "$ASSETS/README.md" "$root/usr/share/doc/vollcrypt-shield/README.md"
  install -d -m 0750 "$root/etc/vollcrypt-shield"
}

if [ "$FORMAT" = deb ]; then
  ARCH=$(dpkg --print-architecture)
  ROOT="$WORK/deb"
  install_payload "$ROOT"
  install -d -m 0755 "$ROOT/DEBIAN"
  cat > "$ROOT/DEBIAN/control" <<EOF
Package: vollcrypt-shield
Version: $VERSION
Architecture: $ARCH
Maintainer: Vollcrypt <security@vollcrypt.dev>
Depends: libc6, systemd
Section: admin
Priority: optional
Description: tamper-evident integrity agent with scoped active response
 Vollcrypt Shield verifies signed Merkle baselines and provides fail-closed,
 reversible response for explicitly configured filesystem scopes.
EOF
  cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemd-sysusers /usr/lib/sysusers.d/vollcrypt-shield.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/vollcrypt-shield.conf
systemctl daemon-reload >/dev/null 2>&1 || true
EOF
  cat > "$ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop 'vollcrypt-shield@*.service' >/dev/null 2>&1 || true
fi
EOF
  cat > "$ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
EOF
  chmod 0755 "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm" "$ROOT/DEBIAN/postrm"
  PACKAGE="$OUTPUT/vollcrypt-shield_${VERSION}_${ARCH}.deb"
  dpkg-deb --root-owner-group --build "$ROOT" "$PACKAGE"
else
  ARCH=$(rpm --eval '%{_arch}')
  RPM_ROOT="$WORK/rpmbuild"
  mkdir -p "$RPM_ROOT/BUILD" "$RPM_ROOT/BUILDROOT" "$RPM_ROOT/RPMS" "$RPM_ROOT/SOURCES" "$RPM_ROOT/SPECS" "$RPM_ROOT/SRPMS"
  install -m 0755 "$BINARY" "$RPM_ROOT/SOURCES/vollcrypt-shield"
  cp "$ASSETS/vollcrypt-shield@.service" "$RPM_ROOT/SOURCES/"
  cp "$ASSETS/vollcrypt-shield.sysusers" "$RPM_ROOT/SOURCES/"
  cp "$ASSETS/vollcrypt-shield.tmpfiles" "$RPM_ROOT/SOURCES/"
  cp "$ASSETS/README.md" "$RPM_ROOT/SOURCES/README.packaging.md"
  cat > "$RPM_ROOT/SPECS/vollcrypt-shield.spec" <<EOF
Name: vollcrypt-shield
Version: $VERSION
Release: 1%{?dist}
Summary: Tamper-evident integrity agent with scoped active response
License: GPL-3.0-only OR LicenseRef-Commercial
Source0: vollcrypt-shield
Source1: vollcrypt-shield@.service
Source2: vollcrypt-shield.sysusers
Source3: vollcrypt-shield.tmpfiles
Source4: README.packaging.md
Requires: systemd
Requires(pre): shadow-utils
BuildArch: $ARCH

%description
Vollcrypt Shield verifies signed Merkle baselines and provides fail-closed,
reversible response for explicitly configured filesystem scopes.

%install
install -D -m 0755 %{SOURCE0} %{buildroot}/usr/bin/vollcrypt-shield
install -D -m 0644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/vollcrypt-shield@.service
install -D -m 0644 %{SOURCE2} %{buildroot}/usr/lib/sysusers.d/vollcrypt-shield.conf
install -D -m 0644 %{SOURCE3} %{buildroot}/usr/lib/tmpfiles.d/vollcrypt-shield.conf
install -D -m 0644 %{SOURCE4} %{buildroot}/usr/share/doc/vollcrypt-shield/README.md
install -d -m 0750 %{buildroot}/etc/vollcrypt-shield

%pre
/usr/bin/getent group vollcrypt-shield >/dev/null 2>&1 || /usr/sbin/groupadd -r vollcrypt-shield
/usr/bin/getent passwd vollcrypt-shield >/dev/null 2>&1 || /usr/sbin/useradd -r -g vollcrypt-shield -d /var/lib/vollcrypt-shield -s /sbin/nologin -c 'Vollcrypt Shield integrity agent' vollcrypt-shield

%post
/usr/bin/systemd-tmpfiles --create /usr/lib/tmpfiles.d/vollcrypt-shield.conf
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :

%preun
if [ \$1 -eq 0 ]; then
  /usr/bin/systemctl stop 'vollcrypt-shield@*.service' >/dev/null 2>&1 || :
fi

%postun
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :

%files
%dir %attr(0750,root,vollcrypt-shield) /etc/vollcrypt-shield
/usr/bin/vollcrypt-shield
/usr/lib/systemd/system/vollcrypt-shield@.service
/usr/lib/sysusers.d/vollcrypt-shield.conf
/usr/lib/tmpfiles.d/vollcrypt-shield.conf
%doc /usr/share/doc/vollcrypt-shield/README.md
EOF
  rpmbuild --define "_topdir $RPM_ROOT" -bb "$RPM_ROOT/SPECS/vollcrypt-shield.spec"
  BUILT=$(find "$RPM_ROOT/RPMS" -type f -name '*.rpm' -print -quit)
  test -n "$BUILT"
  rpm -qp --scripts "$BUILT" | grep -Fq '/usr/lib/tmpfiles.d/vollcrypt-shield.conf'
  if rpm -qp --scripts "$BUILT" | grep -Fq '%{'; then
    echo "RPM scriptlets contain an unexpanded macro" >&2
    exit 1
  fi
  PACKAGE="$OUTPUT/$(basename "$BUILT")"
  cp "$BUILT" "$PACKAGE"
fi

test -s "$PACKAGE"
printf '%s\n' "$PACKAGE"

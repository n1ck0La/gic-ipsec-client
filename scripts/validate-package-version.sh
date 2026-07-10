#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
PACKAGE_RELEASE="$(tr -d '[:space:]' < PACKAGE_RELEASE)"
FULL_VERSION="${VERSION}-${PACKAGE_RELEASE}"

fail() {
  echo "version validation failed: $*" >&2
  exit 1
}

python3 - "$VERSION" "$PACKAGE_RELEASE" <<'PY'
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

version, release = sys.argv[1:3]

pyproject_version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))[
    "project"
]["version"]
if pyproject_version != version:
    raise SystemExit(f"pyproject.toml version {pyproject_version} != {version}")

version_py = Path("src/gic_ipsec_client/_version.py").read_text(encoding="utf-8")
if f'__version__ = "{version}"' not in version_py:
    raise SystemExit("_version.py does not match VERSION")

spec = Path("packaging/fedora/gic-ipsec-client.spec").read_text(encoding="utf-8")
if not re.search(rf"(?m)^Version:\s+{re.escape(version)}$", spec):
    raise SystemExit("RPM spec Version does not match VERSION")
if not re.search(rf"(?m)^Release:\s+{re.escape(release)}%{{\?dist}}$", spec):
    raise SystemExit("RPM spec Release does not match PACKAGE_RELEASE")

changelog = Path("debian/changelog").read_text(encoding="utf-8")
if f"gic-ipsec-client ({version}-{release})" not in changelog:
    raise SystemExit("debian/changelog does not match VERSION/PACKAGE_RELEASE")
PY

for file in VERSION pyproject.toml src/gic_ipsec_client/_version.py \
  packaging/fedora/gic-ipsec-client.spec debian/changelog; do
  if grep -q '0\.1\.0' "$file"; then
    fail "$file still contains 0.1.0"
  fi
done

if [ -d dist ]; then
  if find dist -maxdepth 1 -type f \( -name '*.rpm' -o -name '*.deb' \) -name '*0.1.0*' \
    | grep -q .; then
    fail "dist contains stale 0.1.0 package artifacts"
  fi
  while IFS= read -r package_file; do
    case "$(basename "$package_file")" in
      *"${VERSION}-${PACKAGE_RELEASE}"*) ;;
      *) fail "$package_file does not contain ${VERSION}-${PACKAGE_RELEASE}" ;;
    esac
  done < <(find dist -maxdepth 1 -type f \( -name '*.rpm' -o -name '*.deb' \))

  shopt -s nullglob
  rpm_files=(dist/gic-ipsec-client-"${VERSION}"-"${PACKAGE_RELEASE}"*.rpm)
  deb_files=(dist/gic-ipsec-client_"${VERSION}"-"${PACKAGE_RELEASE}"_*.deb)
  shopt -u nullglob

  if [ "${#rpm_files[@]}" -gt 0 ] && command -v rpm >/dev/null 2>&1; then
    rpm_version="$(rpm -qp --qf '%{VERSION}' "${rpm_files[0]}")"
    rpm_release="$(rpm -qp --qf '%{RELEASE}' "${rpm_files[0]}")"
    [ "$rpm_version" = "$VERSION" ] || fail "RPM metadata version $rpm_version != $VERSION"
    [[ "$rpm_release" == "$PACKAGE_RELEASE"* ]] || {
      fail "RPM metadata release $rpm_release does not start with $PACKAGE_RELEASE"
    }
  fi

  if [ "${#deb_files[@]}" -gt 0 ] && command -v dpkg-deb >/dev/null 2>&1; then
    deb_version="$(dpkg-deb -f "${deb_files[0]}" Version)"
    [ "$deb_version" = "$FULL_VERSION" ] || {
      fail "DEB metadata version $deb_version != $FULL_VERSION"
    }
  fi
fi

if [ "${CHECK_INSTALLED_VERSION:-0}" = "1" ]; then
  if command -v gic-ipsec-client >/dev/null 2>&1; then
    gic-ipsec-client --version | grep -Fx "gic-ipsec-client ${VERSION}" >/dev/null || {
      fail "gic-ipsec-client --version does not match $VERSION"
    }
  fi

  if command -v gic-ipsec-helper >/dev/null 2>&1; then
    gic-ipsec-helper --version | grep -Fx "gic-ipsec-helper ${VERSION}" >/dev/null || {
      fail "gic-ipsec-helper --version does not match $VERSION"
    }
  fi

  if [ -x /usr/libexec/gic-ipsec-client/gic-ipsec-helper ]; then
    /usr/libexec/gic-ipsec-client/gic-ipsec-helper --version \
      | grep -Fx "gic-ipsec-helper ${VERSION}" >/dev/null || {
        fail "installed helper --version does not match $VERSION"
      }
  fi
fi

echo "Version validation passed for ${FULL_VERSION}"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-$(tr -d '[:space:]' < VERSION)}"
PACKAGE_RELEASE="${PACKAGE_RELEASE:-$(tr -d '[:space:]' < PACKAGE_RELEASE)}"
RPM_RELEASE="${RPM_RELEASE:-$PACKAGE_RELEASE}"
DEB_RELEASE="${DEB_RELEASE:-$PACKAGE_RELEASE}"
NFPM="${NFPM:-nfpm}"

if [ "${APPEND_GIT_RELEASE:-0}" = "1" ] && [ "${GITHUB_REF_TYPE:-}" != "tag" ]; then
  short_sha="${GITHUB_SHA:-$(git rev-parse --short HEAD 2>/dev/null || true)}"
  if [ -n "$short_sha" ]; then
    RPM_RELEASE="${RPM_RELEASE}.git${short_sha}"
    DEB_RELEASE="${DEB_RELEASE}+git${short_sha}"
  fi
fi

if ! command -v "$NFPM" >/dev/null 2>&1; then
  cat >&2 <<'EOF'
nfpm is required to build .deb/.rpm packages, but it was not found.

Install nfpm from your distro packages or from the nfpm project, then retry.
You can also set NFPM=/absolute/path/to/nfpm when running this script.
EOF
  exit 127
fi

rm -rf build/package dist
mkdir -p build/package/app build/package/venv dist

python3 -m venv build/package/venv
build/package/venv/bin/python -m pip install --upgrade pip
build/package/venv/bin/python -m pip install .

cp -a README.md pyproject.toml src build/package/app/

VERSION="$VERSION" PACKAGE_RELEASE="$DEB_RELEASE" "$NFPM" pkg \
  --config packaging/nfpm.yaml \
  --packager deb \
  --target "dist/gic-ipsec-client_${VERSION}-${DEB_RELEASE}_amd64.deb"
VERSION="$VERSION" PACKAGE_RELEASE="$RPM_RELEASE" "$NFPM" pkg \
  --config packaging/nfpm.yaml \
  --packager rpm \
  --target "dist/gic-ipsec-client-${VERSION}-${RPM_RELEASE}.x86_64.rpm"

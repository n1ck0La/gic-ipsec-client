#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])' 2>/dev/null || echo 0.1.0)}"
NFPM="${NFPM:-nfpm}"

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

VERSION="$VERSION" "$NFPM" pkg --config packaging/nfpm.yaml --packager deb \
  --target "dist/gic-ipsec-client_${VERSION}_amd64.deb"
VERSION="$VERSION" "$NFPM" pkg --config packaging/nfpm.yaml --packager rpm \
  --target "dist/gic-ipsec-client-${VERSION}-1.x86_64.rpm"

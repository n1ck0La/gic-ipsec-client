#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])' 2>/dev/null || echo 0.1.0)}"

cd "$ROOT"
rm -rf build/package dist
mkdir -p build/package/app build/package/venv dist

python3 -m venv build/package/venv
build/package/venv/bin/python -m pip install --upgrade pip
build/package/venv/bin/python -m pip install .

cp -a README.md pyproject.toml src build/package/app/

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm is required to build .deb/.rpm packages." >&2
  exit 1
fi

VERSION="$VERSION" nfpm pkg --config packaging/nfpm.yaml --packager deb \
  --target "dist/see-ipsec-client_${VERSION}_amd64.deb"
VERSION="$VERSION" nfpm pkg --config packaging/nfpm.yaml --packager rpm \
  --target "dist/see-ipsec-client-${VERSION}-1.x86_64.rpm"

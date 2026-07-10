#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 patch|minor|major" >&2
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

part="$1"
case "$part" in
  patch|minor|major) ;;
  *)
    usage
    exit 2
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

current="$(tr -d '[:space:]' < VERSION)"
if [[ ! "$current" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "VERSION must be semantic X.Y.Z, got: $current" >&2
  exit 1
fi

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"

case "$part" in
  patch)
    patch=$((patch + 1))
    ;;
  minor)
    minor=$((minor + 1))
    patch=0
    ;;
  major)
    major=$((major + 1))
    minor=0
    patch=0
    ;;
esac

new_version="${major}.${minor}.${patch}"
package_release="1"
changelog_date="$(date -R)"

python3 - "$new_version" "$package_release" "$changelog_date" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

version, package_release, changelog_date = sys.argv[1:4]

replacements = {
    Path("VERSION"): version + "\n",
    Path("PACKAGE_RELEASE"): package_release + "\n",
}

for path, content in replacements.items():
    path.write_text(content, encoding="utf-8")

files = {
    Path("pyproject.toml"): (
        r'(?m)^version = "[0-9]+\.[0-9]+\.[0-9]+"$',
        f'version = "{version}"',
    ),
    Path("src/gic_ipsec_client/_version.py"): (
        r'(?m)^__version__ = "[0-9]+\.[0-9]+\.[0-9]+"$',
        f'__version__ = "{version}"',
    ),
    Path("packaging/fedora/gic-ipsec-client.spec"): (
        r"(?m)^Version:\s+[0-9]+\.[0-9]+\.[0-9]+$",
        f"Version:        {version}",
    ),
}

for path, (pattern, replacement) in files.items():
    text = path.read_text(encoding="utf-8")
    updated = re.sub(pattern, replacement, text)
    updated = re.sub(
        r"(?m)^Release:\s+[^\n]+$",
        f"Release:        {package_release}%{{?dist}}",
        updated,
    ) if path.name == "gic-ipsec-client.spec" else updated
    if updated == text:
        raise SystemExit(f"No replacement made in {path}")
    path.write_text(updated, encoding="utf-8")

changelog = Path("debian/changelog")
changelog.write_text(
    "\n".join(
        [
            f"gic-ipsec-client ({version}-{package_release}) unstable; urgency=medium",
            "",
            f"  * Release {version}.",
            "",
            f" -- GIC IPsec Client contributors <noreply@example.invalid>  {changelog_date}",
            "",
        ]
    ),
    encoding="utf-8",
)
PY

echo "Bumped version to ${new_version}-${package_release}"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

version="$(tr -d '[:space:]' < VERSION)"
release="$(tr -d '[:space:]' < PACKAGE_RELEASE)"
if [[ ! "$release" =~ ^[0-9]+$ ]]; then
  echo "PACKAGE_RELEASE must be numeric for automatic bumps, got: $release" >&2
  exit 1
fi

new_release=$((release + 1))
changelog_date="$(date -R)"

python3 - "$version" "$new_release" "$changelog_date" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

version, release, changelog_date = sys.argv[1:4]

Path("PACKAGE_RELEASE").write_text(release + "\n", encoding="utf-8")

spec = Path("packaging/fedora/gic-ipsec-client.spec")
text = spec.read_text(encoding="utf-8")
spec.write_text(
    re.sub(r"(?m)^Release:\s+[^\n]+$", f"Release:        {release}%{{?dist}}", text),
    encoding="utf-8",
)

Path("debian/changelog").write_text(
    "\n".join(
        [
            f"gic-ipsec-client ({version}-{release}) unstable; urgency=medium",
            "",
            f"  * Packaging rebuild for {version}.",
            "",
            f" -- GIC IPsec Client contributors <noreply@example.invalid>  {changelog_date}",
            "",
        ]
    ),
    encoding="utf-8",
)
PY

echo "Bumped package release to ${version}-${new_release}"

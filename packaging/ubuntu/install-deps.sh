#!/usr/bin/env sh
set -eu

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not found. This script is for Ubuntu/Debian-style systems." >&2
  exit 1
fi

check_pkg() {
  pkg="$1"
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    printf '%s\n' "$pkg"
  else
    printf 'missing:%s\n' "$pkg"
  fi
}

packages="
python3
python3-pip
python3-venv
strongswan-swanctl
charon-systemd
strongswan
strongswan-libcharon-extra-plugins
policykit-1
polkitd
libsecret-1-0
libsecret-tools
"

installable=""
echo "Checking package availability..."
for pkg in $packages; do
  result="$(check_pkg "$pkg")"
  case "$result" in
    missing:*) echo "  unavailable or renamed: ${result#missing:}" ;;
    *) echo "  available: $result"; installable="$installable $result" ;;
  esac
done

echo
echo "Install command:"
echo "  sudo apt-get update && sudo apt-get install$installable"
echo
echo "If charon-systemd is unavailable on your release, install the distro's strongSwan service package."

#!/usr/bin/env sh
set -eu

if ! command -v dnf >/dev/null 2>&1; then
  echo "dnf not found. This script is for Fedora/RHEL-style systems." >&2
  exit 1
fi

check_pkg() {
  pkg="$1"
  if dnf -q repoquery "$pkg" >/dev/null 2>&1; then
    printf '%s\n' "$pkg"
  else
    printf 'missing:%s\n' "$pkg"
  fi
}

packages="
python3
python3-pip
strongswan
polkit
NetworkManager
systemd-resolved
iproute
bind-utils
libsecret
libsecret-devel
"

installable=""
echo "Checking package availability..."
for pkg in $packages; do
  result="$(check_pkg "$pkg")"
  case "$result" in
    missing:*) echo "  unavailable or packaged differently: ${result#missing:}" ;;
    *) echo "  available: $result"; installable="$installable $result" ;;
  esac
done

echo
echo "Install command:"
echo "  sudo dnf install$installable"
echo
echo "NetworkManager-libreswan is optional fallback tooling, not GIC IPsec Client's primary backend."

# GIC IPsec Client

GIC IPsec Client is a Linux desktop VPN client for multiple IKEv2 remote-access
profiles. It uses the system strongSwan `swanctl`/VICI backend and delegates
root-only operations to a small `pkexec` helper.

The app does not ship any customer or site profile. Users create or import
profiles, and secrets are stored only through Linux Secret Service/keyring.

## Features

- Multi-profile GUI for add, edit, clone, delete, import, export, connect,
  disconnect, DNS testing, and diagnostics export.
- Nested profile model for gateway, authentication, traffic, DNS, crypto, and
  platform settings.
- Dynamic `swanctl` rendering from profile data only.
- Fedora and Debian/Ubuntu `swanctl` config-root detection.
- Split and full tunnel rendering.
- App-managed Fedora `systemd-resolved` DNS fallback with rollback snapshots.
- Sanitized diagnostics and debug bundles.
- nfpm-based `.deb` and `.rpm` packaging skeleton.

## Development

```bash
git clone https://github.com/n1ck0La/gic-ipsec-client
cd gic-ipsec-client
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
python -m ruff check .
```

Run the GUI:

```bash
python -m gic_ipsec_client
```

Run the helper:

```bash
python -m gic_ipsec_client.helper.cli --help
```

## Packaging

Install nfpm.

Ubuntu:
```bash
echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list
sudo apt update
sudo apt install nfpm
```
Fedora:
```bash
sudo tee /etc/yum.repos.d/goreleaser.repo <<'EOF'
[goreleaser]
name=GoReleaser
baseurl=https://repo.goreleaser.com/yum/
enabled=1
gpgcheck=0
EOF
sudo dnf install nfpm
```

Then run:

```bash
bash ./packaging/build-packages.sh
```

Expected outputs:

- `dist/gic-ipsec-client_<version>_amd64.deb`
- `dist/gic-ipsec-client-<version>-1.x86_64.rpm`

Install the local Ubuntu package with `apt` so package dependencies are resolved:

```bash
sudo apt update
sudo apt install ./gic-ipsec-client_0.1.0_amd64.deb
```

If you already tried installing with `dpkg -i`, repair dependencies with:

```bash
sudo apt -f install
```

Install the local Fedora package with `dnf` so package dependencies are resolved:

```bash
sudo dnf install ./gic-ipsec-client-0.1.0-1.x86_64.rpm
```

The package layout installs:

- `/opt/gic-ipsec-client/app`
- `/opt/gic-ipsec-client/venv`
- `/usr/bin/gic-ipsec-client`
- `/usr/libexec/gic-ipsec-client/gic-ipsec-helper`
- `/usr/share/applications/gic-ipsec-client.desktop`
- `/usr/share/icons/hicolor/scalable/apps/gic-ipsec-client.svg`
- `/usr/share/polkit-1/actions/com.gicipsec.client.policy`
- `/etc/gic-ipsec-client/defaults.json`

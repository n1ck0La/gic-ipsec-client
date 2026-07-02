# SEE IPsec Client

SEE IPsec Client is a Linux desktop VPN client for multiple IKEv2 remote-access
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
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
ruff check .
```

Run the GUI:

```bash
python -m gic_ipsec_client
```

Run the helper:

```bash
see-ipsec-helper --help
```

## Packaging

Install nfpm, then run:

```bash
./packaging/build-packages.sh
```

Expected outputs:

- `dist/see-ipsec-client_<version>_amd64.deb`
- `dist/see-ipsec-client-<version>-1.x86_64.rpm`

The package layout installs:

- `/opt/see-ipsec-client/app`
- `/opt/see-ipsec-client/venv`
- `/usr/bin/see-ipsec-client`
- `/usr/libexec/see-ipsec-client/see-ipsec-helper`
- `/usr/share/applications/see-ipsec-client.desktop`
- `/usr/share/icons/hicolor/256x256/apps/see-ipsec-client.png`
- `/usr/share/polkit-1/actions/com.see.ipsecclient.policy`
- `/etc/see-ipsec-client/defaults.json`

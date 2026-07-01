# GIC IPsec Client

GIC (GUI IPsec Client) is a Linux desktop VPN client for IKEv2 remote access
profiles. It uses the system strongSwan `swanctl`/VICI backend and does not
implement IPsec, IKE, ESP, cryptography, kernel tunnel handling, packet capture,
or a password store.

The first profile type targets FortiGate-compatible IKEv2 remote access with a
PSK for gateway/IKE authentication and EAP-MSCHAPv2 username/password
authentication for the user.

## What It Does

- Provides a PySide6/Qt6 desktop GUI for profiles, connect/disconnect, status,
  logs, diagnostics, and sanitized debug bundle export.
- Renders validated strongSwan `swanctl` connection and secrets files.
- Uses UUIDs for root-side config filenames.
- Invokes privileged work through `pkexec gic-ipsec-helper`.
- Redacts PSKs and passwords from logs and debug bundles.
- Can save user secrets only through Python keyring/libsecret when available.

## What It Does Not Do

- It does not implement IPsec/IKE crypto or packet processing.
- It does not replace strongSwan.
- It does not silently install packages.
- It does not save plaintext secrets when no secure keyring is available.
- It does not support FortiClient-only EMS/ZTNA/proprietary overlay features.

## Ubuntu Setup

```bash
cd gic-ipsec-client
./packaging/ubuntu/install-deps.sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Package names vary by Ubuntu release. The install script checks likely package
names and prints actionable messages when a package is unavailable.

## Fedora Setup

```bash
cd gic-ipsec-client
./packaging/fedora/install-deps.sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

NetworkManager-libreswan can be useful for other VPN workflows, but it is not
the primary backend for GIC.

## Development

Run the GUI:

```bash
python -m gic_ipsec_client
```

Run the helper directly for development:

```bash
gic-ipsec-helper --help
```

Build a local wheel:

```bash
python -m pip install build
python -m build
```

Run tests and lint:

```bash
pytest
ruff check .
```

## FortiGate Profile Flow

1. Create a profile with the FortiGate preset.
2. Enter the gateway FQDN/IP, username/EAP identity, PSK, and user password.
   Use Advanced > Strict remote ID only when the gateway requires a fixed IKE
   identity.
3. Start with UDP transport and IKE port 500.
4. Choose Split tunnel for internal routes only or Full tunnel for all traffic.
   Split tunnel requires at least one remote route; the editor can add the SEE
   FortiGate route preset list in one click. Full tunnel requires an
   IPsec-to-WAN FortiGate firewall policy with NAT enabled.
5. Use Test profile render before connecting.
6. Connect. GIC detects the active `swanctl` config root, writes
   `conf.d/gic-<uuid>.conf` through the helper, runs `swanctl --load-all`,
   verifies the generated connection appears in `swanctl --list-conns`, and
   only then initiates the child SA.

## Known Limitations

- EAP-MSCHAPv2 is implemented first. EAP-TTLS/PAP is a future extension.
- TCP transport is treated as a compatibility mode and still needs real gateway
  testing.
- DNS integration depends on the installed strongSwan resolve or
  systemd-resolved integration.
- Real connection behavior must be tested with target FortiGate and strongSwan
  packages on each distro release.

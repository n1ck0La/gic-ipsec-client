# Troubleshooting

## Client-Side Commands

```bash
pkexec /usr/libexec/gic-ipsec-client/gic-ipsec-helper list-sas
pkexec /usr/libexec/gic-ipsec-client/gic-ipsec-helper list-conns
pkexec /usr/libexec/gic-ipsec-client/gic-ipsec-helper diagnostics --profile-uuid <uuid>
journalctl -u strongswan* -u charon-systemd --since "10 minutes ago"
ip route
resolvectl status
```

If `resolvectl` is not available, check NetworkManager DNS details:

```bash
nmcli device show
```

## Common Client Checks

- Confirm `swanctl` is installed and can reach the VICI socket.
- Confirm a strongSwan service such as `strongswan-starter`, `strongswan`, or
  `charon-systemd` is active.
- Confirm `/run/charon.vici` or `/var/run/charon.vici` exists.
- Confirm the `vici`, `eap-identity`, `eap-mschapv2`, `kernel-netlink`, and DNS
  integration plugins are installed.
- Run GIC diagnostics and export a sanitized bundle when asking for help.
- Verify the generated `conf.d/gic-<uuid>.conf` exists under the selected
  `swanctl` config root. On Fedora this is normally
  `/etc/strongswan/swanctl`; on Ubuntu/Debian it is normally `/etc/swanctl`.
- On Fedora with systemd-resolved stub DNS and split tunnel, GIC first applies
  route-only VPN DNS domains to `lo` with `resolvectl`. If verification shows
  queries still using the physical link, GIC snapshots the default interface,
  applies the route-only VPN DNS domains there, flushes caches, and resets
  resolver server features. On disconnect, GIC restores the saved DNS servers,
  domains, and default-route state before terminating the IKE_SA. If explicit
  restore fails, it runs `nmcli dev reapply <interface>`. The old `gicipsec0`
  dummy link is retained only for cleanup and diagnostics of earlier runs.

## FortiGate-Side Hints

- Check UDP/500 and UDP/4500 reachability.
- Use packet sniffer for UDP 500/4500 and ESP.
- Use IKE debug only with filters.
- Check phase1, phase2, mode-cfg address pool, user group, firewall policy, and
  split routes.
- Start with UDP transport before testing TCP compatibility modes.

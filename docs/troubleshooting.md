# Troubleshooting

## Client-Side Commands

```bash
pkexec gic-ipsec-helper list-sas
pkexec gic-ipsec-helper list-conns
pkexec gic-ipsec-helper diagnostics --profile-uuid <uuid>
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
- Confirm a strongSwan service such as `charon-systemd` or `strongswan` is
  active.
- Confirm the `vici`, `eap-identity`, `eap-mschapv2`, `kernel-netlink`, and DNS
  integration plugins are installed.
- Run GIC diagnostics and export a sanitized bundle when asking for help.
- Verify the generated `conf.d/gic-<uuid>.conf` exists under the selected
  `swanctl` config root. On Fedora this is normally
  `/etc/strongswan/swanctl`; on Ubuntu/Debian it is normally `/etc/swanctl`.
- On Fedora with systemd-resolved stub DNS, GIC applies DNS to the active
  default physical link with `resolvectl` because policy-based strongSwan does
  not create a normal VPN interface.

## FortiGate-Side Hints

- Check UDP/500 and UDP/4500 reachability.
- Use packet sniffer for UDP 500/4500 and ESP.
- Use IKE debug only with filters.
- Check phase1, phase2, mode-cfg address pool, user group, firewall policy, and
  split routes.
- Start with UDP transport before testing TCP compatibility modes.

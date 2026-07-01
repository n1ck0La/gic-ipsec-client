# Troubleshooting

## Client-Side Commands

```bash
swanctl --list-sas
swanctl --list-conns
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
- Verify `/etc/swanctl/secrets.d/gic-ipsec/<uuid>.secrets` is owned by root and
  mode `0600`.

## FortiGate-Side Hints

- Check UDP/500 and UDP/4500 reachability.
- Use packet sniffer for UDP 500/4500 and ESP.
- Use IKE debug only with filters.
- Check phase1, phase2, mode-cfg address pool, user group, firewall policy, and
  split routes.
- Start with UDP transport before testing TCP compatibility modes.

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

- Confirm `strongswan.service` is active. GIC uses the `swanctl`/VICI backend;
  `strongswan-starter.service` is incompatible and is disabled during Connect.
- Run `swanctl --list-conns`. A zero exit status is the readiness check for VICI.
  A `charon.vici` file by itself can be stale and does not prove that VICI works.
- On Fedora, when `/run/strongswan/charon.vici` exists, GIC uses
  `swanctl --uri unix:///run/strongswan/charon.vici ...` for every VICI command.
- Fedora Connect always writes the selected profile to
  `/etc/strongswan/swanctl/conf.d/gic-<uuid>.conf` before service startup or
  `swanctl --load-all`, even if an older saved setting selected `/etc/swanctl`.
- GIC diagnostics separately report file existence, `ss -lx` listening state,
  and `swanctl --list-conns` connectivity for these paths:
  `/run/strongswan/charon.vici`, `/var/run/strongswan/charon.vici`,
  `/run/charon.vici`, and `/var/run/charon.vici`.
- If VICI recovery is required, GIC stops both `strongswan.service` and
  `strongswan-starter.service` before removing any known stale VICI path, then
  starts `strongswan.service`. It never removes a VICI path while either service
  is still active.
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

## Optional Passwordless Polkit Rule

The packaged policy uses `auth_admin_keep`, so one authentication can be reused
for a short polkit authorization window. Administrators who accept the security
tradeoff can instead authorize active local members of `wheel` or `sudo` without
a password by creating `/etc/polkit-1/rules.d/49-gic-ipsec-client.rules`:

```javascript
polkit.addRule(function(action, subject) {
    if (action.id == "com.gicipsec.client.helper" &&
        subject.active && subject.local &&
        (subject.isInGroup("wheel") || subject.isInGroup("sudo"))) {
        return polkit.Result.YES;
    }
});
```

This grants those groups passwordless access to all privileged GIC helper
actions. Create the rule only on systems where that is appropriate.

## FortiGate-Side Hints

- Check UDP/500 and UDP/4500 reachability.
- Use packet sniffer for UDP 500/4500 and ESP.
- Use IKE debug only with filters.
- Check phase1, phase2, mode-cfg address pool, user group, firewall policy, and
  split routes.
- Start with UDP transport before testing TCP compatibility modes.

# Sample swanctl Output

Example `swanctl --list-sas` output shape for a connected profile:

```text
see-ipsec-00000000-0000-4000-8000-000000000000: #1, ESTABLISHED, IKEv2, ...
  local  'user@example.com' @ 10.10.10.25[4500]
  remote 'vpn.example.com' @ 203.0.113.10[4500]
  see-ipsec-00000000-0000-4000-8000-000000000000-child: #1, reqid 1, INSTALLED, TUNNEL
    local  10.250.10.5/32
    remote 10.0.0.0/8
```

Sanitized debug bundles should keep this operational shape while removing PSKs
and passwords.

# FortiGate Profile

SEE IPsec Client supports FortiGate IKEv2 remote access with:

- FortiGate/gateway authentication by PSK.
- User authentication by EAP-MSCHAPv2 username/password.
- UDP transport by default.
- Mode-config virtual IP assignment.
- Optional split tunnel routes.

Avoid FortiClient-only options for the first version. Avoid EMS serial checks,
ZTNA posture requirements, FortiClient-only network overlay behavior, and
proprietary Network ID unless specifically tested. Start with UDP transport.
TCP transport should be a later compatibility mode, not the default.

## Reference FortiGate Configuration

Replace placeholders before use.

```text
config firewall address
    edit "SEE-VPN-CLIENT-RANGE"
        set type iprange
        set start-ip <VPN_POOL_START>
        set end-ip <VPN_POOL_END>
    next
    edit "SEE-LAN"
        set subnet <LAN_SUBNET> <LAN_MASK>
    next
end

config user group
    edit "SEE-VPN-USERS"
        set member <LOCAL_OR_REMOTE_USERS_OR_GROUPS>
    next
end

config vpn ipsec phase1-interface
    edit "see-linux-ikev2"
        set type dynamic
        set interface "wan1"
        set ike-version 2
        set peertype any
        set net-device disable
        set mode-cfg enable
        set proposal aes128-sha256 aes256-sha256
        set dhgrp 14 19 20
        set eap enable
        set eap-identity send-request
        set authusrgrp "SEE-VPN-USERS"
        set transport udp
        set assign-ip-from name
        set ipv4-name "SEE-VPN-CLIENT-RANGE"
        set dns-mode auto
        set ipv4-split-include "SEE-LAN"
        set psksecret <REPLACE_WITH_STRONG_PSK>
    next
end

config vpn ipsec phase2-interface
    edit "see-linux-ikev2-p2"
        set phase1name "see-linux-ikev2"
        set proposal aes128-sha256 aes256-sha256
    next
end

config firewall policy
    edit 0
        set name "SEE Linux IPsec to LAN"
        set srcintf "see-linux-ikev2"
        set dstintf "<LAN_INTERFACE>"
        set action accept
        set srcaddr "SEE-VPN-CLIENT-RANGE"
        set dstaddr "SEE-LAN"
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

## Client-Side Matching Values

- `gateway_fqdn_or_ip`: public FortiGate address.
- `Strict remote ID`: optional. Leave empty for the FortiGate PSK+EAP default,
  which renders `remote.id=%any` and IKE secret `id-1/id-2=%any`.
- `username` and `eap_identity`: the user allowed by `SEE-VPN-USERS`.
- `psk`: the FortiGate `psksecret`.
- `ike_proposals`: keep the default FortiGate-compatible values first.
- `esp_proposals`: keep the default FortiGate-compatible values first.

Name:           gic-ipsec-client
Version:        0.1.0
Release:        1%{?dist}
Summary:        strongSwan-backed multi-site IKEv2 VPN client

License:        MIT
URL:            https://example.invalid/gic-ipsec-client
Requires: strongswan
Requires: python3
Requires: polkit
Requires: NetworkManager
Requires: systemd-resolved
Requires: iproute
Requires: bind-utils

%description
GIC IPsec Client is a small Linux desktop VPN client that uses the system
strongSwan swanctl/VICI backend and delegates privileged operations to a
pkexec helper.

%files
/opt/gic-ipsec-client/app
/opt/gic-ipsec-client/venv
/usr/bin/gic-ipsec-client
/usr/libexec/gic-ipsec-client/gic-ipsec-helper
/usr/share/applications/gic-ipsec-client.desktop
/usr/share/icons/hicolor/scalable/apps/gic-ipsec-client.svg
/usr/share/polkit-1/actions/com.gicipsec.client.policy
/etc/gic-ipsec-client/defaults.json

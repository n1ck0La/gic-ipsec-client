from __future__ import annotations

import os
from pathlib import Path

from gic_ipsec_client.backend.models import VpnProfile, fortigate_default_profile

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_sources_do_not_contain_site_specific_defaults() -> None:
    banned_literals = {
        "192.168.88.203",
        "see-radars.com",
        "seetech.local",
        "nextcloud.see-radars.com",
        "see-vpn.duckdns.org",
        "192.168.88.0/24",
        "ens18",
        "m.yaroshenko",
    }
    scanned_roots = [
        ROOT / "src",
        ROOT / "packaging",
        ROOT / "README.md",
        ROOT / "docs",
        ROOT / "pyproject.toml",
    ]
    findings: list[str] = []

    for root in scanned_roots:
        paths = [root] if root.is_file() else [path for path in root.rglob("*") if path.is_file()]
        for path in paths:
            if path.suffix in {".pyc", ".png"}:
                continue
            text = path.read_text(encoding="utf-8")
            for literal in banned_literals:
                if literal in text:
                    findings.append(f"{path.relative_to(ROOT)} contains {literal}")

    assert findings == []


def test_profile_serialization_uses_nested_schema_without_secrets() -> None:
    profile = VpnProfile(
        id="10000000-0000-4000-8000-000000000001",
        profile_name="Acme VPN",
        gateway_fqdn_or_ip="vpn.acme.example",
        username="alice",
        eap_identity="alice@acme.example",
        psk="do-not-store-psk",
        password="do-not-store-password",
        remote_routes=["10.44.0.0/16"],
        dns_servers=["10.44.0.53"],
        dns_search_domains=["corp.acme.example"],
        dns_test_names=["portal.corp.acme.example"],
    )

    payload = profile.to_dict()

    assert set(payload) >= {"gateway", "auth", "traffic", "dns", "crypto", "platform"}
    assert payload["gateway"]["host"] == "vpn.acme.example"
    assert payload["auth"]["secret_storage"] == "keyring"
    assert payload["dns"]["test_names"] == ["portal.corp.acme.example"]
    assert "psk" not in payload["auth"]
    assert "password" not in payload["auth"]

    restored = VpnProfile.from_dict(payload)

    assert restored.gateway_fqdn_or_ip == profile.gateway_fqdn_or_ip
    assert restored.remote_routes == ["10.44.0.0/16"]
    assert restored.psk == ""
    assert restored.password == ""


def test_fortigate_preset_is_site_neutral() -> None:
    profile = fortigate_default_profile()

    assert profile.gateway_fqdn_or_ip == "vpn.example.com"
    assert profile.gateway.remote_id_mode == "any"
    assert profile.remote_routes == []
    assert profile.dns_servers == []
    assert profile.dns_search_domains == []


def test_packaging_layout_targets_requested_paths() -> None:
    nfpm = (ROOT / "packaging" / "nfpm.yaml").read_text(encoding="utf-8")

    assert "name: see-ipsec-client" in nfpm
    assert "dst: /opt/see-ipsec-client/app" in nfpm
    assert "dst: /opt/see-ipsec-client/venv" in nfpm
    assert "dst: /usr/bin/see-ipsec-client" in nfpm
    assert "dst: /usr/libexec/see-ipsec-client/see-ipsec-helper" in nfpm
    assert "dst: /usr/share/icons/hicolor/scalable/apps/see-ipsec-client.svg" in nfpm
    assert "dst: /usr/share/polkit-1/actions/com.see.ipsecclient.policy" in nfpm
    assert "dst: /etc/see-ipsec-client/defaults.json" in nfpm
    assert "strongswan-swanctl" in nfpm
    assert "swanctl" in nfpm

    client_wrapper = ROOT / "packaging" / "bin" / "see-ipsec-client"
    helper_wrapper = ROOT / "packaging" / "libexec" / "see-ipsec-helper"
    policy = (ROOT / "packaging" / "polkit" / "com.see.ipsecclient.policy").read_text(
        encoding="utf-8"
    )

    assert os.access(client_wrapper, os.X_OK)
    assert os.access(helper_wrapper, os.X_OK)
    assert "/opt/see-ipsec-client/venv/bin/see-ipsec-client" in client_wrapper.read_text(
        encoding="utf-8"
    )
    assert "/opt/see-ipsec-client/venv/bin/see-ipsec-helper" in helper_wrapper.read_text(
        encoding="utf-8"
    )
    assert "/usr/libexec/see-ipsec-client/see-ipsec-helper" in policy

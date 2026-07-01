from __future__ import annotations

from gic_ipsec_client.backend.diagnostics import (
    DNS_QUERY_WRONG_LINK_HINT,
    DNS_SERVER_MISSING_HINT,
    DUMMY_DNS_IGNORED_HINT,
    PSK_IDENTITY_MISMATCH_HINT,
    SPLIT_TUNNEL_REMOTE_TS_MISMATCH_HINT,
    STRONGSWAN_DNS_HOOK_NONFATAL_HINT,
    diagnostic_hints,
    dns_query_used_unexpected_link,
    dummy_dns_link_ignored,
    internal_dns_test_names,
    redact_mapping,
    redact_text,
    route_only_domains_configured_on_lo,
)
from gic_ipsec_client.backend.models import VpnProfile


def test_diagnostics_redaction_catches_password_patterns() -> None:
    text = """
    psk = topsecret
    psksecret fortigate-secret
    password: "hunter2"
    secret = "ike-secret"
    eap password = eap-secret
    """

    redacted = redact_text(text)

    assert "topsecret" not in redacted
    assert "fortigate-secret" not in redacted
    assert "hunter2" not in redacted
    assert "ike-secret" not in redacted
    assert "eap-secret" not in redacted
    assert redacted.count("<redacted>") >= 5


def test_diagnostics_redaction_keeps_username_without_privacy_mode() -> None:
    text = "username = alice\npassword = secret"

    redacted = redact_text(text)

    assert "alice" in redacted
    assert "secret" not in redacted


def test_diagnostics_redaction_privacy_mode_hides_username() -> None:
    text = "username = alice\neap_identity = alice@example.com\npassword = secret"

    redacted = redact_text(text, privacy_mode=True)

    assert "alice" not in redacted
    assert "alice@example.com" not in redacted
    assert "secret" not in redacted


def test_redact_mapping_redacts_nested_secret_keys() -> None:
    payload = {
        "profile": {
            "username": "alice",
            "psk": "psk-value",
            "nested": {"password": "password-value"},
        }
    }

    redacted = redact_mapping(payload)

    assert redacted["profile"]["username"] == "alice"
    assert redacted["profile"]["psk"] == "<redacted>"
    assert redacted["profile"]["nested"]["password"] == "<redacted>"


def test_diagnostics_hint_for_shared_key_identity_mismatch() -> None:
    hints = diagnostic_hints(
        "IKE_AUTH request failed: no shared key found for '192.168.20.8' - '185.244.158.240'"
    )

    assert hints == [PSK_IDENTITY_MISMATCH_HINT]


def test_diagnostics_detects_split_full_tunnel_mismatch() -> None:
    profile = VpnProfile(
        id="00000000-0000-4000-8000-000000000001",
        profile_name="Split VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        username="alice",
        eap_identity="alice",
        psk="psk",
        password="password",
        remote_routes=["192.168.20.0/24"],
        dns_servers=["192.168.20.1"],
    )

    hints = diagnostic_hints(
        profile=profile,
        list_conns_output="remote: 0.0.0.0/0",
        resolved_status="Global\n",
    )

    assert SPLIT_TUNNEL_REMOTE_TS_MISMATCH_HINT in hints
    assert DNS_SERVER_MISSING_HINT in hints


def test_diagnostics_uses_internal_split_dns_hostnames() -> None:
    assert internal_dns_test_names(["see-radars.com", "seetech.local"]) == [
        "nextcloud.see-radars.com",
        "srv-dc-01.seetech.local",
    ]


def test_diagnostics_detects_route_only_domains_on_lo() -> None:
    status = """
    Link 1 (lo)
        DNS Servers: 192.168.88.203
        DNS Domain: ~see-radars.com ~seetech.local
    Link 2 (ens18)
        DNS Servers: 1.1.1.1
    """

    assert route_only_domains_configured_on_lo(
        status,
        ["see-radars.com", "seetech.local"],
    )


def test_diagnostics_warns_when_internal_query_uses_physical_link() -> None:
    query_output = """
    nextcloud.see-radars.com: 192.168.88.65
    -- Information acquired via protocol DNS in 3.1ms.
    -- Data is authenticated: no; Data was acquired via local or encrypted transport: no
    -- Data from: network
    Link 2 (ens18)
    """

    assert dns_query_used_unexpected_link(query_output)
    hints = diagnostic_hints(internal_query_output=query_output)

    assert DNS_QUERY_WRONG_LINK_HINT in hints


def test_diagnostics_warns_when_dummy_dns_is_ignored_by_resolved() -> None:
    profile = VpnProfile(
        id="00000000-0000-4000-8000-000000000001",
        profile_name="Split VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        username="alice",
        eap_identity="alice",
        psk="psk",
        password="password",
        remote_routes=["192.168.88.0/24"],
        dns_servers=["192.168.88.203"],
        dns_search_domains=["see-radars.com"],
    )
    dummy_status = """
    Link 99 (seeipsec0)
        DNS Servers: 192.168.88.203
        DNS Domain: ~see-radars.com
    """
    query_output = """
    nextcloud.see-radars.com: 185.70.111.155
    -- link: ens18
    """

    assert dummy_dns_link_ignored(dummy_status, query_output, profile.dns_servers)
    hints = diagnostic_hints(
        profile=profile,
        resolved_status="DNS Servers: 192.168.88.203",
        internal_query_output=query_output,
        dummy_resolved_status=dummy_status,
    )

    assert DUMMY_DNS_IGNORED_HINT in hints


def test_diagnostics_allows_physical_link_when_dns_apply_verified_it() -> None:
    query_output = """
    nextcloud.see-radars.com: 192.168.88.65
    -- link: ens18
    """

    hints = diagnostic_hints(
        internal_query_output=query_output,
        dns_apply_report={"success": True, "verified_interface": "ens18"},
    )

    assert DNS_QUERY_WRONG_LINK_HINT not in hints


def test_strongswan_dns_hook_failure_is_nonfatal_when_app_dns_succeeds() -> None:
    hints = diagnostic_hints(
        "handling INTERNAL_IP4_DNS attribute failed",
        dns_apply_report={"success": True},
    )

    assert STRONGSWAN_DNS_HOOK_NONFATAL_HINT in hints

from __future__ import annotations

from gic_ipsec_client.backend.diagnostics import (
    DNS_QUERY_WRONG_LINK_HINT,
    DNS_SERVER_MISSING_HINT,
    DUMMY_DNS_IGNORED_HINT,
    PSK_IDENTITY_MISMATCH_HINT,
    SPLIT_TUNNEL_REMOTE_TS_MISMATCH_HINT,
    STRONGSWAN_DNS_HOOK_NONFATAL_HINT,
    VPN_DNS_ROLLBACK_FAILED_HINT,
    diagnostic_hints,
    dns_query_used_unexpected_link,
    dummy_dns_link_ignored,
    install_hint,
    internal_dns_test_names,
    profile_dns_test_names,
    redact_mapping,
    redact_text,
    route_only_domains_configured_on_lo,
    vpn_dns_rollback_failed,
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


def test_diagnostics_dns_test_names_are_profile_driven() -> None:
    profile = VpnProfile(
        id="00000000-0000-4000-8000-000000000001",
        profile_name="Split VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        username="alice",
        eap_identity="alice",
        psk="psk",
        password="password",
        remote_routes=["10.88.0.0/24"],
        dns_search_domains=["corp.example", "corp.local"],
        dns_test_names=["portal.corp.example", "dc.corp.local"],
    )

    assert profile_dns_test_names(profile) == [
        "portal.corp.example",
        "dc.corp.local",
        "corp.example",
        "corp.local",
    ]
    assert internal_dns_test_names(["corp.example", "corp.local"]) == [
        "corp.example",
        "corp.local",
    ]


def test_diagnostics_detects_route_only_domains_on_lo() -> None:
    status = """
    Link 1 (lo)
        DNS Servers: 10.88.0.53
        DNS Domain: ~corp.example ~corp.local
    Link 2 (wan0)
        DNS Servers: 1.1.1.1
    """

    assert route_only_domains_configured_on_lo(
        status,
        ["corp.example", "corp.local"],
    )


def test_diagnostics_warns_when_internal_query_uses_physical_link() -> None:
    query_output = """
    portal.corp.example: 10.88.0.65
    -- Information acquired via protocol DNS in 3.1ms.
    -- Data is authenticated: no; Data was acquired via local or encrypted transport: no
    -- Data from: network
    Link 2 (wan0)
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
        remote_routes=["10.88.0.0/24"],
        dns_servers=["10.88.0.53"],
        dns_search_domains=["corp.example"],
    )
    dummy_status = """
    Link 99 (gicipsec0)
        DNS Servers: 10.88.0.53
        DNS Domain: ~corp.example
    """
    query_output = """
    portal.corp.example: 203.0.113.155
    -- link: wan0
    """

    assert dummy_dns_link_ignored(dummy_status, query_output, profile.dns_servers)
    hints = diagnostic_hints(
        profile=profile,
        resolved_status="DNS Servers: 10.88.0.53",
        internal_query_output=query_output,
        dummy_resolved_status=dummy_status,
    )

    assert DUMMY_DNS_IGNORED_HINT in hints


def test_diagnostics_allows_physical_link_when_dns_apply_verified_it() -> None:
    query_output = """
    portal.corp.example: 10.88.0.65
    -- link: wan0
    """

    hints = diagnostic_hints(
        internal_query_output=query_output,
        dns_apply_report={"success": True, "verified_interface": "wan0"},
    )

    assert DNS_QUERY_WRONG_LINK_HINT not in hints


def test_diagnostics_warns_when_disconnected_vpn_dns_remains() -> None:
    profile = VpnProfile(
        id="00000000-0000-4000-8000-000000000001",
        profile_name="Split VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        username="alice",
        eap_identity="alice",
        psk="psk",
        password="password",
        remote_routes=["10.88.0.0/24"],
        dns_servers=["10.88.0.53"],
        dns_search_domains=["corp.example"],
    )
    status = "Link 2 (wan0)\nDNS Servers: 10.88.0.53\n"

    assert vpn_dns_rollback_failed(
        profile=profile,
        list_sas_output="",
        resolved_status=status,
    )
    hints = diagnostic_hints(
        profile=profile,
        dns_apply_report={"dns_apply_ran": True},
        default_interface_status=status,
    )

    assert VPN_DNS_ROLLBACK_FAILED_HINT in hints


def test_strongswan_dns_hook_failure_is_nonfatal_when_app_dns_succeeds() -> None:
    hints = diagnostic_hints(
        "handling INTERNAL_IP4_DNS attribute failed",
        dns_apply_report={"success": True},
    )

    assert STRONGSWAN_DNS_HOOK_NONFATAL_HINT in hints


def test_fedora_install_hint_does_not_use_debian_swanctl_package_name() -> None:
    hint = install_hint({"ID": "fedora"})

    assert "strongswan-swanctl" not in hint
    assert "strongswan" in hint
    assert "bind-utils" in hint


def test_diagnostics_install_hints_keep_fedora_and_ubuntu_packages_separate() -> None:
    ubuntu_hint = install_hint({"ID": "ubuntu"})

    assert "strongswan-swanctl" not in install_hint({"ID": "fedora"})
    assert "strongswan-swanctl" in ubuntu_hint
    assert "libcharon-extra-plugins" in ubuntu_hint
    assert " swanctl," not in ubuntu_hint

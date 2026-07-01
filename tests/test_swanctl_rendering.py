from __future__ import annotations

import pytest

from gic_ipsec_client.backend.models import VpnProfile, fortigate_default_profile
from gic_ipsec_client.backend.renderer import (
    render_profile_config,
    render_profile_files,
    render_sanitized_bundle_config,
    render_secret_config,
)
from gic_ipsec_client.backend.swanctl_paths import (
    FEDORA_SWANCTL_ROOT,
    SwanctlLayout,
    detect_swanctl_config_root,
)
from gic_ipsec_client.backend.validators import ProfileValidationError, validate_profile


def valid_profile() -> VpnProfile:
    return VpnProfile(
        id="00000000-0000-4000-8000-000000000001",
        profile_name="Render VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        remote_id="vpn.example.com",
        local_id="alice@example.com",
        username="alice",
        eap_identity="alice@example.com",
        psk="do-not-leak-psk",
        password="do-not-leak-password",
        remote_routes=["10.20.0.0/16", "10.30.0.0/16"],
    )


def test_swanctl_renderer_creates_expected_sections() -> None:
    profile = valid_profile()
    rendered = render_profile_config(profile)

    assert "connections {" in rendered
    assert f"{profile.connection_name} {{" in rendered
    assert "auth = eap-mschapv2" in rendered
    assert 'remote_addrs = "vpn.example.com"' in rendered
    assert "remote_ts = 10.20.0.0/16, 10.30.0.0/16" in rendered
    assert f"{profile.child_name} {{" in rendered


def test_split_tunnel_renders_configured_remote_routes() -> None:
    profile = valid_profile()
    rendered = render_profile_config(profile)

    assert "remote_ts = 10.20.0.0/16, 10.30.0.0/16" in rendered
    assert "remote_ts = 0.0.0.0/0" not in rendered


def test_full_tunnel_renders_default_route_remote_ts() -> None:
    profile = valid_profile()
    profile.split_tunnel_enabled = False
    profile.remote_routes = []
    rendered = render_profile_config(profile)

    assert "remote_ts = 0.0.0.0/0" in rendered


def test_split_tunnel_without_routes_is_rejected() -> None:
    profile = valid_profile()
    profile.remote_routes = []

    with pytest.raises(ProfileValidationError) as exc:
        validate_profile(profile)

    assert "Split tunnel is enabled but no remote routes are configured." in str(exc.value)


def test_swanctl_secret_renderer_creates_psk_and_eap_sections() -> None:
    rendered = render_secret_config(valid_profile())

    assert "secrets {" in rendered
    assert "ike-gic-00000000-0000-4000-8000-000000000001" in rendered
    assert "eap-gic-00000000-0000-4000-8000-000000000001" in rendered
    assert "id-2 = vpn.example.com" in rendered
    assert 'secret = "do-not-leak-psk"' in rendered
    assert 'secret = "do-not-leak-password"' in rendered


def test_renderer_redacts_secrets_in_debug_mode() -> None:
    profile = valid_profile()
    rendered = render_sanitized_bundle_config(profile)

    assert "do-not-leak-psk" not in rendered
    assert "do-not-leak-password" not in rendered
    assert "<redacted>" in rendered


def test_render_profile_files_uses_uuid_paths() -> None:
    profile = valid_profile()
    layout = SwanctlLayout(root=FEDORA_SWANCTL_ROOT, source="test")
    rendered = render_profile_files(profile, layout=layout)

    assert rendered.config_path.name == f"gic-{profile.id}.conf"
    assert rendered.secrets_path is None


def test_fedora_root_detection_prefers_strongswan_swanctl() -> None:
    root, source = detect_swanctl_config_root(
        os_release={"ID": "fedora"},
        command_runner=lambda _args, _timeout: "",
    )

    assert root == FEDORA_SWANCTL_ROOT
    assert source == "Fedora distro default"


def test_fedora_renderer_creates_one_flat_config_with_secrets() -> None:
    profile = valid_profile()
    layout = SwanctlLayout(root=FEDORA_SWANCTL_ROOT, source="test", use_secrets_dir=False)
    rendered = render_profile_files(profile, layout=layout)

    assert rendered.config_path == FEDORA_SWANCTL_ROOT / "conf.d" / f"gic-{profile.id}.conf"
    assert rendered.secrets_path is None
    assert "connections {" in rendered.config_text
    assert "secrets {" in rendered.config_text
    assert rendered.secrets_text == ""
    assert rendered.config_mode == 0o600


def test_fedora_renderer_does_not_use_nested_gic_ipsec_path() -> None:
    profile = valid_profile()
    layout = SwanctlLayout(root=FEDORA_SWANCTL_ROOT, source="test")
    rendered = render_profile_files(profile, layout=layout)

    assert "conf.d/gic-ipsec" not in rendered.config_path.as_posix()


def test_fortigate_preset_uses_eap_identity_and_any_psk_ids() -> None:
    profile = fortigate_default_profile()
    profile.id = "00000000-0000-4000-8000-000000000002"
    profile.gateway_fqdn_or_ip = "see-vpn.duckdns.org"
    profile.username = "m.yaroshenko"
    profile.eap_identity = ""
    profile.psk = "do-not-leak-psk"
    profile.password = "do-not-leak-password"
    profile.remote_routes = ["192.168.20.0/24"]

    rendered = render_profile_config(profile) + "\n" + render_secret_config(profile)

    assert "remote_addrs = \"see-vpn.duckdns.org\"" in rendered
    assert "id = m.yaroshenko" in rendered
    assert "eap_id = m.yaroshenko" in rendered
    assert "id = %any" in rendered
    assert "id-1 = %any" in rendered
    assert "id-2 = %any" in rendered

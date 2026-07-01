from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gic_ipsec_client.backend.diagnostics import redact_text
from gic_ipsec_client.backend.models import VpnProfile
from gic_ipsec_client.backend.validators import validate_profile

CONF_ROOT = Path("/etc/swanctl/conf.d/gic-ipsec")
SECRETS_ROOT = Path("/etc/swanctl/secrets.d/gic-ipsec")


@dataclass(frozen=True, slots=True)
class RenderedProfile:
    profile_id: str
    config_path: Path
    secrets_path: Path
    config_text: str
    secrets_text: str


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _list_value(values: list[str]) -> str:
    return ", ".join(values)


def _remote_ts(profile: VpnProfile) -> str:
    if profile.split_tunnel_enabled and profile.remote_routes:
        return _list_value(profile.remote_routes)
    return "0.0.0.0/0"


def render_profile_config(profile: VpnProfile, *, debug: bool = False) -> str:
    """Render the non-secret `swanctl.conf` connection section."""

    validate_profile(profile, require_secrets=not debug)
    conn = profile.connection_name
    child = profile.child_name
    eap_identity = profile.eap_identity or profile.username

    lines = [
        "connections {",
        f"    {conn} {{",
        "        version = 2",
        f"        remote_addrs = {_quote(profile.gateway_fqdn_or_ip)}",
        f"        proposals = {_list_value(profile.ike_proposals)}",
        "        mobike = yes",
        "        encap = yes",
    ]
    if profile.ike_port != 500:
        lines.append(f"        remote_port = {profile.ike_port}")
    if profile.request_virtual_ip:
        lines.append("        vips = 0.0.0.0")
    if profile.dpd_enabled:
        lines.extend(["        dpd_delay = 30s", "        dpd_timeout = 120s"])

    lines.extend(
        [
            "        local {",
            "            auth = eap-mschapv2",
            f"            eap_id = {_quote(eap_identity)}",
        ]
    )
    if profile.local_id:
        lines.append(f"            id = {_quote(profile.local_id)}")
    lines.extend(["        }", "        remote {", "            auth = psk"])
    if profile.remote_id:
        lines.append(f"            id = {_quote(profile.remote_id)}")
    lines.extend(
        [
            "        }",
            "        children {",
            f"            {child} {{",
            "                local_ts = dynamic",
            f"                remote_ts = {_remote_ts(profile)}",
            f"                esp_proposals = {_list_value(profile.esp_proposals)}",
            "                start_action = none",
            "                close_action = none",
        ]
    )
    if profile.dpd_enabled:
        lines.append("                dpd_action = clear")
    lines.extend(["            }", "        }", "    }", "}"])
    return "\n".join(lines) + "\n"


def render_secret_config(profile: VpnProfile, *, debug: bool = False) -> str:
    """Render strongSwan secrets for PSK gateway auth and EAP-MSCHAPv2 user auth."""

    validate_profile(profile, require_secrets=not debug)
    conn = profile.connection_name
    psk = "<redacted>" if debug else profile.psk
    password = "<redacted>" if debug else profile.password
    remote_id = profile.remote_id or profile.gateway_fqdn_or_ip
    eap_identity = profile.eap_identity or profile.username

    lines = [
        "secrets {",
        f"    ike-{conn} {{",
    ]
    if profile.local_id:
        lines.append(f"        id-1 = {_quote(profile.local_id)}")
    lines.extend(
        [
            f"        id-2 = {_quote(remote_id)}",
            f"        secret = {_quote(psk)}",
            "    }",
            f"    eap-{conn} {{",
            f"        id = {_quote(eap_identity)}",
            f"        secret = {_quote(password)}",
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def render_profile_files(
    profile: VpnProfile,
    *,
    conf_root: Path = CONF_ROOT,
    secrets_root: Path = SECRETS_ROOT,
) -> RenderedProfile:
    validate_profile(profile)
    return RenderedProfile(
        profile_id=profile.id,
        config_path=conf_root / f"{profile.id}.conf",
        secrets_path=secrets_root / f"{profile.id}.secrets",
        config_text=render_profile_config(profile),
        secrets_text=render_secret_config(profile),
    )


def render_sanitized_bundle_config(profile: VpnProfile, *, privacy_mode: bool = False) -> str:
    rendered = render_profile_config(profile, debug=True) + "\n" + render_secret_config(
        profile, debug=True
    )
    return redact_text(rendered, privacy_mode=privacy_mode)

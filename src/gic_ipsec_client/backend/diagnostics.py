from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gic_ipsec_client import __version__
from gic_ipsec_client.backend.models import VpnProfile

SECRET_KEYS = {"psk", "psksecret", "password", "secret", "eap_password", "eap password"}
PRIVACY_KEYS = {"username", "eap_identity"}

QUOTED_SECRET_RE = re.compile(
    r"(?i)((?:\"?(?:psksecret|psk|password|secret|eap[-_\s]?password)\"?)\s*[:=]\s*\")"
    r"(.*?)(\")"
)
BARE_SECRET_RE = re.compile(
    r"(?i)(\b(?:psksecret|psk|password|secret|eap[-_\s]?password)\b\s*[:=]\s*)([^\s,}]+)"
)
FORTIGATE_SECRET_RE = re.compile(r"(?i)(\bpsksecret\s+)(\S+)")
USERNAME_RE = re.compile(r"(?i)(\b(?:username|eap_identity)\b\s*[:=]\s*)([^\s,}]+)")
NO_SHARED_KEY_RE = re.compile(r"no shared key found for", re.IGNORECASE)
PSK_IDENTITY_MISMATCH_HINT = (
    "IKE PSK identity mismatch. Try FortiGate preset with remote.id=%any and "
    "IKE secret id-1/id-2=%any."
)


@dataclass(slots=True)
class DiagnosticReport:
    summary: dict[str, Any]
    sections: dict[str, str] = field(default_factory=dict)

    def as_text(self) -> str:
        parts = ["GIC diagnostics", json.dumps(self.summary, indent=2, sort_keys=True)]
        for name, content in self.sections.items():
            parts.extend([f"\n## {name}", content.strip()])
        return "\n".join(parts).strip() + "\n"


def redact_text(text: str, *, privacy_mode: bool = False) -> str:
    redacted = QUOTED_SECRET_RE.sub(r"\1<redacted>\3", text)
    redacted = BARE_SECRET_RE.sub(r"\1<redacted>", redacted)
    redacted = FORTIGATE_SECRET_RE.sub(r"\1<redacted>", redacted)
    if privacy_mode:
        redacted = USERNAME_RE.sub(r"\1<redacted>", redacted)
    return redacted


def redact_mapping(value: Any, *, privacy_mode: bool = False) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in SECRET_KEYS:
                result[key] = "<redacted>"
            elif privacy_mode and normalized in PRIVACY_KEYS:
                result[key] = "<redacted>"
            else:
                result[key] = redact_mapping(item, privacy_mode=privacy_mode)
        return result
    if isinstance(value, list):
        return [redact_mapping(item, privacy_mode=privacy_mode) for item in value]
    if isinstance(value, str):
        return redact_text(value, privacy_mode=privacy_mode)
    return value


def diagnostic_hints(*texts: str) -> list[str]:
    combined = "\n".join(texts)
    hints: list[str] = []
    if NO_SHARED_KEY_RE.search(combined):
        hints.append(PSK_IDENTITY_MISMATCH_HINT)
    return hints


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        values[key] = raw_value.strip().strip('"')
    return values


def distro_family(os_release: dict[str, str] | None = None) -> str:
    release = os_release or read_os_release()
    distro_id = release.get("ID", "").lower()
    id_like = release.get("ID_LIKE", "").lower()
    values = {distro_id, *id_like.split()}
    if values & {"debian", "ubuntu"}:
        return "debian"
    if values & {"fedora", "rhel", "centos"}:
        return "fedora"
    return "unknown"


def install_hint(os_release: dict[str, str] | None = None) -> str:
    family = distro_family(os_release)
    if family == "debian":
        return (
            "Use packaging/ubuntu/install-deps.sh, or install python3, python3-pip, "
            "python3-venv, strongswan-swanctl, charon-systemd/strongswan, polkit, "
            "and libsecret packages."
        )
    if family == "fedora":
        return (
            "Use packaging/fedora/install-deps.sh, or install python3, python3-pip, "
            "strongswan, strongswan-swanctl if packaged separately, polkit, and libsecret."
        )
    return "Install Python 3.11+, strongSwan swanctl/VICI, polkit, and libsecret for your distro."


def _run_optional(args: tuple[str, ...], *, timeout_seconds: int = 15) -> str:
    from gic_ipsec_client.backend.commands import CommandSpec, run_command

    if not shutil.which(args[0]):
        return f"{args[0]} not found"
    try:
        completed = run_command(CommandSpec(args, timeout_seconds=timeout_seconds))
    except (OSError, TimeoutError) as exc:
        return f"{args[0]} failed: {exc}"
    output = (completed.stdout or "") + (completed.stderr or "")
    return output.strip() or f"{args[0]} exited with {completed.returncode}"


def _run_helper_diagnostics(
    *,
    profile: VpnProfile | None,
    config_root_override: str,
) -> dict[str, Any]:
    from gic_ipsec_client.backend.commands import build_pkexec_helper_command, run_command

    args: list[str] = []
    if profile is not None:
        args.extend(["--profile-uuid", profile.id])
    if config_root_override:
        args.extend(["--config-root", config_root_override])
    try:
        completed = run_command(build_pkexec_helper_command("diagnostics", *args))
    except (OSError, TimeoutError) as exc:
        return {"error": f"helper diagnostics failed: {exc}"}
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0:
        return {"error": output.strip() or f"helper diagnostics exited with {completed.returncode}"}
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        return {"error": f"helper diagnostics returned invalid JSON: {exc}", "raw": output}
    if not isinstance(payload, dict):
        return {"error": "helper diagnostics returned a non-object JSON payload"}
    return payload


def _format_swanctl_diagnostics(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _service_summary() -> dict[str, str]:
    services = ("charon-systemd", "strongswan", "strongswan-starter")
    return {
        service: _run_optional(("systemctl", "is-active", service), timeout_seconds=5)
        for service in services
    }


def check_dependencies() -> dict[str, Any]:
    return {
        "strongSwan installed": bool(shutil.which("swanctl") or shutil.which("strongswan")),
        "swanctl available": bool(shutil.which("swanctl")),
        "pkexec available": bool(shutil.which("pkexec")),
        "services": _service_summary() if shutil.which("systemctl") else {"systemctl": "not found"},
        "required plugins likely needed": [
            "vici",
            "eap-identity",
            "eap-mschapv2",
            "kernel-netlink",
            "resolve or systemd-resolved integration",
        ],
        "install_hint": install_hint(),
    }


def collect_diagnostics(
    *,
    profile: VpnProfile | None = None,
    privacy_mode: bool = False,
    config_root_override: str = "",
) -> DiagnosticReport:
    swanctl_diagnostics = _run_helper_diagnostics(
        profile=profile,
        config_root_override=config_root_override,
    )
    strongswan_logs = _run_optional(
        (
            "journalctl",
            "-u",
            "strongswan*",
            "-u",
            "charon-systemd",
            "--since",
            "10 minutes ago",
            "-n",
            "100",
            "--no-pager",
        ),
        timeout_seconds=20,
    )
    hints = diagnostic_hints(
        str(swanctl_diagnostics.get("list_sas_output", "")),
        str(swanctl_diagnostics.get("list_conns_output", "")),
        strongswan_logs,
    )
    sections = {
        "swanctl_config_and_vici": _format_swanctl_diagnostics(swanctl_diagnostics),
        "current_sas": str(swanctl_diagnostics.get("list_sas_output", "")),
        "loaded_conns": str(swanctl_diagnostics.get("list_conns_output", "")),
        "diagnostic_hints": "\n".join(hints),
        "route_table": _run_optional(("ip", "route"), timeout_seconds=10),
        "dns": _run_optional(("resolvectl", "status"), timeout_seconds=10)
        if shutil.which("resolvectl")
        else _run_optional(("nmcli", "device", "show"), timeout_seconds=10),
        "strongswan_logs": strongswan_logs,
    }
    redacted_sections = {
        name: redact_text(content, privacy_mode=privacy_mode) for name, content in sections.items()
    }
    summary = check_dependencies()
    summary["diagnostic_hints"] = hints
    summary["swanctl"] = {
        "selected_config_root": swanctl_diagnostics.get("selected_swanctl_config_root", ""),
        "selection_source": swanctl_diagnostics.get("selection_source", ""),
        "/etc/swanctl exists": swanctl_diagnostics.get("root_exists", {}).get(
            "/etc/swanctl",
            False,
        )
        if isinstance(swanctl_diagnostics.get("root_exists", {}), dict)
        else False,
        "/etc/strongswan/swanctl exists": swanctl_diagnostics.get("root_exists", {}).get(
            "/etc/strongswan/swanctl",
            False,
        )
        if isinstance(swanctl_diagnostics.get("root_exists", {}), dict)
        else False,
        "generated_profile_file": swanctl_diagnostics.get("generated_profile_file", ""),
        "generated_profile_file_exists": swanctl_diagnostics.get(
            "generated_profile_file_exists",
            False,
        ),
        "generated_connection_loaded": swanctl_diagnostics.get("generated_connection_loaded"),
        "helper_error": swanctl_diagnostics.get("error", ""),
    }
    if profile is not None:
        summary["profile"] = profile.sanitized_dict(privacy_mode=privacy_mode)
    return DiagnosticReport(
        summary=redact_mapping(summary, privacy_mode=privacy_mode),
        sections=redacted_sections,
    )


def export_debug_bundle(
    output_dir: Path,
    *,
    profile: VpnProfile | None = None,
    privacy_mode: bool = False,
    config_root_override: str = "",
) -> Path:
    from gic_ipsec_client.backend.renderer import render_sanitized_bundle_config

    output_dir.mkdir(parents=True, exist_ok=True)
    fd, archive_name = tempfile.mkstemp(
        prefix="gic-debug-",
        suffix=".tar.gz",
        dir=output_dir,
    )
    os.close(fd)
    archive_path = Path(archive_name)

    report = collect_diagnostics(
        profile=profile,
        privacy_mode=privacy_mode,
        config_root_override=config_root_override,
    )
    os_release = read_os_release()
    profile_json = (
        json.dumps(profile.sanitized_dict(privacy_mode=privacy_mode), indent=2, sort_keys=True)
        if profile
        else "{}"
    )
    rendered = render_sanitized_bundle_config(profile, privacy_mode=privacy_mode) if profile else ""

    with tempfile.TemporaryDirectory(prefix="gic-debug-src-") as tmp_name:
        tmp = Path(tmp_name)
        files = {
            "app-version.txt": f"{__version__}\n",
            "os-release.json": json.dumps(os_release, indent=2, sort_keys=True) + "\n",
            "profile.sanitized.json": profile_json + "\n",
            "swanctl.sanitized.conf": rendered,
            "diagnostics.txt": report.as_text(),
            "swanctl-list-sas.txt": report.sections.get("current_sas", "") + "\n",
            "swanctl-list-conns.txt": report.sections.get("loaded_conns", "") + "\n",
            "swanctl-config-diagnostics.txt": report.sections.get(
                "swanctl_config_and_vici",
                "",
            )
            + "\n",
            "ip-route.txt": report.sections.get("route_table", "") + "\n",
            "dns.txt": report.sections.get("dns", "") + "\n",
            "strongswan-logs.txt": report.sections.get("strongswan_logs", "") + "\n",
        }
        for name, content in files.items():
            sanitized = redact_text(content, privacy_mode=privacy_mode)
            (tmp / name).write_text(sanitized, encoding="utf-8")
        with tarfile.open(archive_path, "w:gz") as tar:
            for file_path in sorted(tmp.iterdir()):
                tar.add(file_path, arcname=file_path.name)
    return archive_path

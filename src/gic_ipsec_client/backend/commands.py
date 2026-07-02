from __future__ import annotations

import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from gic_ipsec_client.backend.swanctl_paths import (
    KNOWN_SWANCTL_ROOTS,
    LEGACY_PROFILE_FILE_PREFIX,
    PROFILE_FILE_PREFIX,
    SwanctlLayout,
    detect_swanctl_layout,
)
from gic_ipsec_client.backend.validators import ProfileValidationError, validate_uuid

SWANCTL_FALLBACK_PATHS = (Path("/usr/bin/swanctl"), Path("/usr/sbin/swanctl"))
HELPER_NOT_FOUND_MESSAGE = (
    "Privileged helper was not found. The package installation is incomplete."
)
HELPER_ENV_VAR = "GIC_IPSEC_HELPER"
HELPER_FALLBACK_PATHS = (
    Path("/usr/libexec/gic-ipsec-client/gic-ipsec-helper"),
    Path("/usr/lib/gic-ipsec-client/gic-ipsec-helper"),
    Path("/opt/gic-ipsec-client/venv/bin/gic-ipsec-helper"),
)
POLKIT_POLICY_PATH = Path("/usr/share/polkit-1/actions/com.gicipsec.client.policy")
POLKIT_EXEC_PATH_KEY = "org.freedesktop.policykit.exec.path"
STRONGSWAN_SERVICE_CANDIDATES = (
    "strongswan-starter.service",
    "strongswan.service",
    "charon-systemd.service",
)
VICI_SOCKET_PATHS = (Path("/run/charon.vici"), Path("/var/run/charon.vici"))
VICI_UNAVAILABLE_MESSAGE = (
    "strongSwan is installed but the VICI control socket is not available. "
    "Start the strongSwan service or install the swanctl/VICI packages."
)


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """A subprocess command represented as an argument array."""

    args: tuple[str, ...]
    timeout_seconds: int = 30
    env: Mapping[str, str] | None = None

    def as_subprocess_kwargs(self) -> dict[str, object]:
        return {
            "args": list(self.args),
            "capture_output": True,
            "check": False,
            "env": self.env,
            "shell": False,
            "text": True,
            "timeout": self.timeout_seconds,
        }


def run_command(spec: CommandSpec) -> subprocess.CompletedProcess[str]:
    return subprocess.run(**spec.as_subprocess_kwargs())  # noqa: S603


def require_executable(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"Required executable not found: {name}")
    return path


def command_v(name: str) -> str:
    return shutil.which(name) or ""


def _absolute_executable_path(path: str | Path) -> str | None:
    candidate = Path(path).expanduser()
    if _is_executable_file(candidate):
        return str(candidate.resolve(strict=False))
    return None


def _is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def resolve_swanctl_path() -> str | None:
    path = command_v("swanctl")
    if path:
        return path
    for candidate in SWANCTL_FALLBACK_PATHS:
        if _is_executable_file(candidate):
            return str(candidate)
    return None


def swanctl_executable() -> str:
    return resolve_swanctl_path() or "swanctl"


def swanctl_load_all() -> CommandSpec:
    return CommandSpec((swanctl_executable(), "--load-all"), timeout_seconds=20)


def swanctl_initiate(child_name: str) -> CommandSpec:
    return CommandSpec(
        (swanctl_executable(), "--initiate", "--child", child_name),
        timeout_seconds=60,
    )


def swanctl_terminate(connection_name: str) -> CommandSpec:
    return CommandSpec(
        (swanctl_executable(), "--terminate", "--ike", connection_name),
        timeout_seconds=20,
    )


def swanctl_list_sas() -> CommandSpec:
    return CommandSpec((swanctl_executable(), "--list-sas"), timeout_seconds=15)


def swanctl_list_conns() -> CommandSpec:
    return CommandSpec((swanctl_executable(), "--list-conns"), timeout_seconds=15)


def rpm_query_file_owner(path: str | Path) -> CommandSpec:
    return CommandSpec(("rpm", "-qf", str(path)), timeout_seconds=10)


def development_helper_path_allowed() -> bool:
    if sys.prefix == sys.base_prefix:
        return False
    return Path(sys.prefix).resolve(strict=False) != Path(
        "/opt/gic-ipsec-client/venv"
    ).resolve(strict=False)


def resolve_helper_path() -> str | None:
    env_path = os.environ.get(HELPER_ENV_VAR, "")
    if env_path:
        resolved = _absolute_executable_path(env_path)
        if resolved:
            return resolved
    for candidate in HELPER_FALLBACK_PATHS:
        resolved = _absolute_executable_path(candidate)
        if resolved:
            return resolved
    if development_helper_path_allowed():
        path = command_v("gic-ipsec-helper")
        if path:
            return _absolute_executable_path(path)
    return None


def polkit_exec_path(policy_path: Path = POLKIT_POLICY_PATH) -> str:
    try:
        root = ET.parse(policy_path).getroot()
    except (OSError, ET.ParseError):
        return ""
    for element in root.iter("annotate"):
        if element.attrib.get("key") == POLKIT_EXEC_PATH_KEY:
            return (element.text or "").strip()
    return ""


def helper_installation_diagnostics(
    *,
    helper_path: str | None = None,
    policy_path: Path = POLKIT_POLICY_PATH,
) -> dict[str, object]:
    resolved_helper_path = helper_path or resolve_helper_path() or ""
    resolved_path = Path(resolved_helper_path) if resolved_helper_path else None
    policy_exec_path = polkit_exec_path(policy_path)
    return {
        "resolved_helper_path": resolved_helper_path,
        "helper_exists": bool(resolved_path and resolved_path.exists()),
        "helper_executable": bool(resolved_path and os.access(resolved_path, os.X_OK)),
        "polkit_policy_file_path": str(policy_path),
        "polkit_exec_path": policy_exec_path,
        "helper_matches_polkit_exec_path": bool(
            resolved_helper_path and policy_exec_path and resolved_helper_path == policy_exec_path
        ),
    }


def systemctl_is_active(service_name: str) -> CommandSpec:
    return CommandSpec(("systemctl", "is-active", service_name), timeout_seconds=15)


def systemctl_list_unit_file(service_name: str) -> CommandSpec:
    return CommandSpec(
        ("systemctl", "list-unit-files", service_name, "--no-legend"),
        timeout_seconds=15,
    )


def systemctl_start(service_name: str) -> CommandSpec:
    service = service_name.removesuffix(".service")
    return CommandSpec(("systemctl", "start", service), timeout_seconds=15)


def journalctl_logs(
    *,
    units: Sequence[str] = ("strongswan*", "charon-systemd"),
    since: str = "10 minutes ago",
    lines: int = 100,
) -> CommandSpec:
    args = ["journalctl"]
    for unit in units:
        args.extend(["-u", unit])
    args.extend(["--since", since, "-n", str(lines), "--no-pager"])
    return CommandSpec(tuple(args), timeout_seconds=10)


def ip_route() -> CommandSpec:
    return CommandSpec(("ip", "route"), timeout_seconds=10)


def resolvectl_status() -> CommandSpec:
    return CommandSpec(("resolvectl", "status"), timeout_seconds=10)


def nmcli_device_show() -> CommandSpec:
    return CommandSpec(("nmcli", "device", "show"), timeout_seconds=10)


def build_pkexec_helper_command(subcommand: str, *args: str) -> CommandSpec:
    helper_path = resolve_helper_path()
    if not helper_path:
        raise FileNotFoundError(HELPER_NOT_FOUND_MESSAGE)
    return CommandSpec(("pkexec", helper_path, subcommand, *args), timeout_seconds=120)


def profile_paths(
    profile_id: str,
    *,
    layout: SwanctlLayout | None = None,
    config_root_override: str | Path | None = None,
) -> tuple[Path, Path | None]:
    validate_uuid(profile_id)
    selected_layout = layout or detect_swanctl_layout(override=config_root_override)
    return (
        selected_layout.profile_config_path(profile_id),
        selected_layout.profile_secrets_path(profile_id)
        if selected_layout.use_secrets_dir
        else None,
    )


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def delete_profile_files(
    profile_id: str,
    *,
    layout: SwanctlLayout | None = None,
    config_root_override: str | Path | None = None,
    all_known_roots: bool = False,
) -> list[Path]:
    """Delete only the UUID-named files GIC IPsec owns below configured swanctl roots."""

    validate_uuid(profile_id)
    layouts = (
        [SwanctlLayout(root=root, source="known root cleanup") for root in KNOWN_SWANCTL_ROOTS]
        if all_known_roots
        else [layout or detect_swanctl_layout(override=config_root_override)]
    )
    deleted: list[Path] = []
    expected_names = {
        f"{PROFILE_FILE_PREFIX}{profile_id}.conf",
        f"{PROFILE_FILE_PREFIX}{profile_id}.secrets",
        f"{LEGACY_PROFILE_FILE_PREFIX}{profile_id}.conf",
        f"{LEGACY_PROFILE_FILE_PREFIX}{profile_id}.secrets",
    }
    for selected_layout in layouts:
        targets = (
            selected_layout.profile_config_path(profile_id),
            selected_layout.profile_secrets_path(profile_id),
            selected_layout.conf_dir / f"{LEGACY_PROFILE_FILE_PREFIX}{profile_id}.conf",
            selected_layout.secrets_dir / f"{LEGACY_PROFILE_FILE_PREFIX}{profile_id}.secrets",
        )
        for path in targets:
            if not _is_under(path, selected_layout.root):
                raise ProfileValidationError(
                    f"Refusing to delete path outside {selected_layout.root}: {path}"
                )
            if path.name not in expected_names:
                raise ProfileValidationError(f"Refusing to delete unexpected filename: {path.name}")
            if path.exists():
                path.unlink()
                deleted.append(path)
    return deleted


def chmod_secret_file(path: Path) -> None:
    os.chmod(path, 0o600)

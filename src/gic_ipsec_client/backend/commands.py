from __future__ import annotations

import os
import shutil
import subprocess
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


def resolve_swanctl_path() -> str | None:
    path = command_v("swanctl")
    if path:
        return path
    for candidate in SWANCTL_FALLBACK_PATHS:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def swanctl_executable() -> str:
    return resolve_swanctl_path() or "swanctl"


def swanctl_load_all() -> CommandSpec:
    return CommandSpec((swanctl_executable(), "--load-all"), timeout_seconds=30)


def swanctl_initiate(child_name: str) -> CommandSpec:
    return CommandSpec(
        (swanctl_executable(), "--initiate", "--child", child_name),
        timeout_seconds=60,
    )


def swanctl_terminate(connection_name: str) -> CommandSpec:
    return CommandSpec(
        (swanctl_executable(), "--terminate", "--ike", connection_name),
        timeout_seconds=30,
    )


def swanctl_list_sas() -> CommandSpec:
    return CommandSpec((swanctl_executable(), "--list-sas"), timeout_seconds=20)


def swanctl_list_conns() -> CommandSpec:
    return CommandSpec((swanctl_executable(), "--list-conns"), timeout_seconds=20)


def rpm_query_file_owner(path: str | Path) -> CommandSpec:
    return CommandSpec(("rpm", "-qf", str(path)), timeout_seconds=10)


def systemctl_is_active(service_name: str) -> CommandSpec:
    return CommandSpec(("systemctl", "is-active", service_name), timeout_seconds=10)


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
    return CommandSpec(tuple(args), timeout_seconds=20)


def ip_route() -> CommandSpec:
    return CommandSpec(("ip", "route"), timeout_seconds=10)


def resolvectl_status() -> CommandSpec:
    return CommandSpec(("resolvectl", "status"), timeout_seconds=10)


def nmcli_device_show() -> CommandSpec:
    return CommandSpec(("nmcli", "device", "show"), timeout_seconds=10)


def build_pkexec_helper_command(subcommand: str, *args: str) -> CommandSpec:
    return CommandSpec(("pkexec", "gic-ipsec-helper", subcommand, *args), timeout_seconds=120)


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

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from gic_ipsec_client.backend.renderer import CONF_ROOT, SECRETS_ROOT
from gic_ipsec_client.backend.validators import ProfileValidationError, validate_uuid


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


def swanctl_load_all() -> CommandSpec:
    return CommandSpec(("swanctl", "--load-all"), timeout_seconds=30)


def swanctl_initiate(child_name: str) -> CommandSpec:
    return CommandSpec(("swanctl", "--initiate", "--child", child_name), timeout_seconds=60)


def swanctl_terminate(connection_name: str) -> CommandSpec:
    return CommandSpec(("swanctl", "--terminate", "--ike", connection_name), timeout_seconds=30)


def swanctl_list_sas() -> CommandSpec:
    return CommandSpec(("swanctl", "--list-sas"), timeout_seconds=20)


def swanctl_list_conns() -> CommandSpec:
    return CommandSpec(("swanctl", "--list-conns"), timeout_seconds=20)


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
    conf_root: Path = CONF_ROOT,
    secrets_root: Path = SECRETS_ROOT,
) -> tuple[Path, Path]:
    validate_uuid(profile_id)
    return conf_root / f"{profile_id}.conf", secrets_root / f"{profile_id}.secrets"


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def delete_profile_files(
    profile_id: str,
    *,
    conf_root: Path = CONF_ROOT,
    secrets_root: Path = SECRETS_ROOT,
) -> list[Path]:
    """Delete only the UUID-named files GIC owns below the configured swanctl roots."""

    conf_path, secrets_path = profile_paths(
        profile_id,
        conf_root=conf_root,
        secrets_root=secrets_root,
    )
    targets = ((conf_path, conf_root), (secrets_path, secrets_root))
    deleted: list[Path] = []
    for path, root in targets:
        if not _is_under(path, root):
            raise ProfileValidationError(f"Refusing to delete path outside {root}: {path}")
        if path.name not in {f"{profile_id}.conf", f"{profile_id}.secrets"}:
            raise ProfileValidationError(f"Refusing to delete unexpected filename: {path.name}")
        if path.exists():
            path.unlink()
            deleted.append(path)
    return deleted


def chmod_secret_file(path: Path) -> None:
    os.chmod(path, 0o600)

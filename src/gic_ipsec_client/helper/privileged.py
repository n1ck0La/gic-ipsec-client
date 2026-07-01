from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.models import VpnProfile
from gic_ipsec_client.backend.renderer import CONF_ROOT, SECRETS_ROOT, render_profile_files
from gic_ipsec_client.backend.validators import (
    ProfileValidationError,
    validate_profile,
    validate_uuid,
)


class HelperError(RuntimeError):
    """User-facing privileged helper error."""


def request_dir_for_uid(uid: int) -> Path:
    return Path("/run/user") / str(uid) / "gic-ipsec-client" / "helper-requests"


def validate_request_path(path: Path, *, uid: int) -> Path:
    root = request_dir_for_uid(uid).resolve(strict=False)
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise HelperError(f"Request file must be under {root}.") from exc
    if not resolved.exists():
        raise HelperError(f"Request file does not exist: {resolved}")
    stat_result = resolved.lstat()
    if stat.S_ISLNK(stat_result.st_mode):
        raise HelperError("Request file must not be a symlink.")
    if stat_result.st_uid != uid:
        raise HelperError("Request file must be owned by the invoking user.")
    if stat_result.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise HelperError("Request file must not be group- or world-writable.")
    return resolved


def read_profile_request(path: Path, *, uid: int, expected_action: str) -> VpnProfile:
    request_path = validate_request_path(path, uid=uid)
    payload = json.loads(request_path.read_text(encoding="utf-8"))
    if payload.get("action") != expected_action:
        raise HelperError(f"Request action must be {expected_action}.")
    profile = VpnProfile.from_dict(payload.get("profile", {}))
    validate_profile(profile)
    return profile


def _atomic_write(path: Path, content: str, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_path, mode)
        if os.geteuid() == 0:
            os.chown(tmp_path, 0, 0)
        tmp_path.replace(path)
        os.chmod(path, mode)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def render_profile_from_request(request_path: Path, *, uid: int) -> dict[str, str]:
    profile = read_profile_request(request_path, uid=uid, expected_action="render_profile")
    rendered = render_profile_files(profile)
    CONF_ROOT.mkdir(parents=True, exist_ok=True)
    SECRETS_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS_ROOT, 0o700)
    _atomic_write(rendered.config_path, rendered.config_text, mode=0o644)
    _atomic_write(rendered.secrets_path, rendered.secrets_text, mode=0o600)
    return {
        "config_path": str(rendered.config_path),
        "secrets_path": str(rendered.secrets_path),
    }


def delete_profile(profile_id: str) -> list[str]:
    validate_uuid(profile_id)
    return [str(path) for path in commands.delete_profile_files(profile_id)]


def load_profile() -> int:
    return commands.run_command(commands.swanctl_load_all()).returncode


def connect_profile(profile_id: str) -> int:
    validate_uuid(profile_id)
    return commands.run_command(commands.swanctl_initiate(f"gic-{profile_id}-child")).returncode


def disconnect_profile(profile_id: str) -> int:
    validate_uuid(profile_id)
    return commands.run_command(commands.swanctl_terminate(f"gic-{profile_id}")).returncode


def status_profile(profile_id: str) -> str:
    validate_uuid(profile_id)
    completed = commands.run_command(commands.swanctl_list_sas())
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0:
        return "Failed"
    return "Connected" if f"gic-{profile_id}" in output else "Disconnected"


def helper_uid() -> int:
    pkexec_uid = os.environ.get("PKEXEC_UID")
    if pkexec_uid:
        return int(pkexec_uid)
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid:
        return int(sudo_uid)
    return os.getuid()


def ensure_runtime_tools() -> None:
    if not shutil.which("swanctl"):
        raise HelperError("swanctl was not found. Install strongSwan swanctl packages first.")


def error_to_message(exc: Exception) -> str:
    if isinstance(exc, (HelperError, ProfileValidationError, FileNotFoundError)):
        return str(exc)
    return f"Unexpected helper failure: {exc}"

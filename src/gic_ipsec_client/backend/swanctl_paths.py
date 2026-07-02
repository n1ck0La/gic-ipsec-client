from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

DEBIAN_SWANCTL_ROOT = Path("/etc/swanctl")
FEDORA_SWANCTL_ROOT = Path("/etc/strongswan/swanctl")
KNOWN_SWANCTL_ROOTS = (DEBIAN_SWANCTL_ROOT, FEDORA_SWANCTL_ROOT)
PROFILE_FILE_PREFIX = "gic-"
LEGACY_PROFILE_FILE_PREFIX = "gic-"

CommandRunner = Callable[[tuple[str, ...], int], str]


@dataclass(slots=True)
class SwanctlLayout:
    root: Path
    source: str
    use_secrets_dir: bool = False
    include_lines: tuple[str, ...] = ()
    include_lines_by_root: dict[str, tuple[str, ...]] = field(default_factory=dict)
    root_exists: dict[str, bool] = field(default_factory=dict)
    distro_family: str = "unknown"
    systemctl_include_lines: tuple[str, ...] = ()
    log_include_lines: tuple[str, ...] = ()

    @property
    def conf_dir(self) -> Path:
        return self.root / "conf.d"

    @property
    def secrets_dir(self) -> Path:
        return self.root / "secrets.d"

    def profile_config_path(self, profile_id: str) -> Path:
        return self.conf_dir / f"{PROFILE_FILE_PREFIX}{profile_id}.conf"

    def profile_secrets_path(self, profile_id: str) -> Path:
        return self.secrets_dir / f"{PROFILE_FILE_PREFIX}{profile_id}.secrets"


def normalize_config_root_override(value: str | os.PathLike[str] | None) -> Path | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw or raw.lower() == "auto":
        return None
    path = Path(raw)
    if path not in KNOWN_SWANCTL_ROOTS:
        allowed = ", ".join(str(root) for root in KNOWN_SWANCTL_ROOTS)
        raise ValueError(f"swanctl config root override must be one of: {allowed}")
    return path


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


def distro_family(os_release: Mapping[str, str] | None = None) -> str:
    release = dict(os_release) if os_release is not None else read_os_release()
    distro_id = release.get("ID", "").lower()
    id_like = release.get("ID_LIKE", "").lower()
    values = {distro_id, *id_like.split()}
    if values & {"debian", "ubuntu"}:
        return "debian"
    if values & {"fedora", "rhel", "centos"}:
        return "fedora"
    return "unknown"


def read_swanctl_conf_include_lines(root: Path) -> tuple[str, ...]:
    conf = root / "swanctl.conf"
    if not conf.exists():
        return ()
    try:
        lines = conf.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return (f"<could not read {conf}: {exc}>",)
    return tuple(line.strip() for line in lines if _is_include_line(line))


def swanctl_conf_includes_secrets_dir(root: Path) -> bool:
    return any("secrets.d" in line.lower() for line in read_swanctl_conf_include_lines(root))


def detect_swanctl_config_root(
    *,
    override: str | os.PathLike[str] | None = None,
    os_release: Mapping[str, str] | None = None,
    command_runner: CommandRunner | None = None,
) -> tuple[Path, str]:
    manual_root = normalize_config_root_override(override)
    if manual_root is not None:
        return manual_root, "manual override"

    runner = command_runner or _default_command_runner
    systemctl_text = runner(("systemctl", "cat", "strongswan"), 10)
    systemctl_roots = _mentioned_roots(systemctl_text)
    if len(systemctl_roots) == 1:
        return systemctl_roots[0], "systemctl cat strongswan"

    log_text = runner(
        (
            "journalctl",
            "-u",
            "strongswan*",
            "-u",
            "charon-systemd",
            "--since",
            "30 minutes ago",
            "-n",
            "200",
            "--no-pager",
        ),
        20,
    )
    log_roots = _mentioned_roots(log_text)
    if len(log_roots) == 1:
        return log_roots[0], "strongSwan startup logs"

    family = distro_family(os_release)
    if family == "fedora":
        return FEDORA_SWANCTL_ROOT, "Fedora distro default"
    if family == "debian":
        return DEBIAN_SWANCTL_ROOT, "Debian/Ubuntu distro default"

    include_roots = [
        root for root in KNOWN_SWANCTL_ROOTS if _include_lines_reference_conf_d(root)
    ]
    if len(include_roots) == 1:
        return include_roots[0], "swanctl.conf include lines"

    existing_roots = [root for root in KNOWN_SWANCTL_ROOTS if root.exists()]
    if len(existing_roots) == 1:
        return existing_roots[0], "existing swanctl root"

    return DEBIAN_SWANCTL_ROOT, "fallback default"


def detect_swanctl_layout(
    *,
    override: str | os.PathLike[str] | None = None,
    os_release: Mapping[str, str] | None = None,
    command_runner: CommandRunner | None = None,
) -> SwanctlLayout:
    runner = command_runner or _default_command_runner
    root, source = detect_swanctl_config_root(
        override=override,
        os_release=os_release,
        command_runner=runner,
    )
    include_lines_by_root = {
        str(candidate): read_swanctl_conf_include_lines(candidate)
        for candidate in KNOWN_SWANCTL_ROOTS
    }
    root_exists = {str(candidate): candidate.exists() for candidate in KNOWN_SWANCTL_ROOTS}
    include_lines = include_lines_by_root.get(str(root), ())
    systemctl_text = runner(("systemctl", "cat", "strongswan"), 10)
    log_text = runner(
        (
            "journalctl",
            "-u",
            "strongswan*",
            "-u",
            "charon-systemd",
            "--since",
            "30 minutes ago",
            "-n",
            "200",
            "--no-pager",
        ),
        20,
    )
    return SwanctlLayout(
        root=root,
        source=source,
        use_secrets_dir=root == DEBIAN_SWANCTL_ROOT
        and any("secrets.d" in line.lower() for line in include_lines),
        include_lines=include_lines,
        include_lines_by_root=include_lines_by_root,
        root_exists=root_exists,
        distro_family=distro_family(os_release),
        systemctl_include_lines=_path_reference_lines(systemctl_text),
        log_include_lines=_path_reference_lines(log_text),
    )


def swanctl_files_by_root(*, max_files_per_root: int = 200) -> dict[str, list[str]]:
    return {
        str(root): _files_under_root(root, max_files=max_files_per_root)
        for root in KNOWN_SWANCTL_ROOTS
    }


def profile_loaded_in_list_conns(
    list_conns_output: str,
    *,
    connection_name: str,
    child_name: str,
) -> bool:
    connection_marker = f"{connection_name}:"
    child_marker = f"{child_name}:"
    return connection_marker in list_conns_output and child_marker in list_conns_output


def _default_command_runner(args: tuple[str, ...], timeout_seconds: int) -> str:
    if not args or not shutil.which(args[0]):
        return ""
    try:
        completed = subprocess.run(  # noqa: S603
            list(args),
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (completed.stdout or "") + (completed.stderr or "")


def _mentioned_roots(text: str) -> list[Path]:
    matches = [root for root in KNOWN_SWANCTL_ROOTS if str(root) in text]
    return list(dict.fromkeys(matches))


def _path_reference_lines(text: str) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in text.splitlines()
        if any(str(root) in line for root in KNOWN_SWANCTL_ROOTS)
        or "conf.d" in line
        or "secrets.d" in line
    )


def _is_include_line(line: str) -> bool:
    stripped = line.strip()
    return (
        bool(stripped)
        and not stripped.startswith("#")
        and stripped.lower().startswith("include")
    )


def _include_lines_reference_conf_d(root: Path) -> bool:
    return any("conf.d" in line.lower() for line in read_swanctl_conf_include_lines(root))


def _files_under_root(root: Path, *, max_files: int) -> list[str]:
    if not root.exists():
        return []
    found: list[str] = []
    try:
        iterator = root.rglob("*")
        for path in iterator:
            if not path.is_file():
                continue
            try:
                found.append(str(path.relative_to(root)))
            except ValueError:
                found.append(str(path))
            if len(found) >= max_files:
                found.append("<truncated>")
                break
    except OSError as exc:
        return [f"<could not list {root}: {exc}>"]
    return sorted(found)

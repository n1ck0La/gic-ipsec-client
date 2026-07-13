from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.models import CONNECTION_PREFIX, LEGACY_CONNECTION_PREFIX, VpnProfile
from gic_ipsec_client.backend.renderer import render_profile_files
from gic_ipsec_client.backend.resolved import (
    DUMMY_DNS_INTERFACE,
    LOOPBACK_DNS_INTERFACE,
    apply_resolved_dns,
    cleanup_dns_apply_report,
    flush_resolved_dns_caches,
    ip_route_get,
    load_dns_apply_report,
    load_resolved_plan,
    parse_default_interface,
    resolvectl_status_interface,
    revert_resolved_dns,
    verify_resolved_dns_after_disconnect,
)
from gic_ipsec_client.backend.resolved import (
    reconnect_network_interface as reconnect_saved_network_interface,
)
from gic_ipsec_client.backend.swanctl_paths import (
    FEDORA_SWANCTL_ROOT,
    KNOWN_SWANCTL_ROOTS,
    SwanctlLayout,
    detect_swanctl_layout,
    distro_family,
    profile_loaded_in_list_conns,
    swanctl_files_by_root,
)
from gic_ipsec_client.backend.validators import (
    ProfileValidationError,
    validate_profile,
    validate_uuid,
)


class HelperError(RuntimeError):
    """User-facing privileged helper error."""


RUNTIME_PROFILE_ROOT = Path("/run/gic-ipsec-client/profiles")
CONNECT_LOCK_ROOT = Path("/run/gic-ipsec-client/connect-locks")
CONNECT_REPORT_ROOT = Path("/run/gic-ipsec-client/connect-reports")
VICI_WAIT_ATTEMPTS = 20
VICI_WAIT_INTERVAL_SECONDS = 0.5
SAFELY_STOPPED_SERVICE_STATES = {"inactive", "failed", "not found"}
PROFILE_WRITE_FAILED_MESSAGE = "Generated strongSwan profile file was not written."


def _path_is_socket(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return False


def _vici_socket_state(
    socket_exists: object,
    run_command: object | None = None,
) -> dict[str, object]:
    socket_exists_fn = socket_exists if callable(socket_exists) else _path_is_socket
    run_command_fn = run_command if callable(run_command) else commands.run_command
    exists_by_path = {
        str(path): bool(socket_exists_fn(path)) for path in commands.VICI_SOCKET_PATHS
    }
    listening_by_path = {str(path): False for path in commands.VICI_SOCKET_PATHS}
    ss_returncode = -1
    ss_output = ""
    try:
        completed = run_command_fn(commands.ss_listening_unix_sockets())
        ss_returncode = int(getattr(completed, "returncode", -1))
        ss_output = _completed_message(completed)
        if ss_returncode == 0:
            socket_tokens = {
                token
                for line in str(getattr(completed, "stdout", "") or "").splitlines()
                for token in line.split()
            }
            listening_by_path = {
                str(path): str(path) in socket_tokens for path in commands.VICI_SOCKET_PATHS
            }
    except (OSError, TimeoutError, subprocess.TimeoutExpired):
        ss_returncode = 127
    existing_paths = [path for path, exists in exists_by_path.items() if exists]
    listening_paths = [path for path, listening in listening_by_path.items() if listening]
    candidates = list(dict.fromkeys([*existing_paths, *listening_paths]))
    vici_socket_path = candidates[0] if candidates else ""
    return {
        "run_strongswan_charon_vici_exists": exists_by_path.get(
            "/run/strongswan/charon.vici",
            False,
        ),
        "var_run_strongswan_charon_vici_exists": exists_by_path.get(
            "/var/run/strongswan/charon.vici",
            False,
        ),
        "run_charon_vici_exists": exists_by_path.get("/run/charon.vici", False),
        "var_run_charon_vici_exists": exists_by_path.get("/var/run/charon.vici", False),
        "run_strongswan_charon_vici_listening": listening_by_path.get(
            "/run/strongswan/charon.vici",
            False,
        ),
        "var_run_strongswan_charon_vici_listening": listening_by_path.get(
            "/var/run/strongswan/charon.vici",
            False,
        ),
        "run_charon_vici_listening": listening_by_path.get("/run/charon.vici", False),
        "var_run_charon_vici_listening": listening_by_path.get(
            "/var/run/charon.vici",
            False,
        ),
        "vici_socket_file_exists": bool(existing_paths),
        "vici_socket_listening": bool(listening_paths),
        "vici_socket_available": False,
        "vici_usable": False,
        "selected_vici_uri": (
            commands.FEDORA_VICI_URI
            if exists_by_path.get(str(commands.FEDORA_VICI_SOCKET_PATH), False)
            else ""
        ),
        "vici_socket_path": vici_socket_path,
        "vici_socket_candidates": candidates,
        "vici_listening_paths": listening_paths,
        "ss_lx_returncode": ss_returncode,
        "ss_lx_output": ss_output,
    }


def _service_available(
    service_name: str,
    *,
    run_command: object,
) -> bool:
    run_command_fn = run_command if callable(run_command) else commands.run_command
    try:
        completed = run_command_fn(commands.systemctl_list_unit_file(service_name))
    except (OSError, TimeoutError, subprocess.TimeoutExpired):
        return False
    return service_name in _completed_message(completed)


def _service_active_state(
    service_name: str,
    *,
    run_command: object,
) -> str:
    run_command_fn = run_command if callable(run_command) else commands.run_command
    try:
        completed = run_command_fn(commands.systemctl_is_active(service_name))
    except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        return f"unknown: {exc}"
    output = _completed_message(completed).strip()
    if output:
        return output.splitlines()[0].strip()
    return "active" if completed.returncode == 0 else "inactive"


def _services_safely_stopped(*states: str) -> bool:
    return all(state in SAFELY_STOPPED_SERVICE_STATES for state in states)


def _stop_services_and_cleanup_vici(
    payload: dict[str, object],
    *,
    run_command: object,
) -> bool:
    run_command_fn = run_command if callable(run_command) else commands.run_command
    payload["vici_recovery_attempted"] = True
    try:
        completed = run_command_fn(
            commands.systemctl_stop_services(
                commands.STRONGSWAN_SERVICE,
                commands.STRONGSWAN_STARTER_SERVICE,
            )
        )
        payload["vici_recovery_stop_returncode"] = completed.returncode
        payload["vici_recovery_stop_output"] = _completed_message(completed)
    except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        payload["vici_recovery_stop_returncode"] = 127
        payload["vici_recovery_stop_output"] = str(exc)

    strongswan_state = _service_active_state(
        commands.STRONGSWAN_SERVICE,
        run_command=run_command_fn,
    )
    starter_state = _service_active_state(
        commands.STRONGSWAN_STARTER_SERVICE,
        run_command=run_command_fn,
    )
    payload["vici_recovery_strongswan_state"] = strongswan_state
    payload["vici_recovery_starter_state"] = starter_state
    if not _services_safely_stopped(strongswan_state, starter_state):
        payload["vici_recovery_cleanup_skipped"] = (
            "VICI socket cleanup skipped because both strongSwan services are not stopped."
        )
        return False

    deleted: list[str] = []
    errors: list[str] = []
    for path in commands.VICI_SOCKET_PATHS:
        try:
            existed = os.path.lexists(path)
            path.unlink(missing_ok=True)
            if existed:
                deleted.append(str(path))
        except OSError as exc:
            errors.append(f"Could not remove stale VICI socket {path}: {exc}")
    payload["vici_recovery_deleted_paths"] = deleted
    payload["vici_recovery_cleanup_errors"] = errors
    return not errors


@contextmanager
def _connect_in_progress_guard(profile_id: str) -> Iterator[None]:
    CONNECT_LOCK_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CONNECT_LOCK_ROOT, 0o700)
    lock_path = CONNECT_LOCK_ROOT / f"{profile_id}.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HelperError(
                "A connection attempt for this profile is already in progress."
            ) from exc
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def detect_strongswan_service(
    *,
    run_command: object | None = None,
) -> dict[str, str]:
    run_command_fn = run_command if callable(run_command) else commands.run_command
    if _service_available(commands.STRONGSWAN_SERVICE, run_command=run_command_fn):
        return {
            "detected_strongswan_service": commands.STRONGSWAN_SERVICE,
            "strongswan_service_state": _service_active_state(
                commands.STRONGSWAN_SERVICE,
                run_command=run_command_fn,
            ),
        }
    return {
        "detected_strongswan_service": "",
        "strongswan_service_state": "not found",
    }


def _wait_for_usable_vici(
    payload: dict[str, object],
    *,
    socket_exists: object,
    run_command: object,
    sleep: object,
    attempts: int = VICI_WAIT_ATTEMPTS,
) -> None:
    socket_exists_fn = socket_exists if callable(socket_exists) else _path_is_socket
    sleep_fn = sleep if callable(sleep) else time.sleep
    for attempt in range(attempts):
        payload.update(_vici_socket_state(socket_exists_fn, run_command=run_command))
        payload.update(
            _swanctl_list_conns_state(
                run_command=run_command,
                vici_uri=str(payload.get("selected_vici_uri", "") or ""),
            )
        )
        usable = bool(payload["swanctl_list_conns_ok"])
        payload["vici_socket_available"] = usable
        payload["vici_usable"] = usable
        if usable:
            return
        if attempt + 1 < attempts:
            sleep_fn(VICI_WAIT_INTERVAL_SECONDS)


def _swanctl_list_conns_state(
    *,
    run_command: object,
    vici_uri: str = "",
) -> dict[str, object]:
    run_command_fn = run_command if callable(run_command) else commands.run_command
    try:
        completed = run_command_fn(commands.swanctl_list_conns(vici_uri=vici_uri))
    except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        return {
            "preflight_list_conns_returncode": 127,
            "preflight_list_conns_stdout": "",
            "preflight_list_conns_stderr": str(exc),
            "preflight_list_conns_output": str(exc),
            "swanctl_list_conns_ok": False,
        }
    output = _completed_message(completed)
    return {
        "preflight_list_conns_returncode": completed.returncode,
        "preflight_list_conns_stdout": getattr(completed, "stdout", "") or "",
        "preflight_list_conns_stderr": getattr(completed, "stderr", "") or "",
        "preflight_list_conns_output": output,
        "swanctl_list_conns_ok": completed.returncode == 0,
    }


def strongswan_preflight(
    *,
    raise_on_failure: bool = True,
    ensure_service: bool = True,
    run_command: object | None = None,
    socket_exists: object | None = None,
    sleep: object | None = None,
) -> dict[str, object]:
    run_command_fn = run_command if callable(run_command) else commands.run_command
    socket_exists_fn = socket_exists if callable(socket_exists) else _path_is_socket
    sleep_fn = sleep if callable(sleep) else time.sleep
    payload: dict[str, object] = {
        "command_v_swanctl": commands.command_v("swanctl"),
        "resolved_swanctl_path": commands.resolve_swanctl_path() or "",
        "selected_strongswan_service": "",
        "strongswan_starter_active": False,
        "strongswan_starter_state": "",
        "strongswan_starter_disabled": False,
        "strongswan_starter_disable_returncode": None,
        "strongswan_starter_disable_output": "",
        "strongswan_starter_warning": "",
        "strongswan_service_available": False,
        "strongswan_service_active_state": "",
        "charon_systemd_service_available": False,
        "charon_systemd_service_state": "",
        "strongswan_service_started": False,
        "strongswan_service_enable_returncode": None,
        "strongswan_service_enable_output": "",
        "started_strongswan_service": False,
        "systemctl_start_returncode": None,
        "systemctl_start_output": "",
        "preflight_list_conns_returncode": None,
        "preflight_list_conns_stdout": "",
        "preflight_list_conns_stderr": "",
        "preflight_list_conns_output": "",
        "swanctl_list_conns_ok": False,
        "vici_usable": False,
        "selected_vici_uri": "",
        "vici_recovery_attempted": False,
        "vici_recovery_stop_returncode": None,
        "vici_recovery_stop_output": "",
        "vici_recovery_deleted_paths": [],
        "vici_recovery_cleanup_errors": [],
        "vici_recovery_cleanup_skipped": "",
        "vici_recovery_start_returncode": None,
        "vici_recovery_start_output": "",
        "preflight_error": "",
    }
    payload.update(detect_strongswan_service(run_command=run_command_fn))
    payload["selected_strongswan_service"] = commands.STRONGSWAN_SERVICE
    strongswan_service_available = _service_available(
        commands.STRONGSWAN_SERVICE,
        run_command=run_command_fn,
    )
    charon_systemd_service_available = _service_available(
        "charon-systemd.service",
        run_command=run_command_fn,
    )
    strongswan_service_state = (
        _service_active_state(commands.STRONGSWAN_SERVICE, run_command=run_command_fn)
        if strongswan_service_available
        else "not found"
    )
    charon_systemd_service_state = (
        _service_active_state("charon-systemd.service", run_command=run_command_fn)
        if charon_systemd_service_available
        else "not found"
    )
    payload["strongswan_service_available"] = strongswan_service_available
    payload["strongswan_service_active_state"] = strongswan_service_state
    payload["charon_systemd_service_available"] = charon_systemd_service_available
    payload["charon_systemd_service_state"] = charon_systemd_service_state
    if strongswan_service_available:
        payload["detected_strongswan_service"] = commands.STRONGSWAN_SERVICE
        payload["strongswan_service_state"] = strongswan_service_state
    starter_state = _service_active_state(
        commands.STRONGSWAN_STARTER_SERVICE,
        run_command=run_command_fn,
    )
    starter_active = starter_state == "active"
    payload["strongswan_starter_state"] = starter_state
    payload["strongswan_starter_active"] = starter_active
    if starter_active:
        payload["strongswan_starter_warning"] = commands.STARTER_INCOMPATIBLE_MESSAGE
    payload.update(_vici_socket_state(socket_exists_fn, run_command=run_command_fn))

    if not payload["resolved_swanctl_path"]:
        message = (
            "swanctl was not found. Install strongSwan packages first. "
            "Searched PATH, /usr/bin/swanctl, and /usr/sbin/swanctl."
        )
        payload["preflight_error"] = message
        if raise_on_failure:
            raise HelperError(message)
        return payload

    if ensure_service:
        if starter_active and not _stop_services_and_cleanup_vici(
            payload,
            run_command=run_command_fn,
        ):
            message = str(payload.get("vici_recovery_cleanup_skipped") or "").strip() or (
                "Could not safely stop both strongSwan services before VICI cleanup."
            )
            payload["preflight_error"] = message
            if raise_on_failure:
                raise HelperError(message)
            return payload

        try:
            disable_completed = run_command_fn(
                commands.systemctl_disable_now(commands.STRONGSWAN_STARTER_SERVICE)
            )
            payload["strongswan_starter_disable_returncode"] = disable_completed.returncode
            payload["strongswan_starter_disable_output"] = _completed_message(disable_completed)
            payload["strongswan_starter_disabled"] = disable_completed.returncode == 0
        except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            payload["strongswan_starter_disable_returncode"] = 127
            payload["strongswan_starter_disable_output"] = str(exc)

        try:
            enable_completed = run_command_fn(
                commands.systemctl_enable_now(commands.STRONGSWAN_SERVICE)
            )
            payload["strongswan_service_enable_returncode"] = enable_completed.returncode
            payload["strongswan_service_enable_output"] = _completed_message(enable_completed)
            payload["strongswan_service_started"] = enable_completed.returncode == 0
            payload["started_strongswan_service"] = enable_completed.returncode == 0
        except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            payload["strongswan_service_enable_returncode"] = 127
            payload["strongswan_service_enable_output"] = str(exc)

        if payload["strongswan_service_enable_returncode"] != 0:
            message = str(payload["strongswan_service_enable_output"]).strip() or (
                "systemctl enable --now strongswan.service failed."
            )
            payload["preflight_error"] = message
            if raise_on_failure:
                raise HelperError(message)
            return payload
        payload["detected_strongswan_service"] = commands.STRONGSWAN_SERVICE
        payload["strongswan_service_state"] = _service_active_state(
            commands.STRONGSWAN_SERVICE,
            run_command=run_command_fn,
        )
        payload["strongswan_service_active_state"] = payload["strongswan_service_state"]

    _wait_for_usable_vici(
        payload,
        socket_exists=socket_exists_fn,
        run_command=run_command_fn,
        sleep=sleep_fn,
        attempts=VICI_WAIT_ATTEMPTS if ensure_service else 1,
    )
    if payload["swanctl_list_conns_ok"]:
        return payload

    if ensure_service and _stop_services_and_cleanup_vici(
        payload,
        run_command=run_command_fn,
    ):
        try:
            start_completed = run_command_fn(
                commands.systemctl_start(commands.STRONGSWAN_SERVICE)
            )
            payload["vici_recovery_start_returncode"] = start_completed.returncode
            payload["vici_recovery_start_output"] = _completed_message(start_completed)
        except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            payload["vici_recovery_start_returncode"] = 127
            payload["vici_recovery_start_output"] = str(exc)
        if payload["vici_recovery_start_returncode"] == 0:
            _wait_for_usable_vici(
                payload,
                socket_exists=socket_exists_fn,
                run_command=run_command_fn,
                sleep=sleep_fn,
            )
            if payload["swanctl_list_conns_ok"]:
                payload["strongswan_service_state"] = _service_active_state(
                    commands.STRONGSWAN_SERVICE,
                    run_command=run_command_fn,
                )
                payload["strongswan_service_active_state"] = payload[
                    "strongswan_service_state"
                ]
                return payload

    recovery_start_error = (
        str(payload.get("vici_recovery_start_output") or "")
        if payload.get("vici_recovery_start_returncode") not in {None, 0}
        else ""
    )
    payload["preflight_error"] = recovery_start_error or (
        str(payload.get("preflight_list_conns_output") or "")
        or commands.VICI_UNAVAILABLE_MESSAGE
    )
    if not payload["preflight_error"]:
        payload["preflight_error"] = commands.VICI_UNAVAILABLE_MESSAGE
    if raise_on_failure:
        raise HelperError(str(payload["preflight_error"]))
    return payload


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
    payload = read_helper_request_payload(path, uid=uid, expected_action=expected_action)
    profile = VpnProfile.from_dict(payload.get("profile", {}))
    validate_profile(profile)
    return profile


def read_helper_request_payload(
    path: Path,
    *,
    uid: int,
    expected_action: str,
) -> dict[str, object]:
    request_path = validate_request_path(path, uid=uid)
    payload = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise HelperError("Request payload must be a JSON object.")
    if payload.get("action") != expected_action:
        raise HelperError(f"Request action must be {expected_action}.")
    return payload


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


def _runtime_profile_path(profile_id: str) -> Path:
    validate_uuid(profile_id)
    return RUNTIME_PROFILE_ROOT / f"{profile_id}.json"


def _write_runtime_profile(profile: VpnProfile) -> None:
    payload = {
        "id": profile.id,
        "name": profile.name,
        "split_tunnel_enabled": profile.split_tunnel_enabled,
        "remote_routes": profile.remote_routes,
        "dns_servers": profile.dns_servers,
        "dns_search_domains": profile.dns_search_domains,
        "dns_test_names": profile.dns_test_names,
        "dns_linux_strategy": profile.dns.linux_strategy,
        "dns_interface": profile.platform.dns_interface,
    }
    path = _runtime_profile_path(profile.id)
    _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True), mode=0o600)


def _read_runtime_profile(profile_id: str) -> dict[str, object] | None:
    path = _runtime_profile_path(profile_id)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def _delete_runtime_profile(profile_id: str) -> None:
    path = _runtime_profile_path(profile_id)
    if path.exists():
        path.unlink()


def _connect_report_path(profile_id: str) -> Path:
    validate_uuid(profile_id)
    return CONNECT_REPORT_ROOT / f"{profile_id}.json"


def _write_connect_report(profile_id: str, payload: Mapping[str, object]) -> None:
    _atomic_write(
        _connect_report_path(profile_id),
        json.dumps(dict(payload), indent=2, sort_keys=True),
        mode=0o600,
    )


def _read_connect_report(profile_id: str) -> dict[str, object]:
    path = _connect_report_path(profile_id)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _delete_connect_report(profile_id: str) -> None:
    path = _connect_report_path(profile_id)
    path.unlink(missing_ok=True)


def _request_config_root_override(payload: Mapping[str, object]) -> str:
    value = payload.get("swanctl_config_root", "")
    return str(value or "")


def _effective_connect_config_root(config_root_override: str = "") -> str:
    if distro_family() == "fedora":
        return str(FEDORA_SWANCTL_ROOT)
    return config_root_override


def _connect_vici_uri(preflight: Mapping[str, object]) -> str:
    selected = str(preflight.get("selected_vici_uri", "") or "")
    if selected:
        return selected
    return commands.FEDORA_VICI_URI if distro_family() == "fedora" else ""


def _conf_d_file_listing(conf_dir: Path) -> list[str]:
    try:
        return sorted(str(path) for path in conf_dir.glob("*.conf") if path.is_file())
    except OSError as exc:
        return [f"<could not list {conf_dir}: {exc}>"]


def _new_connect_report(profile_id: str, layout: SwanctlLayout) -> dict[str, object]:
    profile_path = layout.profile_config_path(profile_id)
    return {
        "selected_profile_uuid": profile_id,
        "generated_profile_file": str(profile_path),
        "generated_profile_file_exists": profile_path.is_file(),
        "conf_d_files": _conf_d_file_listing(layout.conf_dir),
        "selected_vici_uri": _connect_vici_uri({}),
        "load_all_returncode": None,
        "load_all_stdout": "",
        "load_all_stderr": "",
        "list_conns_returncode": None,
        "list_conns_stdout": "",
        "list_conns_stderr": "",
        "selected_connection_loaded": False,
    }


def _record_generated_profile_state(
    profile_id: str,
    report: dict[str, object],
    layout: SwanctlLayout,
) -> bool:
    profile_path = layout.profile_config_path(profile_id)
    exists = profile_path.is_file()
    report.update(
        {
            "generated_profile_file": str(profile_path),
            "generated_profile_file_exists": exists,
            "conf_d_files": _conf_d_file_listing(layout.conf_dir),
        }
    )
    _write_connect_report(profile_id, report)
    return exists


def render_profile_from_request(
    request_path: Path,
    *,
    uid: int,
    config_root_override: str = "",
    expected_action: str = "render_profile",
    expected_profile_id: str = "",
) -> dict[str, str]:
    payload = read_helper_request_payload(
        request_path,
        uid=uid,
        expected_action=expected_action,
    )
    profile = VpnProfile.from_dict(payload.get("profile", {}))
    validate_profile(profile)
    if expected_profile_id and profile.id != expected_profile_id:
        raise HelperError("Request profile UUID does not match the connect command.")
    override = config_root_override or _request_config_root_override(payload)
    if expected_action == "connect":
        override = _effective_connect_config_root(override)
    layout = detect_swanctl_layout(override=override)
    rendered = render_profile_files(profile, layout=layout)
    rendered.config_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(rendered.config_path, rendered.config_text, mode=rendered.config_mode)
    if rendered.secrets_path is not None:
        rendered.secrets_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(rendered.secrets_path.parent, 0o700)
        _atomic_write(rendered.secrets_path, rendered.secrets_text, mode=rendered.secrets_mode)
    _write_runtime_profile(profile)
    return {
        "swanctl_config_root": str(layout.root),
        "layout_source": layout.source,
        "config_path": str(rendered.config_path),
        "secrets_path": str(rendered.secrets_path) if rendered.secrets_path else "",
    }


def delete_profile(profile_id: str, *, config_root_override: str = "") -> list[str]:
    validate_uuid(profile_id)
    deleted = [
        str(path)
        for path in commands.delete_profile_files(
            profile_id,
            config_root_override=config_root_override,
            all_known_roots=not bool(config_root_override),
        )
    ]
    _delete_runtime_profile(profile_id)
    _delete_connect_report(profile_id)
    revert_resolved_dns(profile_id, run_command=commands.run_command)
    cleanup_dns_apply_report(profile_id)
    return deleted


def load_profile() -> int:
    preflight = strongswan_preflight()
    vici_uri = _connect_vici_uri(preflight)
    return commands.run_command(commands.swanctl_load_all(vici_uri=vici_uri)).returncode


def connect_from_request(profile_id: str, *, uid: int) -> int:
    validate_uuid(profile_id)
    with _connect_in_progress_guard(profile_id):
        request_path = request_dir_for_uid(uid) / f"{profile_id}.json"
        validated_request = validate_request_path(request_path, uid=uid)
        request_payload = read_helper_request_payload(
            validated_request,
            uid=uid,
            expected_action="connect",
        )
        effective_root = _effective_connect_config_root(
            _request_config_root_override(request_payload)
        )
        layout = detect_swanctl_layout(override=effective_root)
        report = _new_connect_report(profile_id, layout)
        _write_connect_report(profile_id, report)
        try:
            try:
                rendered = render_profile_from_request(
                    validated_request,
                    uid=uid,
                    config_root_override=str(layout.root),
                    expected_action="connect",
                    expected_profile_id=profile_id,
                )
            except OSError as exc:
                if not _record_generated_profile_state(profile_id, report, layout):
                    raise HelperError(PROFILE_WRITE_FAILED_MESSAGE) from exc
                raise
            config_root = str(rendered.get("swanctl_config_root", "") or "")
            if not _record_generated_profile_state(profile_id, report, layout):
                raise HelperError(PROFILE_WRITE_FAILED_MESSAGE)
            return _connect_profile(profile_id, config_root_override=config_root)
        finally:
            try:
                validated_request.unlink(missing_ok=True)
            except OSError:
                pass


def connect_profile(profile_id: str, *, config_root_override: str = "") -> int:
    validate_uuid(profile_id)
    with _connect_in_progress_guard(profile_id):
        return _connect_profile(profile_id, config_root_override=config_root_override)


def _connect_profile(profile_id: str, *, config_root_override: str = "") -> int:
    validate_uuid(profile_id)
    connection_name = f"{CONNECTION_PREFIX}{profile_id}"
    child_name = f"{connection_name}-child"
    effective_root = _effective_connect_config_root(config_root_override)
    layout = detect_swanctl_layout(override=effective_root)
    profile_path = layout.profile_config_path(profile_id)
    report = _new_connect_report(profile_id, layout)
    _write_connect_report(profile_id, report)
    if not profile_path.is_file():
        raise HelperError(PROFILE_WRITE_FAILED_MESSAGE)
    preflight = strongswan_preflight()
    vici_uri = _connect_vici_uri(preflight)
    report["selected_vici_uri"] = vici_uri
    load_completed = commands.run_command(commands.swanctl_load_all(vici_uri=vici_uri))
    report.update(
        {
            "load_all_returncode": load_completed.returncode,
            "load_all_stdout": load_completed.stdout or "",
            "load_all_stderr": load_completed.stderr or "",
        }
    )
    _write_connect_report(profile_id, report)
    if load_completed.returncode != 0:
        raise HelperError(_completed_message(load_completed) or "swanctl --load-all failed.")

    list_completed = commands.run_command(commands.swanctl_list_conns(vici_uri=vici_uri))
    list_output = (list_completed.stdout or "") + (list_completed.stderr or "")
    selected_loaded = profile_loaded_in_list_conns(
        list_output,
        connection_name=connection_name,
        child_name=child_name,
    )
    report.update(
        {
            "list_conns_returncode": list_completed.returncode,
            "list_conns_stdout": list_completed.stdout or "",
            "list_conns_stderr": list_completed.stderr or "",
            "selected_connection_loaded": selected_loaded,
        }
    )
    _write_connect_report(profile_id, report)
    if list_completed.returncode != 0:
        raise HelperError(_completed_message(list_completed) or "swanctl --list-conns failed.")

    if not selected_loaded:
        raise HelperError(
            "Profile was rendered but strongSwan did not load it. "
            "Check swanctl config root and include paths."
        )
    existing_sas_completed = commands.run_command(
        commands.swanctl_list_sas(vici_uri=vici_uri)
    )
    existing_sas_output = _completed_message(existing_sas_completed)
    if existing_sas_completed.returncode != 0:
        raise HelperError(existing_sas_output or "swanctl --list-sas failed.")
    if _selected_sa_active(profile_id, existing_sas_output):
        list_sas_output = existing_sas_output
    else:
        initiate_completed = commands.run_command(
            commands.swanctl_initiate(child_name, vici_uri=vici_uri)
        )
        if initiate_completed.returncode != 0:
            raise HelperError(
                _completed_message(initiate_completed) or "swanctl --initiate failed."
            )
        list_sas_completed = commands.run_command(
            commands.swanctl_list_sas(vici_uri=vici_uri)
        )
        list_sas_output = _completed_message(list_sas_completed)
        if list_sas_completed.returncode != 0:
            raise HelperError(list_sas_output or "swanctl --list-sas failed.")
        if not _selected_sa_active(profile_id, list_sas_output):
            raise HelperError("Selected IKE_SA is not active after initiation.")
    runtime_profile = _read_runtime_profile(profile_id)
    if runtime_profile is None:
        return 0
    dns_errors = apply_resolved_dns(
        profile_id=profile_id,
        dns_servers=[str(item) for item in runtime_profile.get("dns_servers", []) or []],
        search_domains=[str(item) for item in runtime_profile.get("dns_search_domains", []) or []],
        split_tunnel_enabled=bool(runtime_profile.get("split_tunnel_enabled", True)),
        test_names=[str(item) for item in runtime_profile.get("dns_test_names", []) or []],
        linux_strategy=str(runtime_profile.get("dns_linux_strategy", "auto")),
        preferred_interface=str(runtime_profile.get("dns_interface", "auto")),
        run_command=commands.run_command,
    )
    if dns_errors:
        raise HelperError("\n".join(dns_errors))
    return 0


def disconnect_profile(profile_id: str) -> int:
    validate_uuid(profile_id)
    dns_errors = revert_resolved_dns(
        profile_id,
        run_command=commands.run_command,
        cleanup_on_success=False,
    )
    preflight = strongswan_preflight()
    vici_uri = _connect_vici_uri(preflight)
    completed = commands.run_command(
        commands.swanctl_terminate(
            f"{CONNECTION_PREFIX}{profile_id}",
            vici_uri=vici_uri,
        )
    )
    warnings = _dns_warning_lines(profile_id)
    if completed.returncode != 0:
        warnings.append(_completed_message(completed) or "swanctl --terminate failed.")
    post_flush_warnings = flush_resolved_dns_caches(run_command=commands.run_command)
    verify_errors = verify_resolved_dns_after_disconnect(
        profile_id,
        run_command=commands.run_command,
    )
    warnings.extend(post_flush_warnings)
    list_sas_completed = commands.run_command(commands.swanctl_list_sas(vici_uri=vici_uri))
    list_sas_output = _completed_message(list_sas_completed)
    sa_errors: list[str] = []
    if list_sas_completed.returncode != 0:
        sa_errors.append(list_sas_output or "swanctl --list-sas failed.")
    elif f"{LEGACY_CONNECTION_PREFIX}{profile_id}" in list_sas_output:
        legacy_completed = commands.run_command(
            commands.swanctl_terminate(
                f"{LEGACY_CONNECTION_PREFIX}{profile_id}",
                vici_uri=vici_uri,
            )
        )
        if legacy_completed.returncode != 0:
            warnings.append(
                _completed_message(legacy_completed) or "legacy swanctl --terminate failed."
            )
        list_sas_completed = commands.run_command(
            commands.swanctl_list_sas(vici_uri=vici_uri)
        )
        list_sas_output = _completed_message(list_sas_completed)
        if list_sas_completed.returncode != 0:
            sa_errors.append(list_sas_output or "swanctl --list-sas failed.")
        elif _selected_sa_active(profile_id, list_sas_output):
            sa_errors.append("Selected IKE_SA remains active after disconnect.")
    elif _selected_sa_active(profile_id, list_sas_output):
        sa_errors.append("Selected IKE_SA remains active after disconnect.")
    errors = [*dns_errors, *verify_errors, *sa_errors]
    if errors:
        raise HelperError("\n".join(errors))
    if warnings:
        _print_disconnect_warnings(warnings)
    return 0


def reconnect_network_interface(profile_id: str) -> int:
    messages = reconnect_saved_network_interface(profile_id, run_command=commands.run_command)
    if messages:
        raise HelperError("\n".join(messages))
    return 0


def status_profile(profile_id: str) -> str:
    validate_uuid(profile_id)
    try:
        preflight = strongswan_preflight()
    except HelperError:
        return "Failed"
    vici_uri = _connect_vici_uri(preflight)
    completed = commands.run_command(commands.swanctl_list_sas(vici_uri=vici_uri))
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0:
        return "Failed"
    return "Connected" if _selected_sa_active(profile_id, output) else "Disconnected"


def _selected_sa_active(profile_id: str, output: str) -> bool:
    prefixes = (CONNECTION_PREFIX, LEGACY_CONNECTION_PREFIX)
    return any(prefix + profile_id in output for prefix in prefixes)


def list_sas() -> str:
    preflight = strongswan_preflight()
    vici_uri = _connect_vici_uri(preflight)
    return _run_swanctl_for_output(commands.swanctl_list_sas(vici_uri=vici_uri))


def list_conns() -> str:
    preflight = strongswan_preflight()
    vici_uri = _connect_vici_uri(preflight)
    return _run_swanctl_for_output(commands.swanctl_list_conns(vici_uri=vici_uri))


def swanctl_diagnostics(
    *,
    profile_id: str | None = None,
    config_root_override: str = "",
) -> dict[str, object]:
    if profile_id:
        validate_uuid(profile_id)
    effective_root = _effective_connect_config_root(config_root_override)
    layout = detect_swanctl_layout(override=effective_root)
    resolved_swanctl_path = commands.resolve_swanctl_path() or ""
    swanctl_rpm_owner = _rpm_owner_for_path(resolved_swanctl_path)
    preflight = strongswan_preflight(raise_on_failure=False, ensure_service=False)
    vici_uri = _connect_vici_uri(preflight)
    if preflight.get("vici_usable"):
        list_conns_completed = commands.run_command(
            commands.swanctl_list_conns(vici_uri=vici_uri)
        )
        list_sas_completed = commands.run_command(commands.swanctl_list_sas(vici_uri=vici_uri))
    else:
        message = str(preflight.get("preflight_error") or commands.VICI_UNAVAILABLE_MESSAGE)
        list_conns_completed = _synthetic_completed(
            commands.swanctl_list_conns(vici_uri=vici_uri).args,
            message,
        )
        list_sas_completed = _synthetic_completed(
            commands.swanctl_list_sas(vici_uri=vici_uri).args,
            message,
        )
    lo_status_completed = commands.run_command(resolvectl_status_interface(LOOPBACK_DNS_INTERFACE))
    dummy_status_completed = commands.run_command(resolvectl_status_interface(DUMMY_DNS_INTERFACE))
    default_route_completed = commands.run_command(ip_route_get("1.1.1.1"))
    default_interface = parse_default_interface(_completed_message(default_route_completed))
    default_status_completed = (
        commands.run_command(resolvectl_status_interface(default_interface))
        if default_interface
        else None
    )
    list_conns_ok = list_conns_completed.returncode == 0
    list_conns_output = _completed_message(list_conns_completed)
    profile_config = layout.profile_config_path(profile_id) if profile_id else None
    connection_name = f"{CONNECTION_PREFIX}{profile_id}" if profile_id else ""
    child_name = f"{connection_name}-child" if profile_id else ""
    loaded = (
        profile_loaded_in_list_conns(
            list_conns_output,
            connection_name=connection_name,
            child_name=child_name,
        )
        if profile_id
        else None
    )
    dns_state_snapshot = load_resolved_plan(profile_id) if profile_id else None
    connect_report = _read_connect_report(profile_id) if profile_id else {}
    return {
        "selected_profile_uuid": profile_id or "",
        "command_v_swanctl": commands.command_v("swanctl"),
        "resolved_swanctl_path": resolved_swanctl_path,
        "swanctl_rpm_owner": swanctl_rpm_owner,
        "selected_strongswan_service": preflight.get("selected_strongswan_service", ""),
        "detected_strongswan_service": preflight.get("detected_strongswan_service", ""),
        "strongswan_service_state": preflight.get("strongswan_service_state", ""),
        "strongswan_service_available": preflight.get("strongswan_service_available", False),
        "strongswan_service_active_state": preflight.get(
            "strongswan_service_active_state",
            "",
        ),
        "charon_systemd_service_available": preflight.get(
            "charon_systemd_service_available",
            False,
        ),
        "charon_systemd_service_state": preflight.get(
            "charon_systemd_service_state",
            "",
        ),
        "strongswan_starter_active": preflight.get("strongswan_starter_active", False),
        "strongswan_starter_state": preflight.get("strongswan_starter_state", ""),
        "strongswan_starter_disabled": preflight.get("strongswan_starter_disabled", False),
        "strongswan_starter_disable_returncode": preflight.get(
            "strongswan_starter_disable_returncode"
        ),
        "strongswan_starter_disable_output": preflight.get(
            "strongswan_starter_disable_output",
            "",
        ),
        "strongswan_starter_warning": preflight.get("strongswan_starter_warning", ""),
        "strongswan_service_started": preflight.get("strongswan_service_started", False),
        "strongswan_service_enable_returncode": preflight.get(
            "strongswan_service_enable_returncode"
        ),
        "strongswan_service_enable_output": preflight.get(
            "strongswan_service_enable_output",
            "",
        ),
        "run_charon_vici_exists": preflight.get("run_charon_vici_exists", False),
        "run_strongswan_charon_vici_exists": preflight.get(
            "run_strongswan_charon_vici_exists",
            False,
        ),
        "var_run_charon_vici_exists": preflight.get("var_run_charon_vici_exists", False),
        "var_run_strongswan_charon_vici_exists": preflight.get(
            "var_run_strongswan_charon_vici_exists",
            False,
        ),
        "run_charon_vici_listening": preflight.get("run_charon_vici_listening", False),
        "run_strongswan_charon_vici_listening": preflight.get(
            "run_strongswan_charon_vici_listening",
            False,
        ),
        "var_run_charon_vici_listening": preflight.get(
            "var_run_charon_vici_listening",
            False,
        ),
        "var_run_strongswan_charon_vici_listening": preflight.get(
            "var_run_strongswan_charon_vici_listening",
            False,
        ),
        "vici_socket_file_exists": preflight.get("vici_socket_file_exists", False),
        "vici_socket_listening": preflight.get("vici_socket_listening", False),
        "vici_socket_available": list_conns_ok,
        "vici_usable": list_conns_ok,
        "selected_vici_uri": vici_uri,
        "vici_socket_path": preflight.get("vici_socket_path", ""),
        "vici_socket_candidates": preflight.get("vici_socket_candidates", []),
        "vici_listening_paths": preflight.get("vici_listening_paths", []),
        "ss_lx_returncode": preflight.get("ss_lx_returncode"),
        "ss_lx_output": preflight.get("ss_lx_output", ""),
        "preflight_list_conns_returncode": preflight.get("preflight_list_conns_returncode"),
        "preflight_list_conns_stdout": preflight.get("preflight_list_conns_stdout", ""),
        "preflight_list_conns_stderr": preflight.get("preflight_list_conns_stderr", ""),
        "swanctl_list_conns_ok": list_conns_ok,
        "started_strongswan_service": preflight.get("started_strongswan_service", False),
        "systemctl_start_returncode": preflight.get("systemctl_start_returncode"),
        "systemctl_start_output": preflight.get("systemctl_start_output", ""),
        "preflight_error": preflight.get("preflight_error", ""),
        "selected_swanctl_config_root": str(layout.root),
        "selection_source": layout.source,
        "uses_secrets_d": layout.use_secrets_dir,
        "root_exists": layout.root_exists,
        "swanctl_conf_include_lines": layout.include_lines_by_root,
        "systemctl_cat_strongswan_include_lines": layout.systemctl_include_lines,
        "startup_log_include_lines": layout.log_include_lines,
        "files_under_roots": swanctl_files_by_root(),
        "conf_d_files": _conf_d_file_listing(layout.conf_dir),
        "generated_profile_file": str(profile_config) if profile_config else "",
        "generated_profile_file_exists": bool(profile_config and profile_config.exists()),
        "profile_file_path": str(profile_config) if profile_config else "",
        "profile_file_exists": bool(profile_config and profile_config.exists()),
        "generated_connection_loaded": loaded,
        "selected_connection_loaded": loaded,
        "load_all_returncode": connect_report.get("load_all_returncode"),
        "load_all_stdout": connect_report.get("load_all_stdout", ""),
        "load_all_stderr": connect_report.get("load_all_stderr", ""),
        "list_conns_returncode": list_conns_completed.returncode,
        "list_conns_stdout": getattr(list_conns_completed, "stdout", "") or "",
        "list_conns_stderr": getattr(list_conns_completed, "stderr", "") or "",
        "list_conns_output": list_conns_output,
        "list_sas_returncode": list_sas_completed.returncode,
        "list_sas_stdout": getattr(list_sas_completed, "stdout", "") or "",
        "list_sas_stderr": getattr(list_sas_completed, "stderr", "") or "",
        "list_sas_output": _completed_message(list_sas_completed),
        "dns_apply_report": load_dns_apply_report(profile_id) if profile_id else {},
        "dns_state_snapshot": dns_state_snapshot.to_dict() if dns_state_snapshot else {},
        "default_dns_interface": default_interface,
        "ip_route_get_1_1_1_1_returncode": default_route_completed.returncode,
        "ip_route_get_1_1_1_1_output": _completed_message(default_route_completed),
        "resolvectl_status_lo_returncode": lo_status_completed.returncode,
        "resolvectl_status_lo_output": _completed_message(lo_status_completed),
        "resolvectl_status_gicipsec0_returncode": dummy_status_completed.returncode,
        "resolvectl_status_gicipsec0_output": _completed_message(dummy_status_completed),
        "resolvectl_status_default_interface_returncode": default_status_completed.returncode
        if default_status_completed
        else -1,
        "resolvectl_status_default_interface_output": _completed_message(default_status_completed)
        if default_status_completed
        else "",
        "known_roots": [str(root) for root in KNOWN_SWANCTL_ROOTS],
    }


def helper_uid() -> int:
    pkexec_uid = os.environ.get("PKEXEC_UID")
    if pkexec_uid:
        return int(pkexec_uid)
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid:
        return int(sudo_uid)
    return os.getuid()


def ensure_runtime_tools() -> None:
    if not commands.resolve_swanctl_path():
        raise FileNotFoundError(
            "swanctl was not found. Install strongSwan packages first. "
            "Searched PATH, /usr/bin/swanctl, and /usr/sbin/swanctl."
        )


def error_to_message(exc: Exception) -> str:
    if isinstance(exc, (HelperError, ProfileValidationError, FileNotFoundError)):
        return str(exc)
    return f"Unexpected helper failure: {exc}"


def _run_swanctl_for_output(spec: commands.CommandSpec) -> str:
    completed = commands.run_command(spec)
    output = _completed_message(completed)
    if completed.returncode != 0:
        raise HelperError(output or f"{' '.join(spec.args)} failed.")
    return output


def _rpm_owner_for_path(path: str) -> str:
    if not path:
        return ""
    if not commands.command_v("rpm"):
        return "rpm not found"
    completed = commands.run_command(commands.rpm_query_file_owner(path))
    return _completed_message(completed)


def _synthetic_completed(
    args: tuple[str, ...],
    message: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr=message)


def _completed_message(completed: object) -> str:
    stdout = getattr(completed, "stdout", "") or ""
    stderr = getattr(completed, "stderr", "") or ""
    return (stdout + stderr).strip()


def _dns_warning_lines(profile_id: str) -> list[str]:
    report = load_dns_apply_report(profile_id)
    raw_warnings = report.get("warnings", []) if isinstance(report, dict) else []
    if not isinstance(raw_warnings, list):
        return []
    return [str(item) for item in raw_warnings if str(item)]


def _print_disconnect_warnings(warnings: list[str]) -> None:
    print("Disconnect completed with warnings")
    for warning in dict.fromkeys(warnings):
        print(f"- {warning}")

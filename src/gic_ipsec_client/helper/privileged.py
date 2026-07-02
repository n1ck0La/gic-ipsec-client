from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping
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
    KNOWN_SWANCTL_ROOTS,
    detect_swanctl_layout,
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


RUNTIME_PROFILE_ROOT = Path("/run/see-ipsec-client/profiles")


def request_dir_for_uid(uid: int) -> Path:
    return Path("/run/user") / str(uid) / "see-ipsec-client" / "helper-requests"


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


def _request_config_root_override(payload: Mapping[str, object]) -> str:
    value = payload.get("swanctl_config_root", "")
    return str(value or "")


def render_profile_from_request(
    request_path: Path,
    *,
    uid: int,
    config_root_override: str = "",
) -> dict[str, str]:
    payload = read_helper_request_payload(request_path, uid=uid, expected_action="render_profile")
    profile = VpnProfile.from_dict(payload.get("profile", {}))
    validate_profile(profile)
    override = config_root_override or _request_config_root_override(payload)
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
    revert_resolved_dns(profile_id, run_command=commands.run_command)
    cleanup_dns_apply_report(profile_id)
    return deleted


def load_profile() -> int:
    return commands.run_command(commands.swanctl_load_all()).returncode


def connect_profile(profile_id: str, *, config_root_override: str = "") -> int:
    validate_uuid(profile_id)
    connection_name = f"{CONNECTION_PREFIX}{profile_id}"
    child_name = f"{connection_name}-child"
    load_completed = commands.run_command(commands.swanctl_load_all())
    if load_completed.returncode != 0:
        raise HelperError(_completed_message(load_completed) or "swanctl --load-all failed.")

    list_completed = commands.run_command(commands.swanctl_list_conns())
    if list_completed.returncode != 0:
        raise HelperError(_completed_message(list_completed) or "swanctl --list-conns failed.")

    list_output = (list_completed.stdout or "") + (list_completed.stderr or "")
    if not profile_loaded_in_list_conns(
        list_output,
        connection_name=connection_name,
        child_name=child_name,
    ):
        raise HelperError(
            "Profile was rendered but strongSwan did not load it. "
            "Check swanctl config root and include paths."
        )
    initiate_completed = commands.run_command(commands.swanctl_initiate(child_name))
    if initiate_completed.returncode != 0:
        return initiate_completed.returncode
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
    completed = commands.run_command(commands.swanctl_terminate(f"{CONNECTION_PREFIX}{profile_id}"))
    warnings = _dns_warning_lines(profile_id)
    if completed.returncode != 0:
        warnings.append(_completed_message(completed) or "swanctl --terminate failed.")
    post_flush_warnings = flush_resolved_dns_caches(run_command=commands.run_command)
    verify_errors = verify_resolved_dns_after_disconnect(
        profile_id,
        run_command=commands.run_command,
    )
    warnings.extend(post_flush_warnings)
    list_sas_completed = commands.run_command(commands.swanctl_list_sas())
    list_sas_output = _completed_message(list_sas_completed)
    sa_errors: list[str] = []
    if list_sas_completed.returncode != 0:
        sa_errors.append(list_sas_output or "swanctl --list-sas failed.")
    elif f"{LEGACY_CONNECTION_PREFIX}{profile_id}" in list_sas_output:
        legacy_completed = commands.run_command(
            commands.swanctl_terminate(f"{LEGACY_CONNECTION_PREFIX}{profile_id}")
        )
        if legacy_completed.returncode != 0:
            warnings.append(
                _completed_message(legacy_completed) or "legacy swanctl --terminate failed."
            )
        list_sas_completed = commands.run_command(commands.swanctl_list_sas())
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
    completed = commands.run_command(commands.swanctl_list_sas())
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0:
        return "Failed"
    return "Connected" if _selected_sa_active(profile_id, output) else "Disconnected"


def _selected_sa_active(profile_id: str, output: str) -> bool:
    prefixes = (CONNECTION_PREFIX, LEGACY_CONNECTION_PREFIX)
    return any(prefix + profile_id in output for prefix in prefixes)


def list_sas() -> str:
    return _run_swanctl_for_output(commands.swanctl_list_sas())


def list_conns() -> str:
    return _run_swanctl_for_output(commands.swanctl_list_conns())


def swanctl_diagnostics(
    *,
    profile_id: str | None = None,
    config_root_override: str = "",
) -> dict[str, object]:
    if profile_id:
        validate_uuid(profile_id)
    layout = detect_swanctl_layout(override=config_root_override)
    list_conns_completed = commands.run_command(commands.swanctl_list_conns())
    list_sas_completed = commands.run_command(commands.swanctl_list_sas())
    lo_status_completed = commands.run_command(resolvectl_status_interface(LOOPBACK_DNS_INTERFACE))
    dummy_status_completed = commands.run_command(resolvectl_status_interface(DUMMY_DNS_INTERFACE))
    default_route_completed = commands.run_command(ip_route_get("1.1.1.1"))
    default_interface = parse_default_interface(_completed_message(default_route_completed))
    default_status_completed = (
        commands.run_command(resolvectl_status_interface(default_interface))
        if default_interface
        else None
    )
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
    return {
        "selected_swanctl_config_root": str(layout.root),
        "selection_source": layout.source,
        "uses_secrets_d": layout.use_secrets_dir,
        "root_exists": layout.root_exists,
        "swanctl_conf_include_lines": layout.include_lines_by_root,
        "systemctl_cat_strongswan_include_lines": layout.systemctl_include_lines,
        "startup_log_include_lines": layout.log_include_lines,
        "files_under_roots": swanctl_files_by_root(),
        "generated_profile_file": str(profile_config) if profile_config else "",
        "generated_profile_file_exists": bool(profile_config and profile_config.exists()),
        "generated_connection_loaded": loaded,
        "list_conns_returncode": list_conns_completed.returncode,
        "list_conns_output": list_conns_output,
        "list_sas_returncode": list_sas_completed.returncode,
        "list_sas_output": _completed_message(list_sas_completed),
        "dns_apply_report": load_dns_apply_report(profile_id) if profile_id else {},
        "dns_state_snapshot": dns_state_snapshot.to_dict() if dns_state_snapshot else {},
        "default_dns_interface": default_interface,
        "ip_route_get_1_1_1_1_returncode": default_route_completed.returncode,
        "ip_route_get_1_1_1_1_output": _completed_message(default_route_completed),
        "resolvectl_status_lo_returncode": lo_status_completed.returncode,
        "resolvectl_status_lo_output": _completed_message(lo_status_completed),
        "resolvectl_status_seeipsec0_returncode": dummy_status_completed.returncode,
        "resolvectl_status_seeipsec0_output": _completed_message(dummy_status_completed),
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
    if not shutil.which("swanctl"):
        raise HelperError("swanctl was not found. Install strongSwan swanctl packages first.")


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

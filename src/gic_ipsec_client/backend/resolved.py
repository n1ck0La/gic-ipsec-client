from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.validators import validate_uuid

FORTIGATE_ROUTE_PRESETS = (
    "192.168.4.0/24",
    "192.168.8.0/24",
    "192.168.12.0/24",
    "192.168.16.0/24",
    "192.168.20.0/24",
    "192.168.24.0/24",
    "192.168.52.0/24",
    "192.168.64.0/24",
    "192.168.68.0/24",
    "192.168.88.0/24",
    "192.168.100.0/24",
    "192.168.104.0/24",
    "192.168.108.0/24",
    "192.168.254.0/24",
)
LOOPBACK_DNS_INTERFACE = "lo"
DUMMY_DNS_INTERFACE = "seeipsec0"
RESOLVED_STATE_ROOT = Path("/run/gic-ipsec-client/resolved")
RunCommand = Callable[[commands.CommandSpec], object]
INTERNAL_DNS_TEST_HOSTS = {
    "see-radars.com": "nextcloud.see-radars.com",
    "seetech.local": "srv-dc-01.seetech.local",
}
EXPECTED_INTERNAL_DNS_RESULTS = {
    "nextcloud.see-radars.com": "192.168.88.65",
    "srv-dc-01.seetech.local": "192.168.88.203",
}


@dataclass(frozen=True, slots=True)
class ResolvedDnsPlan:
    profile_id: str
    interface: str
    dns_servers: tuple[str, ...]
    search_domains: tuple[str, ...]
    split_tunnel_enabled: bool
    snapshot: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "interface": self.interface,
            "dns_servers": list(self.dns_servers),
            "search_domains": list(self.search_domains),
            "split_tunnel_enabled": self.split_tunnel_enabled,
            "snapshot": self.snapshot,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ResolvedDnsPlan:
        return cls(
            profile_id=str(data.get("profile_id", "")),
            interface=str(data.get("interface", "")),
            dns_servers=tuple(str(item) for item in data.get("dns_servers", []) or []),
            search_domains=tuple(str(item) for item in data.get("search_domains", []) or []),
            split_tunnel_enabled=bool(data.get("split_tunnel_enabled", True)),
            snapshot=str(data.get("snapshot", "")),
        )


def resolvectl_status() -> commands.CommandSpec:
    return commands.CommandSpec(("resolvectl", "status"), timeout_seconds=15)


def resolvectl_status_interface(interface: str) -> commands.CommandSpec:
    return commands.CommandSpec(("resolvectl", "status", interface), timeout_seconds=15)


def systemd_resolved_is_active() -> commands.CommandSpec:
    return commands.CommandSpec(("systemctl", "is-active", "systemd-resolved"), timeout_seconds=10)


def ip_route_get(address: str) -> commands.CommandSpec:
    return commands.CommandSpec(("ip", "route", "get", address), timeout_seconds=10)


def ip_xfrm_policy() -> commands.CommandSpec:
    return commands.CommandSpec(("ip", "xfrm", "policy"), timeout_seconds=10)


def ip_xfrm_state() -> commands.CommandSpec:
    return commands.CommandSpec(("ip", "xfrm", "state"), timeout_seconds=10)


def resolvectl_query(name: str) -> commands.CommandSpec:
    return commands.CommandSpec(("resolvectl", "query", name), timeout_seconds=15)


def resolvectl_reset_server_features() -> commands.CommandSpec:
    return commands.CommandSpec(("resolvectl", "reset-server-features"), timeout_seconds=15)


def dig_short(server: str, name: str) -> commands.CommandSpec:
    return commands.CommandSpec(("dig", f"@{server}", name, "+short"), timeout_seconds=15)


def ip_link_add_dummy(interface: str = DUMMY_DNS_INTERFACE) -> commands.CommandSpec:
    return commands.CommandSpec(
        ("ip", "link", "add", interface, "type", "dummy"),
        timeout_seconds=10,
    )


def ip_link_set_up(interface: str = DUMMY_DNS_INTERFACE) -> commands.CommandSpec:
    return commands.CommandSpec(("ip", "link", "set", interface, "up"), timeout_seconds=10)


def ip_link_show(interface: str = DUMMY_DNS_INTERFACE) -> commands.CommandSpec:
    return commands.CommandSpec(("ip", "link", "show", interface), timeout_seconds=10)


def ip_link_delete(interface: str = DUMMY_DNS_INTERFACE) -> commands.CommandSpec:
    return commands.CommandSpec(("ip", "link", "delete", interface), timeout_seconds=10)


def parse_default_interface(route_get_output: str) -> str:
    match = re.search(r"\bdev\s+(\S+)", route_get_output)
    return match.group(1) if match else ""


def internal_dns_test_names(search_domains: list[str] | tuple[str, ...]) -> list[str]:
    names: list[str] = []
    for domain in search_domains:
        clean = domain.strip().lstrip("~")
        if not clean:
            continue
        names.append(INTERNAL_DNS_TEST_HOSTS.get(clean, clean))
    return list(dict.fromkeys(names))


def build_resolvectl_apply_commands(
    *,
    interface: str,
    dns_servers: list[str] | tuple[str, ...],
    search_domains: list[str] | tuple[str, ...],
    split_tunnel_enabled: bool,
    split_default_route: str = "no",
    reset_server_features: bool = False,
) -> list[commands.CommandSpec]:
    if not interface or not dns_servers:
        return []
    specs = [
        commands.CommandSpec(
            ("resolvectl", "dns", interface, *tuple(dns_servers)),
            timeout_seconds=15,
        )
    ]
    if split_tunnel_enabled:
        domains: list[str] = []
        for domain in search_domains:
            clean = domain.strip().lstrip("~")
            if not clean:
                continue
            domains.append(f"~{clean}")
        if domains:
            specs.append(
                commands.CommandSpec(
                    ("resolvectl", "domain", interface, *tuple(domains)),
                    timeout_seconds=15,
                )
            )
        specs.append(
            commands.CommandSpec(
                ("resolvectl", "default-route", interface, split_default_route),
                timeout_seconds=15,
            )
        )
    else:
        specs.extend(
            [
                commands.CommandSpec(
                    ("resolvectl", "domain", interface, "~."),
                    timeout_seconds=15,
                ),
                commands.CommandSpec(
                    ("resolvectl", "default-route", interface, "yes"),
                    timeout_seconds=15,
                ),
            ]
        )
    specs.append(commands.CommandSpec(("resolvectl", "flush-caches"), timeout_seconds=15))
    if reset_server_features:
        specs.append(resolvectl_reset_server_features())
    return specs


def build_resolvectl_revert_commands(interface: str) -> list[commands.CommandSpec]:
    if not interface:
        return []
    return [
        commands.CommandSpec(("resolvectl", "revert", interface), timeout_seconds=15),
        commands.CommandSpec(("resolvectl", "flush-caches"), timeout_seconds=15),
    ]


def resolved_state_path(profile_id: str, *, state_root: Path = RESOLVED_STATE_ROOT) -> Path:
    validate_uuid(profile_id)
    return state_root / f"{profile_id}.json"


def save_resolved_plan(plan: ResolvedDnsPlan, *, state_root: Path = RESOLVED_STATE_ROOT) -> Path:
    path = resolved_state_path(plan.profile_id, state_root=state_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def load_resolved_plan(
    profile_id: str,
    *,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> ResolvedDnsPlan | None:
    path = resolved_state_path(profile_id, state_root=state_root)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    plan = ResolvedDnsPlan.from_dict(payload)
    if not plan.interface:
        return None
    return plan


def cleanup_resolved_plan(profile_id: str, *, state_root: Path = RESOLVED_STATE_ROOT) -> None:
    path = resolved_state_path(profile_id, state_root=state_root)
    if path.exists():
        path.unlink()


def dns_apply_report_path(profile_id: str, *, state_root: Path = RESOLVED_STATE_ROOT) -> Path:
    validate_uuid(profile_id)
    return state_root / f"{profile_id}.dns-apply.json"


def save_dns_apply_report(
    profile_id: str,
    report: dict[str, object],
    *,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> Path:
    path = dns_apply_report_path(profile_id, state_root=state_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def load_dns_apply_report(
    profile_id: str,
    *,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> dict[str, object]:
    path = dns_apply_report_path(profile_id, state_root=state_root)
    if not path.exists():
        return {"profile_id": profile_id, "dns_apply_ran": False}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {"profile_id": profile_id}


def cleanup_dns_apply_report(profile_id: str, *, state_root: Path = RESOLVED_STATE_ROOT) -> None:
    path = dns_apply_report_path(profile_id, state_root=state_root)
    if path.exists():
        path.unlink()


def apply_resolved_dns(
    *,
    profile_id: str,
    dns_servers: list[str],
    search_domains: list[str],
    split_tunnel_enabled: bool,
    run_command: RunCommand = commands.run_command,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> list[str]:
    validate_uuid(profile_id)
    report: dict[str, object] = _new_dns_apply_report(profile_id)
    if not dns_servers:
        report["notes"] = ["No DNS servers configured."]
        save_dns_apply_report(profile_id, report, state_root=state_root)
        return []
    active = run_command(systemd_resolved_is_active())
    _record_completed(report, systemd_resolved_is_active(), active, phase="precheck")
    resolved_is_active = (
        getattr(active, "returncode", 1) == 0
        and str(getattr(active, "stdout", "")).strip() == "active"
    )
    if not resolved_is_active:
        report["notes"] = ["systemd-resolved is not active."]
        save_dns_apply_report(profile_id, report, state_root=state_root)
        return []
    if split_tunnel_enabled:
        messages = _apply_split_dns_with_fallback(
            profile_id=profile_id,
            dns_servers=dns_servers,
            search_domains=search_domains,
            run_command=run_command,
            state_root=state_root,
            report=report,
        )
        save_dns_apply_report(profile_id, report, state_root=state_root)
        return messages
    else:
        route = run_command(ip_route_get("1.1.1.1"))
        _record_completed(report, ip_route_get("1.1.1.1"), route, phase="detect-interface")
        if getattr(route, "returncode", 1) != 0:
            report["errors"] = ["Could not detect default interface for DNS."]
            save_dns_apply_report(profile_id, report, state_root=state_root)
            return ["Could not detect default interface for DNS."]
        interface = parse_default_interface(str(getattr(route, "stdout", "")))
        if not interface:
            report["errors"] = ["Could not detect default interface for DNS."]
            save_dns_apply_report(profile_id, report, state_root=state_root)
            return ["Could not detect default interface for DNS."]

    messages = _apply_dns_to_interface(
        profile_id=profile_id,
        interface=interface,
        dns_servers=dns_servers,
        search_domains=search_domains,
        split_tunnel_enabled=split_tunnel_enabled,
        run_command=run_command,
        state_root=state_root,
        report=report,
    )
    save_dns_apply_report(profile_id, report, state_root=state_root)
    return messages


def revert_resolved_dns(
    profile_id: str,
    *,
    run_command: RunCommand = commands.run_command,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> list[str]:
    validate_uuid(profile_id)
    messages: list[str] = []
    previous_plan = load_resolved_plan(profile_id, state_root=state_root)
    interfaces = list(
        dict.fromkeys(
            item
            for item in (
                previous_plan.interface if previous_plan else "",
                LOOPBACK_DNS_INTERFACE,
                DUMMY_DNS_INTERFACE,
            )
            if item
        )
    )
    for interface in interfaces:
        for spec in build_resolvectl_revert_commands(interface)[:1]:
            completed = run_command(spec)
            if getattr(completed, "returncode", 1) != 0:
                messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
    show_dummy = run_command(ip_link_show(DUMMY_DNS_INTERFACE))
    if getattr(show_dummy, "returncode", 1) == 0:
        delete_spec = ip_link_delete(DUMMY_DNS_INTERFACE)
        delete_dummy = run_command(delete_spec)
        if getattr(delete_dummy, "returncode", 1) != 0:
            messages.append(
                _completed_message(delete_dummy) or f"{' '.join(delete_spec.args)} failed."
            )
    for spec in [commands.CommandSpec(("resolvectl", "flush-caches"), timeout_seconds=15)]:
        completed = run_command(spec)
        if getattr(completed, "returncode", 1) != 0:
            messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
    reset_spec = resolvectl_reset_server_features()
    reset_completed = run_command(reset_spec)
    if getattr(reset_completed, "returncode", 1) != 0:
        messages.append(
            _completed_message(reset_completed) or f"{' '.join(reset_spec.args)} failed."
        )
    if not messages:
        cleanup_resolved_plan(profile_id, state_root=state_root)
    return messages


def summarize_xfrm_state(output: str) -> str:
    kept: list[str] = []
    redacted_prefixes = ("auth", "auth-trunc", "enc", "aead", "comp")
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.split(maxsplit=1)[0] in redacted_prefixes:
            continue
        kept.append(raw_line)
    return "\n".join(kept)


def _completed_message(completed: object) -> str:
    stdout = str(getattr(completed, "stdout", "") or "")
    stderr = str(getattr(completed, "stderr", "") or "")
    return (stdout + stderr).strip()


def _new_dns_apply_report(profile_id: str) -> dict[str, object]:
    return {
        "profile_id": profile_id,
        "dns_apply_ran": False,
        "fallback_used": False,
        "selected_interface": "",
        "verified_interface": "",
        "success": False,
        "commands": [],
        "verification": [],
        "errors": [],
        "notes": [],
    }


def _record_completed(
    report: dict[str, object],
    spec: commands.CommandSpec,
    completed: object,
    *,
    phase: str,
) -> None:
    key = "verification" if phase.startswith("verify") else "commands"
    entries = report.setdefault(key, [])
    if isinstance(entries, list):
        entries.append(
            {
                "phase": phase,
                "args": list(spec.args),
                "returncode": int(getattr(completed, "returncode", -1)),
                "stdout": str(getattr(completed, "stdout", "") or ""),
                "stderr": str(getattr(completed, "stderr", "") or ""),
            }
        )


def _record_failed_execution(
    report: dict[str, object],
    spec: commands.CommandSpec,
    exc: OSError | TimeoutError,
    *,
    phase: str,
) -> None:
    _record_completed(
        report,
        spec,
        _SyntheticCompleted(returncode=127, stderr=str(exc)),
        phase=phase,
    )


def _apply_dns_to_interface(
    *,
    profile_id: str,
    interface: str,
    dns_servers: list[str],
    search_domains: list[str],
    split_tunnel_enabled: bool,
    run_command: RunCommand,
    state_root: Path,
    report: dict[str, object],
    split_default_route: str = "no",
    reset_server_features: bool = False,
) -> list[str]:
    snapshot_spec = resolvectl_status_interface(interface)
    snapshot_result = run_command(snapshot_spec)
    _record_completed(report, snapshot_spec, snapshot_result, phase="snapshot")
    snapshot = _completed_message(snapshot_result)
    plan = ResolvedDnsPlan(
        profile_id=profile_id,
        interface=interface,
        dns_servers=tuple(dns_servers),
        search_domains=tuple(search_domains),
        split_tunnel_enabled=split_tunnel_enabled,
        snapshot=snapshot,
    )
    save_resolved_plan(plan, state_root=state_root)

    messages: list[str] = []
    apply_specs = build_resolvectl_apply_commands(
        interface=interface,
        dns_servers=dns_servers,
        search_domains=search_domains,
        split_tunnel_enabled=split_tunnel_enabled,
        split_default_route=split_default_route,
        reset_server_features=reset_server_features,
    )
    if apply_specs:
        report["dns_apply_ran"] = True
        report["selected_interface"] = interface
    for spec in apply_specs:
        completed = run_command(spec)
        _record_completed(report, spec, completed, phase="apply")
        if getattr(completed, "returncode", 1) != 0:
            messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
    return messages


@dataclass(frozen=True, slots=True)
class _SyntheticCompleted:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


def _run_verification_command(
    spec: commands.CommandSpec,
    *,
    run_command: RunCommand,
    report: dict[str, object],
    phase: str,
) -> object:
    try:
        completed = run_command(spec)
    except (OSError, TimeoutError) as exc:
        _record_failed_execution(report, spec, exc, phase=phase)
        return _SyntheticCompleted(returncode=127, stderr=str(exc))
    _record_completed(report, spec, completed, phase=phase)
    return completed


def _query_links(output: str) -> list[str]:
    links = re.findall(r"\bLink\s+\d+\s+\(([^)]+)\)", output)
    links.extend(re.findall(r"--\s*link:\s*([^\s]+)", output, flags=re.IGNORECASE))
    return links


def _query_confirms_dns_path(*, name: str, output: str, selected_interface: str) -> bool:
    expected_ip = EXPECTED_INTERNAL_DNS_RESULTS.get(name)
    if expected_ip and re.search(rf"(?<![\d.]){re.escape(expected_ip)}(?![\d.])", output):
        return True
    if not output.strip():
        return False
    links = _query_links(output)
    if not links:
        return True
    return all(link == selected_interface for link in links)


def _verify_dns_interface(
    *,
    interface: str,
    dns_servers: list[str],
    search_domains: list[str],
    run_command: RunCommand,
    report: dict[str, object],
) -> bool:
    status_spec = resolvectl_status_interface(interface)
    _run_verification_command(
        status_spec,
        run_command=run_command,
        report=report,
        phase=f"verify-status-{interface}",
    )
    names = internal_dns_test_names(search_domains)
    confirmed = False
    for name in names:
        for server in dns_servers:
            dig_direct_spec = dig_short(server, name)
            _run_verification_command(
                dig_direct_spec,
                run_command=run_command,
                report=report,
                phase=f"verify-dig-direct-{interface}",
            )
        dig_stub_spec = dig_short("127.0.0.53", name)
        _run_verification_command(
            dig_stub_spec,
            run_command=run_command,
            report=report,
            phase=f"verify-dig-stub-{interface}",
        )
        query_spec = resolvectl_query(name)
        query = _run_verification_command(
            query_spec,
            run_command=run_command,
            report=report,
            phase=f"verify-query-{interface}",
        )
        query_text = _completed_message(query)
        if getattr(query, "returncode", 1) == 0 and _query_confirms_dns_path(
            name=name,
            output=query_text,
            selected_interface=interface,
        ):
            confirmed = True
    return confirmed


def _apply_split_dns_with_fallback(
    *,
    profile_id: str,
    dns_servers: list[str],
    search_domains: list[str],
    run_command: RunCommand,
    state_root: Path,
    report: dict[str, object],
) -> list[str]:
    lo_messages = _apply_dns_to_interface(
        profile_id=profile_id,
        interface=LOOPBACK_DNS_INTERFACE,
        dns_servers=dns_servers,
        search_domains=search_domains,
        split_tunnel_enabled=True,
        run_command=run_command,
        state_root=state_root,
        report=report,
    )
    if _verify_dns_interface(
        interface=LOOPBACK_DNS_INTERFACE,
        dns_servers=dns_servers,
        search_domains=search_domains,
        run_command=run_command,
        report=report,
    ):
        report["success"] = True
        report["verified_interface"] = LOOPBACK_DNS_INTERFACE
        return lo_messages

    report["fallback_used"] = True
    route_spec = ip_route_get("1.1.1.1")
    route = run_command(route_spec)
    _record_completed(report, route_spec, route, phase="fallback-detect-interface")
    if getattr(route, "returncode", 1) != 0:
        message = "Could not detect default interface for DNS fallback."
        errors = report.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(message)
        return [*lo_messages, message]
    fallback_interface = parse_default_interface(str(getattr(route, "stdout", "")))
    if not fallback_interface:
        message = "Could not detect default interface for DNS fallback."
        errors = report.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(message)
        return [*lo_messages, message]

    notes = report.setdefault("notes", [])
    if isinstance(notes, list):
        notes.append(
            f"lo DNS did not verify; applying split DNS to {fallback_interface}."
        )
    physical_messages = _apply_dns_to_interface(
        profile_id=profile_id,
        interface=fallback_interface,
        dns_servers=dns_servers,
        search_domains=search_domains,
        split_tunnel_enabled=True,
        run_command=run_command,
        state_root=state_root,
        report=report,
        split_default_route="yes",
        reset_server_features=True,
    )
    if _verify_dns_interface(
        interface=fallback_interface,
        dns_servers=dns_servers,
        search_domains=search_domains,
        run_command=run_command,
        report=report,
    ):
        report["success"] = True
        report["verified_interface"] = fallback_interface
        return physical_messages
    else:
        message = f"VPN DNS verification failed for lo and {fallback_interface}."
        errors = report.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(message)
        return [*lo_messages, *physical_messages, message]

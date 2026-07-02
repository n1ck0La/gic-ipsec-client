from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.validators import validate_uuid

LOOPBACK_DNS_INTERFACE = "lo"
DUMMY_DNS_INTERFACE = "seeipsec0"
RESOLVED_STATE_ROOT = Path("/run/see-ipsec-client")
RunCommand = Callable[[commands.CommandSpec], object]


def _optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "+defaultroute"}:
        return True
    if text in {"0", "false", "no", "-defaultroute"}:
        return False
    return None


@dataclass(frozen=True, slots=True)
class ResolvedDnsPlan:
    profile_id: str
    interface: str
    dns_servers: tuple[str, ...]
    search_domains: tuple[str, ...]
    split_tunnel_enabled: bool
    snapshot: str = ""
    default_route: bool | None = None
    dhcp_managed: bool = False
    fallback_dns_servers: tuple[str, ...] = ()
    vpn_dns_servers: tuple[str, ...] = ()
    vpn_search_domains: tuple[str, ...] = ()
    active_connection: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "interface": self.interface,
            "dns_servers": list(self.dns_servers),
            "domains": list(self.search_domains),
            "search_domains": list(self.search_domains),
            "split_tunnel_enabled": self.split_tunnel_enabled,
            "default_route": self.default_route,
            "dhcp_managed": self.dhcp_managed,
            "fallback_dns_servers": list(self.fallback_dns_servers),
            "vpn_dns_servers": list(self.vpn_dns_servers),
            "vpn_search_domains": list(self.vpn_search_domains),
            "active_connection": self.active_connection,
            "raw_status": self.snapshot,
            "snapshot": self.snapshot,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ResolvedDnsPlan:
        raw_domains = data.get("domains", data.get("search_domains", [])) or []
        return cls(
            profile_id=str(data.get("profile_id", "")),
            interface=str(data.get("interface", "")),
            dns_servers=tuple(str(item) for item in data.get("dns_servers", []) or []),
            search_domains=tuple(str(item) for item in raw_domains),
            split_tunnel_enabled=bool(data.get("split_tunnel_enabled", True)),
            snapshot=str(data.get("raw_status", data.get("snapshot", ""))),
            default_route=_optional_bool(data.get("default_route")),
            dhcp_managed=bool(data.get("dhcp_managed", False)),
            fallback_dns_servers=tuple(
                str(item) for item in data.get("fallback_dns_servers", []) or []
            ),
            vpn_dns_servers=tuple(str(item) for item in data.get("vpn_dns_servers", []) or []),
            vpn_search_domains=tuple(
                str(item) for item in data.get("vpn_search_domains", []) or []
            ),
            active_connection=str(data.get("active_connection", "")),
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


def resolvectl_dns(
    interface: str,
    dns_servers: list[str] | tuple[str, ...],
) -> commands.CommandSpec:
    return commands.CommandSpec(
        ("resolvectl", "dns", interface, *tuple(dns_servers)),
        timeout_seconds=15,
    )


def resolvectl_domain(
    interface: str,
    domains: list[str] | tuple[str, ...],
) -> commands.CommandSpec:
    args = ("resolvectl", "domain", interface, *tuple(domains or ("",)))
    return commands.CommandSpec(args, timeout_seconds=15)


def resolvectl_default_route(interface: str, enabled: bool) -> commands.CommandSpec:
    return commands.CommandSpec(
        ("resolvectl", "default-route", interface, "yes" if enabled else "no"),
        timeout_seconds=15,
    )


def dig_short(server: str, name: str) -> commands.CommandSpec:
    return commands.CommandSpec(("dig", f"@{server}", name, "+short"), timeout_seconds=15)


def nmcli_device_show(interface: str) -> commands.CommandSpec:
    return commands.CommandSpec(
        (
            "nmcli",
            "-t",
            "-f",
            "GENERAL.CONNECTION,IP4.DNS,IP4.DOMAIN,IP4.SEARCHES",
            "device",
            "show",
            interface,
        ),
        timeout_seconds=15,
    )


def nmcli_device_reapply(interface: str) -> commands.CommandSpec:
    return commands.CommandSpec(("nmcli", "dev", "reapply", interface), timeout_seconds=30)


def nmcli_connection_down(connection_name: str) -> commands.CommandSpec:
    return commands.CommandSpec(("nmcli", "con", "down", connection_name), timeout_seconds=45)


def nmcli_connection_up(connection_name: str) -> commands.CommandSpec:
    return commands.CommandSpec(("nmcli", "con", "up", connection_name), timeout_seconds=45)


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


def is_ssh_session() -> bool:
    return any(os.environ.get(name) for name in ("SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"))


def internal_dns_test_names(
    search_domains: list[str] | tuple[str, ...],
    test_names: list[str] | tuple[str, ...] = (),
) -> list[str]:
    names: list[str] = []
    for name in test_names:
        clean_name = name.strip()
        if clean_name:
            names.append(clean_name)
    for domain in search_domains:
        clean = domain.strip().lstrip("~")
        if not clean:
            continue
        names.append(clean)
    return list(dict.fromkeys(names))


def parse_resolvectl_link_status(output: str) -> dict[str, object]:
    dns_servers: list[str] = []
    domains: list[str] = []
    default_route: bool | None = None
    continuation: str | None = None

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continuation = None
            continue
        if stripped.startswith("DNS Servers:"):
            dns_servers.extend(stripped.removeprefix("DNS Servers:").split())
            continuation = "dns"
            continue
        if stripped.startswith("DNS Domain:"):
            domains.extend(stripped.removeprefix("DNS Domain:").split())
            continuation = "domain"
            continue
        if stripped.startswith("DefaultRoute setting:"):
            default_route = _optional_bool(stripped.removeprefix("DefaultRoute setting:"))
            continuation = None
            continue
        if stripped.startswith("Protocols:"):
            if "+DefaultRoute" in stripped:
                default_route = True
            elif "-DefaultRoute" in stripped:
                default_route = False
            continuation = None
            continue
        if ":" not in stripped and raw_line[:1].isspace():
            if continuation == "dns":
                dns_servers.extend(stripped.split())
            elif continuation == "domain":
                domains.extend(stripped.split())
        else:
            continuation = None

    return {
        "dns_servers": list(dict.fromkeys(dns_servers)),
        "domains": list(dict.fromkeys(domains)),
        "default_route": default_route,
    }


def parse_nmcli_device_snapshot(output: str) -> dict[str, object]:
    active_connection = ""
    fallback_dns: list[str] = []
    domains: list[str] = []
    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        value = value.replace(r"\:", ":").strip()
        if key == "GENERAL.CONNECTION":
            active_connection = value
        elif key.startswith("IP4.DNS") and value:
            fallback_dns.append(value)
        elif key.startswith(("IP4.DOMAIN", "IP4.SEARCHES")) and value:
            domains.extend(value.split())
    return {
        "active_connection": active_connection,
        "fallback_dns_servers": list(dict.fromkeys(fallback_dns)),
        "fallback_domains": list(dict.fromkeys(domains)),
    }


def build_resolvectl_restore_commands(plan: ResolvedDnsPlan) -> list[commands.CommandSpec]:
    if not plan.interface or not plan.dns_servers:
        return []
    default_route = True if plan.default_route is None else plan.default_route
    return [
        resolvectl_dns(plan.interface, plan.dns_servers),
        resolvectl_domain(plan.interface, plan.search_domains),
        resolvectl_default_route(plan.interface, default_route),
        commands.CommandSpec(("resolvectl", "flush-caches"), timeout_seconds=15),
        resolvectl_reset_server_features(),
    ]


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
    specs = [resolvectl_dns(interface, dns_servers)]
    if split_tunnel_enabled:
        domains: list[str] = []
        for domain in search_domains:
            clean = domain.strip().lstrip("~")
            if not clean:
                continue
            domains.append(f"~{clean}")
        if domains:
            specs.append(resolvectl_domain(interface, domains))
        specs.append(resolvectl_default_route(interface, split_default_route == "yes"))
    else:
        specs.extend(
            [
                resolvectl_domain(interface, ("~.",)),
                resolvectl_default_route(interface, True),
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
    return state_root / f"dns-state-{profile_id}.json"


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
    return state_root / f"dns-apply-{profile_id}.json"


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
    test_names: list[str] | None = None,
    linux_strategy: str = "auto",
    preferred_interface: str = "auto",
    run_command: RunCommand = commands.run_command,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> list[str]:
    validate_uuid(profile_id)
    report: dict[str, object] = _new_dns_apply_report(profile_id)
    if linux_strategy == "disabled":
        report["notes"] = ["Profile DNS strategy is disabled."]
        save_dns_apply_report(profile_id, report, state_root=state_root)
        return []
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
            test_names=test_names or [],
            linux_strategy=linux_strategy,
            preferred_interface=preferred_interface,
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
        test_names=test_names or [],
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
    cleanup_on_success: bool = True,
) -> list[str]:
    validate_uuid(profile_id)
    messages: list[str] = []
    previous_plan = load_resolved_plan(profile_id, state_root=state_root)
    report = load_dns_apply_report(profile_id, state_root=state_root)
    restored_physical_interface = False
    if previous_plan and previous_plan.interface not in {
        LOOPBACK_DNS_INTERFACE,
        DUMMY_DNS_INTERFACE,
    }:
        restored_physical_interface = True
        messages.extend(
            _restore_physical_dns(
                previous_plan,
                run_command=run_command,
                report=report,
            )
        )

    cleanup_interfaces = list(
        dict.fromkeys(
            item
            for item in (
                previous_plan.interface
                if previous_plan
                and previous_plan.interface in {LOOPBACK_DNS_INTERFACE, DUMMY_DNS_INTERFACE}
                else "",
                LOOPBACK_DNS_INTERFACE,
                DUMMY_DNS_INTERFACE,
            )
            if item
        )
    )
    for interface in cleanup_interfaces:
        for spec in build_resolvectl_revert_commands(interface)[:1]:
            completed = run_command(spec)
            _record_completed(report, spec, completed, phase="rollback")
            if getattr(completed, "returncode", 1) != 0:
                _record_warning(
                    report,
                    _completed_message(completed) or f"{' '.join(spec.args)} failed.",
                )
    show_dummy = run_command(ip_link_show(DUMMY_DNS_INTERFACE))
    _record_completed(report, ip_link_show(DUMMY_DNS_INTERFACE), show_dummy, phase="rollback")
    if getattr(show_dummy, "returncode", 1) == 0:
        delete_spec = ip_link_delete(DUMMY_DNS_INTERFACE)
        delete_dummy = run_command(delete_spec)
        _record_completed(report, delete_spec, delete_dummy, phase="rollback")
        if getattr(delete_dummy, "returncode", 1) != 0:
            _record_warning(
                report,
                _completed_message(delete_dummy) or f"{' '.join(delete_spec.args)} failed.",
            )
    else:
        _record_warning(report, "seeipsec0 not present; nothing to clean up.")
    for spec in [commands.CommandSpec(("resolvectl", "flush-caches"), timeout_seconds=15)]:
        completed = run_command(spec)
        _record_completed(report, spec, completed, phase="rollback")
        if getattr(completed, "returncode", 1) != 0:
            _record_warning(
                report,
                _completed_message(completed) or f"{' '.join(spec.args)} failed.",
            )
    reset_spec = resolvectl_reset_server_features()
    reset_completed = run_command(reset_spec)
    _record_completed(report, reset_spec, reset_completed, phase="rollback")
    if getattr(reset_completed, "returncode", 1) != 0:
        _record_warning(
            report,
            _completed_message(reset_completed) or f"{' '.join(reset_spec.args)} failed.",
        )
    if restored_physical_interface:
        notes = report.setdefault("notes", [])
        if isinstance(notes, list):
            notes.append("Restored DNS before terminating the IKE_SA.")
    save_dns_apply_report(profile_id, report, state_root=state_root)
    if not messages and cleanup_on_success:
        cleanup_resolved_plan(profile_id, state_root=state_root)
    return messages


def flush_resolved_dns_caches(
    *,
    run_command: RunCommand = commands.run_command,
) -> list[str]:
    messages: list[str] = []
    for spec in (
        commands.CommandSpec(("resolvectl", "flush-caches"), timeout_seconds=15),
        resolvectl_reset_server_features(),
    ):
        completed = _run_optional_command(spec, run_command=run_command)
        if getattr(completed, "returncode", 1) != 0:
            messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
    return messages


def verify_resolved_dns_after_disconnect(
    profile_id: str,
    *,
    run_command: RunCommand = commands.run_command,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> list[str]:
    validate_uuid(profile_id)
    plan = load_resolved_plan(profile_id, state_root=state_root)
    if plan is None or not plan.interface:
        return []
    report = load_dns_apply_report(profile_id, state_root=state_root)
    messages: list[str] = []

    status_spec = resolvectl_status_interface(plan.interface)
    status = _run_and_record(
        status_spec,
        run_command=run_command,
        report=report,
        phase="verify-disconnect",
    )
    status_text = _completed_message(status)
    for vpn_server in plan.vpn_dns_servers:
        if vpn_server and vpn_server not in plan.dns_servers and vpn_server in status_text:
            messages.append(
                f"VPN DNS server {vpn_server} is still configured on {plan.interface}."
            )

    for spec in (
        resolvectl_query("i.ua"),
        dig_short("127.0.0.53", "i.ua"),
        resolvectl_query("google.com"),
    ):
        completed = _run_and_record(
            spec,
            run_command=run_command,
            report=report,
            phase="verify-disconnect",
        )
        if getattr(completed, "returncode", 1) != 0 or not _completed_message(completed):
            messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
    save_dns_apply_report(profile_id, report, state_root=state_root)
    if not messages:
        cleanup_resolved_plan(profile_id, state_root=state_root)
    return messages


def reconnect_network_interface(
    profile_id: str,
    *,
    run_command: RunCommand = commands.run_command,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> list[str]:
    validate_uuid(profile_id)
    if is_ssh_session():
        return ["Refusing to reconnect the network interface from an SSH session."]
    plan = load_resolved_plan(profile_id, state_root=state_root)
    if plan is None or not plan.active_connection:
        return ["No saved active NetworkManager connection is available for reconnect."]
    messages: list[str] = []
    for spec in (
        nmcli_connection_down(plan.active_connection),
        nmcli_connection_up(plan.active_connection),
    ):
        completed = _run_optional_command(spec, run_command=run_command)
        if getattr(completed, "returncode", 1) != 0:
            messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
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
        "warnings": [],
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


def _record_warning(report: dict[str, object], message: str) -> None:
    warnings = report.setdefault("warnings", [])
    if isinstance(warnings, list) and message:
        warnings.append(message)


def _run_and_record(
    spec: commands.CommandSpec,
    *,
    run_command: RunCommand,
    report: dict[str, object],
    phase: str,
) -> object:
    completed = _run_optional_command(spec, run_command=run_command)
    _record_completed(report, spec, completed, phase=phase)
    return completed


def _restore_physical_dns(
    plan: ResolvedDnsPlan,
    *,
    run_command: RunCommand,
    report: dict[str, object],
) -> list[str]:
    if plan.dhcp_managed and not plan.dns_servers:
        reapply = _run_and_record(
            nmcli_device_reapply(plan.interface),
            run_command=run_command,
            report=report,
            phase="rollback",
        )
        if getattr(reapply, "returncode", 1) == 0:
            return []
        return [
            _completed_message(reapply)
            or f"{' '.join(nmcli_device_reapply(plan.interface).args)} failed."
        ]

    restore_messages: list[str] = []
    for spec in build_resolvectl_restore_commands(plan):
        completed = _run_and_record(
            spec,
            run_command=run_command,
            report=report,
            phase="rollback",
        )
        if getattr(completed, "returncode", 1) != 0:
            if spec.args == resolvectl_reset_server_features().args:
                _record_warning(
                    report,
                    _completed_message(completed) or f"{' '.join(spec.args)} failed.",
                )
                continue
            restore_messages.append(
                _completed_message(completed) or f"{' '.join(spec.args)} failed."
            )
    if not restore_messages:
        return []

    reapply_spec = nmcli_device_reapply(plan.interface)
    reapply = _run_and_record(
        reapply_spec,
        run_command=run_command,
        report=report,
        phase="rollback-fallback",
    )
    if getattr(reapply, "returncode", 1) == 0:
        notes = report.setdefault("notes", [])
        if isinstance(notes, list):
            notes.append(f"Explicit DNS restore failed; nmcli reapplied {plan.interface}.")
        return []

    message = _completed_message(reapply) or f"{' '.join(reapply_spec.args)} failed."
    if not is_ssh_session() and plan.active_connection:
        message = (
            f"{message}\nReconnect network interface is available for "
            f"{plan.interface} ({plan.active_connection})."
        )
    return [*restore_messages, message]


def _run_optional_command(
    spec: commands.CommandSpec,
    *,
    run_command: RunCommand,
) -> object:
    try:
        return run_command(spec)
    except (OSError, TimeoutError) as exc:
        return _SyntheticCompleted(returncode=127, stderr=str(exc))


def _snapshot_resolved_dns_plan(
    *,
    profile_id: str,
    interface: str,
    vpn_dns_servers: list[str],
    vpn_search_domains: list[str],
    split_tunnel_enabled: bool,
    run_command: RunCommand,
    report: dict[str, object],
) -> ResolvedDnsPlan:
    snapshot_spec = resolvectl_status_interface(interface)
    snapshot_result = _run_optional_command(snapshot_spec, run_command=run_command)
    _record_completed(report, snapshot_spec, snapshot_result, phase="snapshot")
    raw_status = _completed_message(snapshot_result)
    parsed_status = parse_resolvectl_link_status(raw_status)

    nmcli_spec = nmcli_device_show(interface)
    nmcli_result = _run_optional_command(nmcli_spec, run_command=run_command)
    _record_completed(report, nmcli_spec, nmcli_result, phase="snapshot")
    nmcli_snapshot = parse_nmcli_device_snapshot(_completed_message(nmcli_result))

    dns_servers = tuple(str(item) for item in parsed_status["dns_servers"])
    fallback_dns_servers = tuple(str(item) for item in nmcli_snapshot["fallback_dns_servers"])
    if not dns_servers and fallback_dns_servers:
        dns_servers = fallback_dns_servers
    domains = tuple(str(item) for item in parsed_status["domains"])
    if not domains:
        domains = tuple(str(item) for item in nmcli_snapshot["fallback_domains"])
    return ResolvedDnsPlan(
        profile_id=profile_id,
        interface=interface,
        dns_servers=dns_servers,
        search_domains=domains,
        split_tunnel_enabled=split_tunnel_enabled,
        snapshot=raw_status,
        default_route=_optional_bool(parsed_status["default_route"]),
        dhcp_managed=not bool(dns_servers),
        fallback_dns_servers=fallback_dns_servers,
        vpn_dns_servers=tuple(vpn_dns_servers),
        vpn_search_domains=tuple(vpn_search_domains),
        active_connection=str(nmcli_snapshot["active_connection"]),
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
    plan = _snapshot_resolved_dns_plan(
        profile_id=profile_id,
        interface=interface,
        vpn_dns_servers=dns_servers,
        vpn_search_domains=search_domains,
        split_tunnel_enabled=split_tunnel_enabled,
        run_command=run_command,
        report=report,
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


def _answer_tokens(output: str) -> set[str]:
    tokens: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("--") or " " in line:
            continue
        tokens.add(line.rstrip("."))
    return tokens


def _query_confirms_dns_path(
    *,
    output: str,
    selected_interface: str,
    direct_answers: set[str],
) -> bool:
    links = _query_links(output)
    if links and not all(link == selected_interface for link in links):
        return False
    if direct_answers and direct_answers & _answer_tokens(output):
        return True
    if not output.strip():
        return False
    if not links:
        return True
    return True


def _verify_dns_interface(
    *,
    interface: str,
    dns_servers: list[str],
    search_domains: list[str],
    test_names: list[str],
    run_command: RunCommand,
    report: dict[str, object],
) -> bool:
    status_spec = resolvectl_status_interface(interface)
    status = _run_verification_command(
        status_spec,
        run_command=run_command,
        report=report,
        phase=f"verify-status-{interface}",
    )
    names = internal_dns_test_names(search_domains, test_names)
    if not names:
        status_text = _completed_message(status)
        return all(server in status_text for server in dns_servers)
    confirmed = False
    for name in names:
        direct_answers: set[str] = set()
        for server in dns_servers:
            dig_direct_spec = dig_short(server, name)
            direct = _run_verification_command(
                dig_direct_spec,
                run_command=run_command,
                report=report,
                phase=f"verify-dig-direct-{interface}",
            )
            if getattr(direct, "returncode", 1) == 0:
                direct_answers.update(_answer_tokens(_completed_message(direct)))
        dig_stub_spec = dig_short("127.0.0.53", name)
        stub = _run_verification_command(
            dig_stub_spec,
            run_command=run_command,
            report=report,
            phase=f"verify-dig-stub-{interface}",
        )
        stub_answers = (
            _answer_tokens(_completed_message(stub))
            if getattr(stub, "returncode", 1) == 0
            else set()
        )
        query_spec = resolvectl_query(name)
        query = _run_verification_command(
            query_spec,
            run_command=run_command,
            report=report,
            phase=f"verify-query-{interface}",
        )
        query_text = _completed_message(query)
        query_returncode = getattr(query, "returncode", 1)
        query_links = _query_links(query_text)
        query_links_ok = not query_links or all(link == interface for link in query_links)
        if (
            query_returncode == 0
            and query_links_ok
            and direct_answers
            and stub_answers
            and direct_answers & stub_answers
        ):
            confirmed = True
            continue
        if query_returncode == 0 and _query_confirms_dns_path(
            output=query_text,
            selected_interface=interface,
            direct_answers=direct_answers,
        ):
            confirmed = True
    return confirmed


def _apply_split_dns_with_fallback(
    *,
    profile_id: str,
    dns_servers: list[str],
    search_domains: list[str],
    test_names: list[str],
    linux_strategy: str,
    preferred_interface: str,
    run_command: RunCommand,
    state_root: Path,
    report: dict[str, object],
) -> list[str]:
    if linux_strategy in {"auto", "resolved-lo"}:
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
            test_names=test_names,
            run_command=run_command,
            report=report,
        ):
            report["success"] = True
            report["verified_interface"] = LOOPBACK_DNS_INTERFACE
            return lo_messages
        if linux_strategy == "resolved-lo":
            message = "VPN DNS verification failed for lo."
            errors = report.setdefault("errors", [])
            if isinstance(errors, list):
                errors.append(message)
            return [*lo_messages, message]
    else:
        lo_messages = []

    if linux_strategy == "networkmanager":
        message = "NetworkManager DNS strategy is not implemented yet."
        errors = report.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(message)
        return [*lo_messages, message]

    fallback_interface = ""
    if preferred_interface and preferred_interface != "auto":
        fallback_interface = preferred_interface
    else:
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

    if fallback_interface == LOOPBACK_DNS_INTERFACE:
        message = "Default DNS fallback interface resolved to loopback."
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
        test_names=test_names,
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

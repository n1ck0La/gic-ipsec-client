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
RESOLVED_STATE_ROOT = Path("/run/gic-ipsec-client/resolved")
RunCommand = Callable[[commands.CommandSpec], object]


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


def parse_default_interface(route_get_output: str) -> str:
    match = re.search(r"\bdev\s+(\S+)", route_get_output)
    return match.group(1) if match else ""


def build_resolvectl_apply_commands(
    *,
    interface: str,
    dns_servers: list[str] | tuple[str, ...],
    search_domains: list[str] | tuple[str, ...],
    split_tunnel_enabled: bool,
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
                ("resolvectl", "default-route", interface, "no"),
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
    if not dns_servers:
        return []
    active = run_command(systemd_resolved_is_active())
    resolved_is_active = (
        getattr(active, "returncode", 1) == 0
        and str(getattr(active, "stdout", "")).strip() == "active"
    )
    if not resolved_is_active:
        return []
    if split_tunnel_enabled:
        interface = LOOPBACK_DNS_INTERFACE
    else:
        route = run_command(ip_route_get("1.1.1.1"))
        if getattr(route, "returncode", 1) != 0:
            return ["Could not detect default interface for DNS."]
        interface = parse_default_interface(str(getattr(route, "stdout", "")))
        if not interface:
            return ["Could not detect default interface for DNS."]

    snapshot_result = run_command(resolvectl_status_interface(interface))
    snapshot = (
        str(getattr(snapshot_result, "stdout", "") or "")
        + str(getattr(snapshot_result, "stderr", "") or "")
    ).strip()
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
    for spec in build_resolvectl_apply_commands(
        interface=interface,
        dns_servers=dns_servers,
        search_domains=search_domains,
        split_tunnel_enabled=split_tunnel_enabled,
    ):
        completed = run_command(spec)
        if getattr(completed, "returncode", 1) != 0:
            messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
    return messages


def revert_resolved_dns(
    profile_id: str,
    *,
    run_command: RunCommand = commands.run_command,
    state_root: Path = RESOLVED_STATE_ROOT,
) -> list[str]:
    plan = load_resolved_plan(profile_id, state_root=state_root)
    if plan is None:
        return []
    messages: list[str] = []
    for spec in build_resolvectl_revert_commands(plan.interface):
        completed = run_command(spec)
        if getattr(completed, "returncode", 1) != 0:
            messages.append(_completed_message(completed) or f"{' '.join(spec.args)} failed.")
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

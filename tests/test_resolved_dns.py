from __future__ import annotations

from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.resolved import (
    ResolvedDnsPlan,
    apply_resolved_dns,
    build_resolvectl_apply_commands,
    revert_resolved_dns,
    save_resolved_plan,
)


class Completed:
    stdout = ""
    stderr = ""
    returncode = 0


def test_fedora_split_dns_uses_lo_route_only_domains() -> None:
    specs = build_resolvectl_apply_commands(
        interface="lo",
        dns_servers=["192.168.88.203"],
        search_domains=["see-radars.com", "seetech.local"],
        split_tunnel_enabled=True,
    )

    assert [spec.args for spec in specs] == [
        ("resolvectl", "dns", "lo", "192.168.88.203"),
        ("resolvectl", "domain", "lo", "~see-radars.com", "~seetech.local"),
        ("resolvectl", "default-route", "lo", "no"),
        ("resolvectl", "flush-caches"),
    ]


def test_split_dns_apply_does_not_replace_physical_interface(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []

    class ActiveCompleted:
        stdout = "active\n"
        stderr = ""
        returncode = 0

    class EmptyCompleted:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(spec: commands.CommandSpec) -> object:
        calls.append(spec.args)
        if spec.args == ("systemctl", "is-active", "systemd-resolved"):
            return ActiveCompleted()
        return EmptyCompleted()

    errors = apply_resolved_dns(
        profile_id=profile_id,
        dns_servers=["192.168.88.203"],
        search_domains=["see-radars.com", "seetech.local"],
        split_tunnel_enabled=True,
        run_command=fake_run,
        state_root=tmp_path,
    )

    assert errors == []
    assert ("ip", "route", "get", "1.1.1.1") not in calls
    assert ("resolvectl", "status", "lo") in calls
    assert ("resolvectl", "dns", "lo", "192.168.88.203") in calls
    assert ("resolvectl", "domain", "lo", "~see-radars.com", "~seetech.local") in calls


def test_disconnect_reverts_lo_for_split_dns(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="lo",
            dns_servers=("192.168.88.203",),
            search_domains=("see-radars.com", "seetech.local"),
            split_tunnel_enabled=True,
        ),
        state_root=tmp_path,
    )
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert calls == [
        ("resolvectl", "revert", "lo"),
        ("resolvectl", "flush-caches"),
    ]

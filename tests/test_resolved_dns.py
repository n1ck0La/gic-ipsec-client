from __future__ import annotations

from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.resolved import (
    ResolvedDnsPlan,
    build_resolvectl_apply_commands,
    revert_resolved_dns,
    save_resolved_plan,
)


class Completed:
    stdout = ""
    stderr = ""
    returncode = 0


def test_fedora_split_dns_uses_route_only_domains() -> None:
    specs = build_resolvectl_apply_commands(
        interface="wlp1s0",
        dns_servers=["192.168.20.1"],
        search_domains=["see.local"],
        split_tunnel_enabled=True,
    )

    assert [spec.args for spec in specs] == [
        ("resolvectl", "dns", "wlp1s0", "192.168.20.1"),
        ("resolvectl", "domain", "wlp1s0", "~see.local", "see.local"),
        ("resolvectl", "default-route", "wlp1s0", "no"),
        ("resolvectl", "flush-caches"),
    ]


def test_disconnect_reverts_resolved_interface(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="wlp1s0",
            dns_servers=("192.168.20.1",),
            search_domains=("see.local",),
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
        ("resolvectl", "revert", "wlp1s0"),
        ("resolvectl", "flush-caches"),
    ]

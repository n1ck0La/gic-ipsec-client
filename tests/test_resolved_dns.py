from __future__ import annotations

from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.resolved import (
    DUMMY_DNS_INTERFACE,
    LOOPBACK_DNS_INTERFACE,
    ResolvedDnsPlan,
    apply_resolved_dns,
    build_resolvectl_apply_commands,
    load_dns_apply_report,
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


def test_physical_split_dns_fallback_uses_default_route_and_resets_features() -> None:
    specs = build_resolvectl_apply_commands(
        interface="ens18",
        dns_servers=["192.168.88.203"],
        search_domains=["see-radars.com", "seetech.local"],
        split_tunnel_enabled=True,
        split_default_route="yes",
        reset_server_features=True,
    )

    assert [spec.args for spec in specs] == [
        ("resolvectl", "dns", "ens18", "192.168.88.203"),
        ("resolvectl", "domain", "ens18", "~see-radars.com", "~seetech.local"),
        ("resolvectl", "default-route", "ens18", "yes"),
        ("resolvectl", "flush-caches"),
        ("resolvectl", "reset-server-features"),
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
        if spec.args == ("resolvectl", "status", "lo"):
            completed = EmptyCompleted()
            completed.stdout = "Link 1 (lo)\nDNS Servers: 192.168.88.203\n"
            return completed
        if spec.args == ("resolvectl", "query", "nextcloud.see-radars.com"):
            completed = EmptyCompleted()
            completed.stdout = "nextcloud.see-radars.com: 192.168.88.65\n-- link: lo\n"
            return completed
        if spec.args == ("resolvectl", "query", "srv-dc-01.seetech.local"):
            completed = EmptyCompleted()
            completed.stdout = "srv-dc-01.seetech.local: 192.168.88.203\n-- link: lo\n"
            return completed
        if spec.args[0] == "dig":
            completed = EmptyCompleted()
            completed.stdout = "192.168.88.65\n"
            return completed
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
    report = load_dns_apply_report(profile_id, state_root=tmp_path)
    assert report["dns_apply_ran"] is True
    assert report["success"] is True
    assert report["verified_interface"] == LOOPBACK_DNS_INTERFACE
    command_entry = report["commands"][1]
    assert {"args", "returncode", "stdout", "stderr"} <= set(command_entry)
    assert ("resolvectl", "query", "nextcloud.see-radars.com") in calls
    assert ("resolvectl", "query", "srv-dc-01.seetech.local") in calls
    assert ("dig", "@192.168.88.203", "nextcloud.see-radars.com", "+short") in calls
    assert ("dig", "@127.0.0.53", "nextcloud.see-radars.com", "+short") in calls


def test_split_dns_falls_back_to_physical_interface_when_lo_query_uses_ens18(
    tmp_path: Path,
) -> None:
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
        if spec.args == ("ip", "route", "get", "1.1.1.1"):
            completed = EmptyCompleted()
            completed.stdout = "1.1.1.1 via 10.0.0.1 dev ens18 src 10.0.0.2\n"
            return completed
        if spec.args == ("resolvectl", "status", "lo"):
            completed = EmptyCompleted()
            completed.stdout = "Link 1 (lo)\nDNS Servers: 192.168.88.203\n"
            return completed
        if spec.args == ("resolvectl", "status", "ens18"):
            completed = EmptyCompleted()
            completed.stdout = "Link 2 (ens18)\nDNS Servers: 192.168.88.203\n"
            return completed
        if spec.args == ("resolvectl", "query", "nextcloud.see-radars.com"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "ens18", "192.168.88.203") in calls:
                completed.stdout = "nextcloud.see-radars.com: 192.168.88.65\n-- link: ens18\n"
            else:
                completed.stdout = "nextcloud.see-radars.com: 185.70.111.155\n-- link: ens18\n"
            return completed
        if spec.args == ("resolvectl", "query", "srv-dc-01.seetech.local"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "ens18", "192.168.88.203") in calls:
                completed.stdout = "srv-dc-01.seetech.local: 192.168.88.203\n-- link: ens18\n"
            else:
                completed.stdout = "resolve call failed\n-- link: ens18\n"
                completed.returncode = 1
            return completed
        if spec.args[0] == "dig":
            completed = EmptyCompleted()
            completed.stdout = "192.168.88.65\n"
            return completed
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
    assert ("ip", "link", "add", "seeipsec0", "type", "dummy") not in calls
    assert ("resolvectl", "dns", DUMMY_DNS_INTERFACE, "192.168.88.203") not in calls
    assert ("ip", "route", "get", "1.1.1.1") in calls
    assert ("resolvectl", "dns", "ens18", "192.168.88.203") in calls
    assert ("resolvectl", "domain", "ens18", "~see-radars.com", "~seetech.local") in calls
    assert ("resolvectl", "default-route", "ens18", "yes") in calls
    assert ("resolvectl", "reset-server-features") in calls
    report = load_dns_apply_report(profile_id, state_root=tmp_path)
    assert report["fallback_used"] is True
    assert report["success"] is True
    assert report["verified_interface"] == "ens18"


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

    class MissingCompleted(Completed):
        returncode = 1

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == ("ip", "link", "show", "seeipsec0"):
            return MissingCompleted()
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert calls == [
        ("resolvectl", "revert", "lo"),
        ("resolvectl", "revert", "seeipsec0"),
        ("ip", "link", "show", "seeipsec0"),
        ("resolvectl", "flush-caches"),
        ("resolvectl", "reset-server-features"),
    ]


def test_disconnect_reverts_saved_physical_dns_interface(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="ens18",
            dns_servers=("192.168.88.203",),
            search_domains=("see-radars.com", "seetech.local"),
            split_tunnel_enabled=True,
        ),
        state_root=tmp_path,
    )
    calls: list[tuple[str, ...]] = []

    class MissingCompleted(Completed):
        returncode = 1

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == ("ip", "link", "show", "seeipsec0"):
            return MissingCompleted()
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert calls == [
        ("resolvectl", "revert", "ens18"),
        ("resolvectl", "revert", "lo"),
        ("resolvectl", "revert", "seeipsec0"),
        ("ip", "link", "show", "seeipsec0"),
        ("resolvectl", "flush-caches"),
        ("resolvectl", "reset-server-features"),
    ]


def test_disconnect_deletes_dummy_interface_when_present(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert ("ip", "link", "delete", "seeipsec0") in calls
    assert ("resolvectl", "reset-server-features") in calls

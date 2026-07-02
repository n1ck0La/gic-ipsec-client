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
    load_resolved_plan,
    revert_resolved_dns,
    save_resolved_plan,
    verify_resolved_dns_after_disconnect,
)


class Completed:
    stdout = ""
    stderr = ""
    returncode = 0


def test_fedora_split_dns_uses_lo_route_only_domains() -> None:
    specs = build_resolvectl_apply_commands(
        interface="lo",
        dns_servers=["10.88.0.53"],
        search_domains=["corp.example", "corp.local"],
        split_tunnel_enabled=True,
    )

    assert [spec.args for spec in specs] == [
        ("resolvectl", "dns", "lo", "10.88.0.53"),
        ("resolvectl", "domain", "lo", "~corp.example", "~corp.local"),
        ("resolvectl", "default-route", "lo", "no"),
        ("resolvectl", "flush-caches"),
    ]


def test_physical_split_dns_fallback_uses_default_route_and_resets_features() -> None:
    specs = build_resolvectl_apply_commands(
        interface="wan0",
        dns_servers=["10.88.0.53"],
        search_domains=["corp.example", "corp.local"],
        split_tunnel_enabled=True,
        split_default_route="yes",
        reset_server_features=True,
    )

    assert [spec.args for spec in specs] == [
        ("resolvectl", "dns", "wan0", "10.88.0.53"),
        ("resolvectl", "domain", "wan0", "~corp.example", "~corp.local"),
        ("resolvectl", "default-route", "wan0", "yes"),
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
            completed.stdout = "Link 1 (lo)\nDNS Servers: 10.88.0.53\n"
            return completed
        if spec.args == ("resolvectl", "query", "portal.corp.example"):
            completed = EmptyCompleted()
            completed.stdout = "portal.corp.example: 10.88.0.65\n-- link: lo\n"
            return completed
        if spec.args == ("resolvectl", "query", "dc.corp.local"):
            completed = EmptyCompleted()
            completed.stdout = "dc.corp.local: 10.88.0.53\n-- link: lo\n"
            return completed
        if spec.args[0] == "dig":
            completed = EmptyCompleted()
            completed.stdout = "10.88.0.65\n"
            return completed
        return EmptyCompleted()

    errors = apply_resolved_dns(
        profile_id=profile_id,
        dns_servers=["10.88.0.53"],
        search_domains=["corp.example", "corp.local"],
        split_tunnel_enabled=True,
        test_names=["portal.corp.example", "dc.corp.local"],
        run_command=fake_run,
        state_root=tmp_path,
    )

    assert errors == []
    assert ("ip", "route", "get", "1.1.1.1") not in calls
    assert ("resolvectl", "status", "lo") in calls
    assert ("resolvectl", "dns", "lo", "10.88.0.53") in calls
    assert ("resolvectl", "domain", "lo", "~corp.example", "~corp.local") in calls
    report = load_dns_apply_report(profile_id, state_root=tmp_path)
    assert report["dns_apply_ran"] is True
    assert report["success"] is True
    assert report["verified_interface"] == LOOPBACK_DNS_INTERFACE
    command_entry = report["commands"][1]
    assert {"args", "returncode", "stdout", "stderr"} <= set(command_entry)
    assert ("resolvectl", "query", "portal.corp.example") in calls
    assert ("resolvectl", "query", "dc.corp.local") in calls
    assert ("dig", "@10.88.0.53", "portal.corp.example", "+short") in calls
    assert ("dig", "@127.0.0.53", "portal.corp.example", "+short") in calls


def test_split_dns_falls_back_to_physical_interface_when_lo_query_uses_wan0(
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
            completed.stdout = "1.1.1.1 via 10.0.0.1 dev wan0 src 10.0.0.2\n"
            return completed
        if spec.args == ("resolvectl", "status", "lo"):
            completed = EmptyCompleted()
            completed.stdout = "Link 1 (lo)\nDNS Servers: 10.88.0.53\n"
            return completed
        if spec.args == ("resolvectl", "status", "wan0"):
            completed = EmptyCompleted()
            completed.stdout = "Link 2 (wan0)\nDNS Servers: 10.88.0.53\n"
            return completed
        if spec.args == ("resolvectl", "query", "portal.corp.example"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "wan0", "10.88.0.53") in calls:
                completed.stdout = "portal.corp.example: 10.88.0.65\n-- link: wan0\n"
            else:
                completed.stdout = "portal.corp.example: 203.0.113.155\n-- link: wan0\n"
            return completed
        if spec.args == ("resolvectl", "query", "dc.corp.local"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "wan0", "10.88.0.53") in calls:
                completed.stdout = "dc.corp.local: 10.88.0.53\n-- link: wan0\n"
            else:
                completed.stdout = "resolve call failed\n-- link: wan0\n"
                completed.returncode = 1
            return completed
        if spec.args == ("dig", "@10.88.0.53", "portal.corp.example", "+short"):
            completed = EmptyCompleted()
            completed.stdout = "10.88.0.65\n"
            return completed
        if spec.args == ("dig", "@127.0.0.53", "portal.corp.example", "+short"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "wan0", "10.88.0.53") in calls:
                completed.stdout = "10.88.0.65\n"
            else:
                completed.stdout = "10.88.0.65\n"
            return completed
        if spec.args[0] == "dig":
            completed = EmptyCompleted()
            completed.stdout = ""
            return completed
        return EmptyCompleted()

    errors = apply_resolved_dns(
        profile_id=profile_id,
        dns_servers=["10.88.0.53"],
        search_domains=["corp.example", "corp.local"],
        split_tunnel_enabled=True,
        test_names=["portal.corp.example", "dc.corp.local"],
        run_command=fake_run,
        state_root=tmp_path,
    )

    assert errors == []
    assert ("ip", "link", "add", "gicipsec0", "type", "dummy") not in calls
    assert ("resolvectl", "dns", DUMMY_DNS_INTERFACE, "10.88.0.53") not in calls
    assert ("ip", "route", "get", "1.1.1.1") in calls
    assert ("resolvectl", "dns", "wan0", "10.88.0.53") in calls
    assert ("resolvectl", "domain", "wan0", "~corp.example", "~corp.local") in calls
    assert ("resolvectl", "default-route", "wan0", "yes") in calls
    assert ("resolvectl", "reset-server-features") in calls
    report = load_dns_apply_report(profile_id, state_root=tmp_path)
    assert report["fallback_used"] is True
    assert report["success"] is True
    assert report["verified_interface"] == "wan0"


def test_dns_snapshot_is_created_before_applying_vpn_dns_to_physical_interface(
    tmp_path: Path,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []
    nmcli_snapshot_args = (
        "nmcli",
        "-t",
        "-f",
        "GENERAL.CONNECTION,IP4.DNS,IP4.DOMAIN,IP4.SEARCHES",
        "device",
        "show",
        "wan0",
    )

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
            completed.stdout = "1.1.1.1 via 10.0.0.1 dev wan0 src 10.0.0.2\n"
            return completed
        if spec.args == ("resolvectl", "status", "wan0"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "wan0", "10.88.0.53") in calls:
                completed.stdout = "Link 2 (wan0)\nDNS Servers: 10.88.0.53\n"
            else:
                completed.stdout = """
                Link 2 (wan0)
                    DNS Servers: 9.9.9.9 8.8.8.8
                    DefaultRoute setting: yes
                """
            return completed
        if spec.args == nmcli_snapshot_args:
            completed = EmptyCompleted()
            completed.stdout = "GENERAL.CONNECTION:Wired connection 1\nIP4.DNS[1]:9.9.9.9\n"
            return completed
        if spec.args == ("resolvectl", "query", "portal.corp.example"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "wan0", "10.88.0.53") in calls:
                completed.stdout = "portal.corp.example: 10.88.0.65\n-- link: wan0\n"
            else:
                completed.stdout = "portal.corp.example: 203.0.113.155\n-- link: wan0\n"
            return completed
        if spec.args == ("resolvectl", "query", "dc.corp.local"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "wan0", "10.88.0.53") in calls:
                completed.stdout = "dc.corp.local: 10.88.0.53\n-- link: wan0\n"
            else:
                completed.returncode = 1
            return completed
        if spec.args == ("dig", "@10.88.0.53", "portal.corp.example", "+short"):
            completed = EmptyCompleted()
            completed.stdout = "10.88.0.65\n"
            return completed
        if spec.args == ("dig", "@127.0.0.53", "portal.corp.example", "+short"):
            completed = EmptyCompleted()
            if ("resolvectl", "dns", "wan0", "10.88.0.53") in calls:
                completed.stdout = "10.88.0.65\n"
            else:
                completed.stdout = "203.0.113.155\n"
            return completed
        if spec.args[0] == "dig":
            completed = EmptyCompleted()
            completed.stdout = ""
            return completed
        return EmptyCompleted()

    errors = apply_resolved_dns(
        profile_id=profile_id,
        dns_servers=["10.88.0.53"],
        search_domains=["corp.example", "corp.local"],
        split_tunnel_enabled=True,
        test_names=["portal.corp.example", "dc.corp.local"],
        run_command=fake_run,
        state_root=tmp_path,
    )

    assert errors == []
    physical_status_index = calls.index(("resolvectl", "status", "wan0"))
    physical_apply_index = calls.index(("resolvectl", "dns", "wan0", "10.88.0.53"))
    assert physical_status_index < physical_apply_index
    plan = load_resolved_plan(profile_id, state_root=tmp_path)
    assert plan is not None
    assert plan.interface == "wan0"
    assert plan.dns_servers == ("9.9.9.9", "8.8.8.8")
    assert plan.default_route is True
    assert plan.vpn_dns_servers == ("10.88.0.53",)


def test_disconnect_reverts_lo_for_split_dns(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="lo",
            dns_servers=("10.88.0.53",),
            search_domains=("corp.example", "corp.local"),
            split_tunnel_enabled=True,
        ),
        state_root=tmp_path,
    )
    calls: list[tuple[str, ...]] = []

    class MissingCompleted(Completed):
        returncode = 1

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == ("ip", "link", "show", "gicipsec0"):
            return MissingCompleted()
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    report = load_dns_apply_report(profile_id, state_root=tmp_path)
    assert "gicipsec0 not present; nothing to clean up." in report["warnings"]
    assert calls == [
        ("resolvectl", "revert", "lo"),
        ("resolvectl", "revert", "gicipsec0"),
        ("ip", "link", "show", "gicipsec0"),
        ("resolvectl", "flush-caches"),
        ("resolvectl", "reset-server-features"),
    ]


def test_cleanup_revert_failure_is_warning_when_explicit_restore_succeeds(
    tmp_path: Path,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="wan0",
            dns_servers=("9.9.9.9", "8.8.8.8"),
            search_domains=(),
            split_tunnel_enabled=True,
            default_route=True,
            vpn_dns_servers=("10.88.0.53",),
        ),
        state_root=tmp_path,
    )

    class FailedRevertCompleted(Completed):
        returncode = 1
        stderr = (
            "Failed to revert interface configuration: Could not activate remote peer "
            "'org.freedesktop.network1': activation request failed: unknown unit"
        )

    class MissingCompleted(Completed):
        returncode = 1

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args in {
            ("resolvectl", "revert", "lo"),
            ("resolvectl", "revert", "gicipsec0"),
        }:
            return FailedRevertCompleted()
        if spec.args == ("ip", "link", "show", "gicipsec0"):
            return MissingCompleted()
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    warnings = load_dns_apply_report(profile_id, state_root=tmp_path)["warnings"]
    assert any("org.freedesktop.network1" in warning for warning in warnings)
    assert "gicipsec0 not present; nothing to clean up." in warnings


def test_disconnect_reverts_saved_physical_dns_interface(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="wan0",
            dns_servers=("9.9.9.9", "8.8.8.8"),
            search_domains=(),
            split_tunnel_enabled=True,
            default_route=True,
            vpn_dns_servers=("10.88.0.53",),
        ),
        state_root=tmp_path,
    )
    calls: list[tuple[str, ...]] = []

    class MissingCompleted(Completed):
        returncode = 1

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == ("ip", "link", "show", "gicipsec0"):
            return MissingCompleted()
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert calls == [
        ("resolvectl", "dns", "wan0", "9.9.9.9", "8.8.8.8"),
        ("resolvectl", "domain", "wan0", ""),
        ("resolvectl", "default-route", "wan0", "yes"),
        ("resolvectl", "flush-caches"),
        ("resolvectl", "reset-server-features"),
        ("resolvectl", "revert", "lo"),
        ("resolvectl", "revert", "gicipsec0"),
        ("ip", "link", "show", "gicipsec0"),
        ("resolvectl", "flush-caches"),
        ("resolvectl", "reset-server-features"),
    ]


def test_disconnect_reapply_fallback_handles_resolvectl_restore_failure(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="wan0",
            dns_servers=("9.9.9.9", "8.8.8.8"),
            search_domains=(),
            split_tunnel_enabled=True,
            default_route=True,
            vpn_dns_servers=("10.88.0.53",),
        ),
        state_root=tmp_path,
    )
    calls: list[tuple[str, ...]] = []

    class FailedCompleted(Completed):
        returncode = 1
        stderr = (
            "Failed to revert interface configuration: Could not activate remote peer "
            "'org.freedesktop.network1': activation request failed: unknown unit"
        )

    class MissingCompleted(Completed):
        returncode = 1

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == ("resolvectl", "dns", "wan0", "9.9.9.9", "8.8.8.8"):
            return FailedCompleted()
        if spec.args == ("ip", "link", "show", "gicipsec0"):
            return MissingCompleted()
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert ("resolvectl", "revert", "wan0") not in calls
    assert ("nmcli", "dev", "reapply", "wan0") in calls


def test_disconnect_verification_flags_leftover_vpn_dns(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="wan0",
            dns_servers=("9.9.9.9", "8.8.8.8"),
            search_domains=(),
            split_tunnel_enabled=True,
            vpn_dns_servers=("10.88.0.53",),
        ),
        state_root=tmp_path,
    )

    class QueryCompleted(Completed):
        stdout = "ok\n"

    class StatusCompleted(Completed):
        stdout = "Link 2 (wan0)\nDNS Servers: 10.88.0.53\n"

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args == ("resolvectl", "status", "wan0"):
            return StatusCompleted()
        return QueryCompleted()

    errors = verify_resolved_dns_after_disconnect(
        profile_id,
        run_command=fake_run,
        state_root=tmp_path,
    )

    assert "VPN DNS server 10.88.0.53 is still configured on wan0." in errors


def test_disconnect_verification_allows_vpn_dns_if_it_existed_before(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    save_resolved_plan(
        ResolvedDnsPlan(
            profile_id=profile_id,
            interface="wan0",
            dns_servers=("10.88.0.53",),
            search_domains=(),
            split_tunnel_enabled=True,
            vpn_dns_servers=("10.88.0.53",),
        ),
        state_root=tmp_path,
    )

    class QueryCompleted(Completed):
        stdout = "ok\n"

    class StatusCompleted(Completed):
        stdout = "Link 2 (wan0)\nDNS Servers: 10.88.0.53\n"

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args == ("resolvectl", "status", "wan0"):
            return StatusCompleted()
        return QueryCompleted()

    errors = verify_resolved_dns_after_disconnect(
        profile_id,
        run_command=fake_run,
        state_root=tmp_path,
    )

    assert errors == []


def test_disconnect_deletes_dummy_interface_when_present(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert ("ip", "link", "delete", "gicipsec0") in calls
    assert ("resolvectl", "reset-server-features") in calls


def test_missing_dummy_interface_is_warning_not_error(tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"

    class MissingCompleted(Completed):
        returncode = 1
        stderr = 'Failed to resolve interface "gicipsec0": No such device'

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args == ("ip", "link", "show", "gicipsec0"):
            return MissingCompleted()
        return Completed()

    errors = revert_resolved_dns(profile_id, run_command=fake_run, state_root=tmp_path)

    assert errors == []
    assert "gicipsec0 not present; nothing to clean up." in load_dns_apply_report(
        profile_id,
        state_root=tmp_path,
    )["warnings"]

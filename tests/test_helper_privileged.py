from __future__ import annotations

from pathlib import Path

import pytest

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.swanctl_paths import SwanctlLayout
from gic_ipsec_client.helper import privileged


class Completed:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _is_swanctl_command(args: tuple[str, ...], *tail: str) -> bool:
    return Path(args[0]).name == "swanctl" and args[1:] == tail


def test_initiate_is_blocked_when_child_is_not_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if _is_swanctl_command(spec.args, "--load-all"):
            return Completed(0, "loaded")
        if _is_swanctl_command(spec.args, "--list-conns"):
            return Completed(0, "other-connection:\n  children:\n    other-child:\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "run_command", fake_run)
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: {"vici_socket_available": True},
    )

    with pytest.raises(
        privileged.HelperError,
        match="Profile was rendered but strongSwan did not load it",
    ):
        privileged.connect_profile(profile_id)

    assert not any(
        _is_swanctl_command(args, "--initiate", "--child", f"gic-{profile_id}-child")
        for args in calls
    )


def test_disconnect_restores_dns_before_terminating_sa(monkeypatch: pytest.MonkeyPatch) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[str] = []

    def fake_revert(*args: object, **kwargs: object) -> list[str]:
        calls.append("restore-dns")
        return []

    def fake_flush(*args: object, **kwargs: object) -> list[str]:
        calls.append("flush-dns")
        return []

    def fake_verify(*args: object, **kwargs: object) -> list[str]:
        calls.append("verify-dns")
        return []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if _is_swanctl_command(spec.args, "--terminate", "--ike", f"gic-{profile_id}"):
            calls.append("terminate-sa")
            return Completed(0)
        if _is_swanctl_command(spec.args, "--list-sas"):
            calls.append("list-sas")
            return Completed(0, "")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(privileged, "revert_resolved_dns", fake_revert)
    monkeypatch.setattr(privileged, "flush_resolved_dns_caches", fake_flush)
    monkeypatch.setattr(privileged, "verify_resolved_dns_after_disconnect", fake_verify)
    monkeypatch.setattr(privileged, "_dns_warning_lines", lambda profile_id: [])
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: {"vici_socket_available": True},
    )
    monkeypatch.setattr(commands, "run_command", fake_run)

    assert privileged.disconnect_profile(profile_id) == 0
    assert calls == ["restore-dns", "terminate-sa", "flush-dns", "verify-dns", "list-sas"]


def test_disconnect_succeeds_with_cleanup_warnings_when_final_state_is_good(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if _is_swanctl_command(spec.args, "--terminate", "--ike", f"gic-{profile_id}"):
            return Completed(1, stderr="terminate already gone")
        if _is_swanctl_command(spec.args, "--list-sas"):
            return Completed(0, "")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(privileged, "revert_resolved_dns", lambda *args, **kwargs: [])
    monkeypatch.setattr(privileged, "flush_resolved_dns_caches", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        privileged,
        "verify_resolved_dns_after_disconnect",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        privileged,
        "_dns_warning_lines",
        lambda profile_id: ["resolvectl revert lo failed"],
    )
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: {"vici_socket_available": True},
    )
    monkeypatch.setattr(commands, "run_command", fake_run)

    assert privileged.disconnect_profile(profile_id) == 0
    output = capsys.readouterr().out
    assert "Disconnect completed with warnings" in output
    assert "resolvectl revert lo failed" in output


def test_disconnect_fails_when_selected_sa_remains_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if _is_swanctl_command(spec.args, "--terminate", "--ike", f"gic-{profile_id}"):
            return Completed(0)
        if _is_swanctl_command(spec.args, "--list-sas"):
            return Completed(0, f"gic-{profile_id}: ESTABLISHED")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(privileged, "revert_resolved_dns", lambda *args, **kwargs: [])
    monkeypatch.setattr(privileged, "flush_resolved_dns_caches", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        privileged,
        "verify_resolved_dns_after_disconnect",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(privileged, "_dns_warning_lines", lambda profile_id: [])
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: {"vici_socket_available": True},
    )
    monkeypatch.setattr(commands, "run_command", fake_run)

    with pytest.raises(privileged.HelperError, match="Selected IKE_SA remains active"):
        privileged.disconnect_profile(profile_id)


def test_disconnect_fails_when_final_dns_verification_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if _is_swanctl_command(spec.args, "--terminate", "--ike", f"gic-{profile_id}"):
            return Completed(0)
        if _is_swanctl_command(spec.args, "--list-sas"):
            return Completed(0, "")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(privileged, "revert_resolved_dns", lambda *args, **kwargs: [])
    monkeypatch.setattr(privileged, "flush_resolved_dns_caches", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        privileged,
        "verify_resolved_dns_after_disconnect",
        lambda *args, **kwargs: ["resolvectl query i.ua failed."],
    )
    monkeypatch.setattr(privileged, "_dns_warning_lines", lambda profile_id: [])
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: {"vici_socket_available": True},
    )
    monkeypatch.setattr(commands, "run_command", fake_run)

    with pytest.raises(privileged.HelperError, match="i.ua failed"):
        privileged.disconnect_profile(profile_id)


def test_swanctl_diagnostics_reports_binary_resolution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args == ("rpm", "-qf", "/usr/bin/swanctl"):
            return Completed(0, "strongswan-6.0.0-1.fc40.x86_64\n")
        return Completed(0, "")

    monkeypatch.setattr(commands, "command_v", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "run_command", fake_run)
    monkeypatch.setattr(
        privileged,
        "detect_swanctl_layout",
        lambda override="": SwanctlLayout(root=tmp_path, source="test"),
    )
    monkeypatch.setattr(privileged, "swanctl_files_by_root", lambda: {})

    payload = privileged.swanctl_diagnostics()

    assert payload["command_v_swanctl"] == "/usr/bin/swanctl"
    assert payload["resolved_swanctl_path"] == "/usr/bin/swanctl"
    assert payload["swanctl_rpm_owner"] == "strongswan-6.0.0-1.fc40.x86_64"
    assert "detected_strongswan_service" in payload
    assert "run_charon_vici_exists" in payload
    assert "var_run_charon_vici_exists" in payload


def test_strongswan_preflight_switches_from_starter_to_swanctl_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    migrated = {"value": False}

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == (
            "systemctl",
            "list-unit-files",
            "strongswan.service",
            "--no-legend",
        ):
            return Completed(0, "strongswan.service enabled\n")
        if spec.args[:2] == ("systemctl", "is-active"):
            if spec.args[2] == "strongswan-starter.service":
                return Completed(0, "active\n")
            if spec.args[2] == "strongswan.service":
                return Completed(
                    0 if migrated["value"] else 3,
                    "active\n" if migrated["value"] else "inactive\n",
                )
            return Completed(3, "inactive\n")
        if spec.args == ("systemctl", "disable", "--now", "strongswan-starter.service"):
            return Completed(0, "Removed symlink\n")
        if spec.args == ("systemctl", "enable", "--now", "strongswan.service"):
            migrated["value"] = True
            return Completed(0, "")
        if spec.args == ("find", "/run", "/var/run", "-type", "s", "-name", "*vici*"):
            return Completed(0, "")
        if _is_swanctl_command(spec.args, "--list-conns"):
            return Completed(0, "loaded connections\n")
        if spec.args[:2] == ("systemctl", "list-unit-files"):
            return Completed(0, "")
        raise AssertionError(f"unexpected command: {spec.args}")

    def socket_exists(path: Path) -> bool:
        return migrated["value"] and path == Path("/run/charon.vici")

    monkeypatch.setattr(commands, "command_v", lambda name: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")

    payload = privileged.strongswan_preflight(
        run_command=fake_run,
        socket_exists=socket_exists,
        sleep=lambda seconds: None,
    )

    assert payload["selected_strongswan_service"] == "strongswan.service"
    assert payload["detected_strongswan_service"] == "strongswan.service"
    assert payload["strongswan_starter_active"] is True
    assert payload["strongswan_starter_disabled"] is True
    assert payload["strongswan_starter_warning"] == commands.STARTER_INCOMPATIBLE_MESSAGE
    assert payload["strongswan_service_state"] == "active"
    assert payload["strongswan_service_started"] is True
    assert payload["started_strongswan_service"] is True
    assert payload["run_charon_vici_exists"] is True
    assert payload["vici_socket_available"] is True
    assert payload["vici_socket_path"] == "/run/charon.vici"
    assert payload["swanctl_list_conns_ok"] is True
    assert payload["preflight_list_conns_returncode"] == 0
    assert ("systemctl", "disable", "--now", "strongswan-starter.service") in calls
    assert ("systemctl", "enable", "--now", "strongswan.service") in calls
    assert (
        "systemctl",
        "list-unit-files",
        "strongswan-starter.service",
        "--no-legend",
    ) not in calls
    assert ("systemctl", "start", "strongswan-starter") not in calls


def test_strongswan_preflight_fails_cleanly_when_vici_socket_never_appears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args == (
            "systemctl",
            "list-unit-files",
            "strongswan.service",
            "--no-legend",
        ):
            return Completed(0, "strongswan.service enabled\n")
        if spec.args[:2] == ("systemctl", "is-active"):
            return Completed(3, "inactive\n")
        if spec.args == ("systemctl", "enable", "--now", "strongswan.service"):
            return Completed(0, "")
        if spec.args == ("find", "/run", "/var/run", "-type", "s", "-name", "*vici*"):
            return Completed(0, "")
        if _is_swanctl_command(spec.args, "--list-conns"):
            return Completed(1, stderr="connecting to VICI failed")
        if spec.args[:2] == ("systemctl", "list-unit-files"):
            return Completed(0, "")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "command_v", lambda name: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")

    with pytest.raises(privileged.HelperError, match="connecting to VICI failed"):
        privileged.strongswan_preflight(
            run_command=fake_run,
            socket_exists=lambda path: False,
            sleep=lambda seconds: None,
        )


def test_connect_does_not_load_or_initiate_without_vici(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        return Completed(0, "")

    monkeypatch.setattr(commands, "run_command", fake_run)
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            privileged.HelperError(commands.VICI_UNAVAILABLE_MESSAGE)
        ),
    )

    with pytest.raises(privileged.HelperError, match=commands.VICI_UNAVAILABLE_MESSAGE):
        privileged.connect_profile(profile_id)

    assert not any(_is_swanctl_command(args, "--load-all") for args in calls)
    assert not any(_is_swanctl_command(args, "--list-conns") for args in calls)
    assert not any(args for args in calls if Path(args[0]).name == "swanctl")


def test_vici_socket_state_finds_nonstandard_vici_socket() -> None:
    def fake_run(spec: commands.CommandSpec) -> Completed:
        assert spec.args == ("find", "/run", "/var/run", "-type", "s", "-name", "*vici*")
        return Completed(0, "/run/strongswan/charon.vici\n")

    payload = privileged._vici_socket_state(lambda path: False, run_command=fake_run)

    assert payload["vici_socket_available"] is True
    assert payload["vici_socket_path"] == "/run/strongswan/charon.vici"
    assert payload["vici_socket_candidates"] == ["/run/strongswan/charon.vici"]


def test_fedora_vici_socket_under_strongswan_runtime_passes_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == (
            "systemctl",
            "list-unit-files",
            "strongswan.service",
            "--no-legend",
        ):
            return Completed(0, "strongswan.service enabled\n")
        if spec.args == (
            "systemctl",
            "list-unit-files",
            "charon-systemd.service",
            "--no-legend",
        ):
            return Completed(0, "")
        if spec.args[:2] == ("systemctl", "is-active"):
            if spec.args[2] == "strongswan.service":
                return Completed(0, "active\n")
            return Completed(3, "inactive\n")
        if _is_swanctl_command(spec.args, "--list-conns"):
            return Completed(0, "gic-fedora:\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    def socket_exists(path: Path) -> bool:
        return path == Path("/run/strongswan/charon.vici")

    monkeypatch.setattr(commands, "command_v", lambda name: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")

    payload = privileged.strongswan_preflight(
        run_command=fake_run,
        socket_exists=socket_exists,
        sleep=lambda seconds: None,
    )

    assert payload["selected_strongswan_service"] == "strongswan.service"
    assert payload["strongswan_service_active_state"] == "active"
    assert payload["charon_systemd_service_available"] is False
    assert payload["run_strongswan_charon_vici_exists"] is True
    assert payload["vici_socket_path"] == "/run/strongswan/charon.vici"
    assert payload["swanctl_list_conns_ok"] is True
    assert payload["vici_socket_available"] is True
    assert ("systemctl", "start", "charon-systemd") not in calls


def test_swanctl_diagnostics_reports_loaded_connection_after_vici(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if _is_swanctl_command(spec.args, "--list-conns"):
            return Completed(
                0,
                f"gic-{profile_id}:\n  children:\n    gic-{profile_id}-child:\n",
            )
        if _is_swanctl_command(spec.args, "--list-sas"):
            return Completed(0, "")
        if spec.args[0] in {"resolvectl", "ip"}:
            return Completed(0, "")
        if spec.args == ("rpm", "-qf", "/usr/bin/swanctl"):
            return Completed(0, "strongswan\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "command_v", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "run_command", fake_run)
    monkeypatch.setattr(
        privileged,
        "detect_swanctl_layout",
        lambda override="": SwanctlLayout(root=tmp_path, source="test"),
    )
    monkeypatch.setattr(privileged, "swanctl_files_by_root", lambda: {})
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda raise_on_failure=True: {
            "selected_strongswan_service": "strongswan.service",
            "detected_strongswan_service": "strongswan.service",
            "strongswan_service_state": "active",
            "strongswan_starter_active": False,
            "strongswan_starter_disabled": False,
            "vici_socket_available": True,
            "vici_socket_path": "/run/charon.vici",
            "run_charon_vici_exists": True,
            "var_run_charon_vici_exists": False,
        },
    )

    payload = privileged.swanctl_diagnostics(profile_id=profile_id)

    assert payload["generated_connection_loaded"] is True
    assert payload["selected_strongswan_service"] == "strongswan.service"
    assert payload["vici_socket_path"] == "/run/charon.vici"
    assert payload["list_conns_returncode"] == 0
    assert payload["list_conns_stderr"] == ""
    assert f"gic-{profile_id}-child" in payload["list_conns_stdout"]

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


def test_strongswan_preflight_detects_starter_first_and_starts_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    started = {"value": False}

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == (
            "systemctl",
            "list-unit-files",
            "strongswan-starter.service",
            "--no-legend",
        ):
            return Completed(0, "strongswan-starter.service enabled\n")
        if spec.args[:2] == ("systemctl", "is-active"):
            return Completed(3, "inactive\n")
        if spec.args == ("systemctl", "start", "strongswan-starter"):
            started["value"] = True
            return Completed(0, "")
        if spec.args[:2] == ("systemctl", "list-unit-files"):
            return Completed(0, "")
        raise AssertionError(f"unexpected command: {spec.args}")

    def socket_exists(path: Path) -> bool:
        return started["value"] and path == Path("/run/charon.vici")

    monkeypatch.setattr(commands, "command_v", lambda name: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")

    payload = privileged.strongswan_preflight(
        run_command=fake_run,
        socket_exists=socket_exists,
        sleep=lambda seconds: None,
    )

    assert payload["detected_strongswan_service"] == "strongswan-starter.service"
    assert payload["strongswan_service_state"] == "inactive"
    assert payload["started_strongswan_service"] is True
    assert payload["run_charon_vici_exists"] is True
    assert payload["vici_socket_available"] is True
    assert ("systemctl", "start", "strongswan-starter") in calls
    assert (
        "systemctl",
        "list-unit-files",
        "strongswan.service",
        "--no-legend",
    ) not in calls


def test_strongswan_preflight_fails_cleanly_when_vici_socket_never_appears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args == (
            "systemctl",
            "list-unit-files",
            "strongswan-starter.service",
            "--no-legend",
        ):
            return Completed(0, "strongswan-starter.service enabled\n")
        if spec.args[:2] == ("systemctl", "is-active"):
            return Completed(3, "inactive\n")
        if spec.args == ("systemctl", "start", "strongswan-starter"):
            return Completed(0, "")
        if spec.args[:2] == ("systemctl", "list-unit-files"):
            return Completed(0, "")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "command_v", lambda name: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")

    with pytest.raises(privileged.HelperError, match=commands.VICI_UNAVAILABLE_MESSAGE):
        privileged.strongswan_preflight(
            run_command=fake_run,
            socket_exists=lambda path: False,
            sleep=lambda seconds: None,
        )

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
    command_args = args[1:]
    if command_args[:2] == ("--uri", commands.FEDORA_VICI_URI):
        command_args = command_args[2:]
    return Path(args[0]).name == "swanctl" and command_args == tail


@pytest.fixture(autouse=True)
def helper_runtime_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    layout = SwanctlLayout(root=tmp_path / "swanctl", source="test")
    layout.conf_dir.mkdir(parents=True)
    layout.profile_config_path(profile_id).write_text("connections {}\n", encoding="utf-8")
    monkeypatch.setattr(privileged, "CONNECT_LOCK_ROOT", tmp_path / "connect-locks")
    monkeypatch.setattr(privileged, "detect_swanctl_layout", lambda override="": layout)


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
    starter_active = {"value": True}

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
                return Completed(
                    0 if starter_active["value"] else 3,
                    "active\n" if starter_active["value"] else "inactive\n",
                )
            if spec.args[2] == "strongswan.service":
                return Completed(
                    0 if migrated["value"] else 3,
                    "active\n" if migrated["value"] else "inactive\n",
                )
            return Completed(3, "inactive\n")
        if spec.args == (
            "systemctl",
            "stop",
            "strongswan.service",
            "strongswan-starter.service",
        ):
            migrated["value"] = False
            starter_active["value"] = False
            return Completed(0, "")
        if spec.args == ("systemctl", "disable", "--now", "strongswan-starter.service"):
            return Completed(0, "Removed symlink\n")
        if spec.args == ("systemctl", "enable", "--now", "strongswan.service"):
            migrated["value"] = True
            return Completed(0, "")
        if spec.args == ("ss", "-lx"):
            output = "u_str LISTEN 0 5 /run/charon.vici 123 * 0\n" if migrated["value"] else ""
            return Completed(0, output)
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
    assert payload["run_charon_vici_listening"] is True
    assert payload["vici_socket_file_exists"] is True
    assert payload["vici_socket_listening"] is True
    assert payload["vici_socket_available"] is True
    assert payload["vici_usable"] is True
    assert payload["vici_socket_path"] == "/run/charon.vici"
    assert payload["swanctl_list_conns_ok"] is True
    assert payload["preflight_list_conns_returncode"] == 0
    assert ("systemctl", "disable", "--now", "strongswan-starter.service") in calls
    assert ("systemctl", "enable", "--now", "strongswan.service") in calls
    assert calls.index(
        ("systemctl", "stop", "strongswan.service", "strongswan-starter.service")
    ) < calls.index(
        ("systemctl", "disable", "--now", "strongswan-starter.service")
    ) < calls.index(("systemctl", "enable", "--now", "strongswan.service"))
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
        if spec.args == ("systemctl", "disable", "--now", "strongswan-starter.service"):
            return Completed(1, "unit not loaded\n")
        if spec.args == ("systemctl", "enable", "--now", "strongswan.service"):
            return Completed(0, "")
        if spec.args == (
            "systemctl",
            "stop",
            "strongswan.service",
            "strongswan-starter.service",
        ):
            return Completed(0, "")
        if spec.args == ("systemctl", "start", "strongswan.service"):
            return Completed(0, "")
        if spec.args == ("ss", "-lx"):
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


def test_stale_vici_socket_file_is_not_usable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args[:2] == ("systemctl", "list-unit-files"):
            service = spec.args[2]
            return Completed(0, f"{service} enabled\n" if service == "strongswan.service" else "")
        if spec.args[:2] == ("systemctl", "is-active"):
            return Completed(0, "active\n")
        if spec.args == ("ss", "-lx"):
            return Completed(0, "")
        if _is_swanctl_command(spec.args, "--list-conns"):
            return Completed(1, stderr="connecting to VICI failed: Connection refused")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "command_v", lambda name: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")

    payload = privileged.strongswan_preflight(
        raise_on_failure=False,
        ensure_service=False,
        run_command=fake_run,
        socket_exists=lambda path: path == Path("/run/strongswan/charon.vici"),
        sleep=lambda seconds: None,
    )

    assert payload["vici_socket_file_exists"] is True
    assert payload["vici_socket_listening"] is False
    assert payload["swanctl_list_conns_ok"] is False
    assert payload["vici_usable"] is False
    assert payload["vici_socket_available"] is False
    assert "Connection refused" in str(payload["preflight_error"])
    assert not any(args[:2] == ("systemctl", "disable") for args in calls)
    assert not any(args[:2] == ("systemctl", "enable") for args in calls)


def test_connect_lists_sas_before_applying_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[str] = []
    list_sas_calls = {"count": 0}

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if _is_swanctl_command(spec.args, "--load-all"):
            calls.append("load-all")
            return Completed(0, "loaded")
        if _is_swanctl_command(spec.args, "--list-conns"):
            calls.append("list-conns")
            return Completed(
                0,
                f"gic-{profile_id}:\n  children:\n    gic-{profile_id}-child:\n",
            )
        if _is_swanctl_command(
            spec.args,
            "--initiate",
            "--child",
            f"gic-{profile_id}-child",
        ):
            calls.append("initiate")
            return Completed(0, "initiated")
        if _is_swanctl_command(spec.args, "--list-sas"):
            calls.append("list-sas")
            list_sas_calls["count"] += 1
            if list_sas_calls["count"] == 1:
                return Completed(0, "")
            return Completed(0, f"gic-{profile_id}: ESTABLISHED\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    def fake_dns(**kwargs: object) -> list[str]:
        calls.append("apply-dns")
        return []

    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: {"vici_usable": True},
    )
    monkeypatch.setattr(
        privileged,
        "_read_runtime_profile",
        lambda profile_uuid: {
            "dns_servers": ["10.0.0.53"],
            "dns_search_domains": ["corp.example"],
            "split_tunnel_enabled": True,
            "dns_test_names": ["host.corp.example"],
            "dns_linux_strategy": "auto",
            "dns_interface": "auto",
        },
    )
    monkeypatch.setattr(privileged, "apply_resolved_dns", fake_dns)
    monkeypatch.setattr(commands, "run_command", fake_run)

    assert privileged.connect_profile(profile_id) == 0
    assert calls == [
        "load-all",
        "list-conns",
        "list-sas",
        "initiate",
        "list-sas",
        "apply-dns",
    ]


def test_connect_retry_skips_initiate_when_profile_sa_is_already_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if _is_swanctl_command(spec.args, "--load-all"):
            return Completed(0, "loaded")
        if _is_swanctl_command(spec.args, "--list-conns"):
            output = f"gic-{profile_id}:\n  children:\n    gic-{profile_id}-child:\n"
            return Completed(0, output)
        if _is_swanctl_command(spec.args, "--list-sas"):
            return Completed(0, f"gic-{profile_id}: ESTABLISHED\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: {"selected_vici_uri": ""},
    )
    monkeypatch.setattr(privileged, "_read_runtime_profile", lambda selected_id: None)
    monkeypatch.setattr(commands, "run_command", fake_run)

    assert privileged.connect_profile(profile_id) == 0
    assert not any("--initiate" in args for args in calls)


def test_connect_requires_profile_file_before_service_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    (tmp_path / "swanctl" / "conf.d" / f"gic-{profile_id}.conf").unlink()
    preflight_calls: list[bool] = []
    monkeypatch.setattr(
        privileged,
        "strongswan_preflight",
        lambda *args, **kwargs: preflight_calls.append(True) or {},
    )

    with pytest.raises(privileged.HelperError, match="Generated profile file does not exist"):
        privileged.connect_profile(profile_id)

    assert preflight_calls == []


def test_connect_in_progress_guard_rejects_same_profile() -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"

    with privileged._connect_in_progress_guard(profile_id):
        with pytest.raises(privileged.HelperError, match="already in progress"):
            with privileged._connect_in_progress_guard(profile_id):
                pass


def test_connect_from_request_renders_and_connects_in_one_helper_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    request_dir = tmp_path / "helper-requests"
    request_dir.mkdir()
    request_path = request_dir / f"{profile_id}.json"
    request_path.write_text("{}", encoding="utf-8")
    request_path.chmod(0o600)
    uid = request_path.stat().st_uid
    calls: list[str] = []
    config_path = tmp_path / "swanctl" / "conf.d" / f"gic-{profile_id}.conf"
    config_path.unlink()

    def fake_render(
        path: Path,
        *,
        uid: int,
        expected_action: str,
        expected_profile_id: str,
    ) -> dict[str, str]:
        assert path == request_path
        assert uid == request_path.stat().st_uid
        assert expected_action == "connect"
        assert expected_profile_id == profile_id
        calls.append("render")
        config_path.write_text("connections {}\n", encoding="utf-8")
        return {
            "swanctl_config_root": str(tmp_path / "swanctl"),
            "config_path": str(config_path),
        }

    monkeypatch.setattr(privileged, "request_dir_for_uid", lambda selected_uid: request_dir)
    monkeypatch.setattr(privileged, "render_profile_from_request", fake_render)
    monkeypatch.setattr(
        privileged,
        "_connect_profile",
        lambda selected_id, config_root_override="": (
            calls.append(
                f"connect:{selected_id}:{config_root_override}:{config_path.is_file()}"
            )
            or 0
        ),
    )

    assert privileged.connect_from_request(profile_id, uid=uid) == 0
    assert calls == [
        "render",
        f"connect:{profile_id}:{tmp_path / 'swanctl'}:True",
    ]
    assert not request_path.exists()


def test_vici_socket_state_reports_listening_separately_from_file_existence() -> None:
    def fake_run(spec: commands.CommandSpec) -> Completed:
        assert spec.args == ("ss", "-lx")
        return Completed(0, "u_str LISTEN 0 5 /run/strongswan/charon.vici 123 * 0\n")

    payload = privileged._vici_socket_state(lambda path: False, run_command=fake_run)

    assert payload["vici_socket_file_exists"] is False
    assert payload["vici_socket_listening"] is True
    assert payload["vici_socket_available"] is False
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
        if spec.args == ("systemctl", "disable", "--now", "strongswan-starter.service"):
            return Completed(0, "")
        if spec.args == ("systemctl", "enable", "--now", "strongswan.service"):
            return Completed(0, "")
        if spec.args == ("ss", "-lx"):
            return Completed(
                0,
                "u_str LISTEN 0 5 /run/strongswan/charon.vici 123 * 0\n",
            )
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
    assert payload["run_strongswan_charon_vici_listening"] is True
    assert payload["vici_socket_path"] == "/run/strongswan/charon.vici"
    assert payload["swanctl_list_conns_ok"] is True
    assert payload["vici_socket_available"] is True
    assert payload["selected_vici_uri"] == commands.FEDORA_VICI_URI
    assert (
        "/usr/bin/swanctl",
        "--uri",
        commands.FEDORA_VICI_URI,
        "--list-conns",
    ) in calls
    assert ("systemctl", "disable", "--now", "strongswan-starter.service") in calls
    assert ("systemctl", "enable", "--now", "strongswan.service") in calls
    assert ("systemctl", "start", "charon-systemd") not in calls


def test_vici_cleanup_is_skipped_while_strongswan_is_active(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sockets = (tmp_path / "charon.vici", tmp_path / "strongswan-charon.vici")
    for path in sockets:
        path.write_text("stale", encoding="utf-8")

    def fake_run(spec: commands.CommandSpec) -> Completed:
        if spec.args[:2] == ("systemctl", "stop"):
            return Completed(0, "")
        if spec.args == ("systemctl", "is-active", "strongswan.service"):
            return Completed(0, "active\n")
        if spec.args == ("systemctl", "is-active", "strongswan-starter.service"):
            return Completed(3, "inactive\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "VICI_SOCKET_PATHS", sockets)
    payload: dict[str, object] = {}

    assert not privileged._stop_services_and_cleanup_vici(payload, run_command=fake_run)
    assert all(path.exists() for path in sockets)
    assert "cleanup skipped" in str(payload["vici_recovery_cleanup_skipped"]).lower()


def test_vici_cleanup_deletes_known_paths_only_after_both_services_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sockets = (tmp_path / "charon.vici", tmp_path / "strongswan-charon.vici")
    for path in sockets:
        path.write_text("stale", encoding="utf-8")
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args[:2] == ("systemctl", "stop"):
            return Completed(0, "")
        if spec.args[:2] == ("systemctl", "is-active"):
            return Completed(3, "inactive\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "VICI_SOCKET_PATHS", sockets)
    payload: dict[str, object] = {}

    assert privileged._stop_services_and_cleanup_vici(payload, run_command=fake_run)
    assert not any(path.exists() for path in sockets)
    assert payload["vici_recovery_deleted_paths"] == [str(path) for path in sockets]
    assert calls[0] == (
        "systemctl",
        "stop",
        "strongswan.service",
        "strongswan-starter.service",
    )


def test_vici_recovery_restarts_service_then_selects_fedora_uri(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running = {"value": False}
    recovered = {"value": False}
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args[:2] == ("systemctl", "list-unit-files"):
            service = spec.args[2]
            output = f"{service} enabled\n" if service == "strongswan.service" else ""
            return Completed(0, output)
        if spec.args[:2] == ("systemctl", "is-active"):
            if spec.args[2] == "strongswan.service" and running["value"]:
                return Completed(0, "active\n")
            return Completed(3, "inactive\n")
        if spec.args == ("systemctl", "disable", "--now", "strongswan-starter.service"):
            return Completed(0, "")
        if spec.args == ("systemctl", "enable", "--now", "strongswan.service"):
            running["value"] = True
            return Completed(0, "")
        if spec.args == (
            "systemctl",
            "stop",
            "strongswan.service",
            "strongswan-starter.service",
        ):
            running["value"] = False
            return Completed(0, "")
        if spec.args == ("systemctl", "start", "strongswan.service"):
            running["value"] = True
            recovered["value"] = True
            return Completed(0, "")
        if spec.args == ("ss", "-lx"):
            output = "u_str LISTEN 0 5 /run/strongswan/charon.vici 123 * 0\n"
            return Completed(0, output)
        if _is_swanctl_command(spec.args, "--list-conns"):
            return Completed(0 if recovered["value"] else 1, stderr="No such file or directory")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "command_v", lambda name: "/usr/bin/swanctl")
    monkeypatch.setattr(commands, "resolve_swanctl_path", lambda: "/usr/bin/swanctl")
    monkeypatch.setattr(privileged, "VICI_WAIT_ATTEMPTS", 1)

    payload = privileged.strongswan_preflight(
        run_command=fake_run,
        socket_exists=lambda path: recovered["value"]
        and path == commands.FEDORA_VICI_SOCKET_PATH,
        sleep=lambda seconds: None,
    )

    stop_call = (
        "systemctl",
        "stop",
        "strongswan.service",
        "strongswan-starter.service",
    )
    start_call = ("systemctl", "start", "strongswan.service")
    assert calls.index(stop_call) < calls.index(start_call)
    assert payload["vici_recovery_attempted"] is True
    assert payload["selected_vici_uri"] == commands.FEDORA_VICI_URI
    assert payload["swanctl_list_conns_ok"] is True


def test_swanctl_diagnostics_reports_loaded_connection_after_vici(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    profile_path = tmp_path / "conf.d" / f"gic-{profile_id}.conf"
    profile_path.parent.mkdir()
    profile_path.write_text("connections {}\n", encoding="utf-8")

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
        lambda **kwargs: {
            "selected_strongswan_service": "strongswan.service",
            "detected_strongswan_service": "strongswan.service",
            "strongswan_service_state": "active",
            "strongswan_starter_active": False,
            "strongswan_starter_disabled": False,
            "vici_socket_available": True,
            "vici_usable": True,
            "selected_vici_uri": commands.FEDORA_VICI_URI,
            "vici_socket_path": "/run/charon.vici",
            "run_charon_vici_exists": True,
            "var_run_charon_vici_exists": False,
        },
    )

    payload = privileged.swanctl_diagnostics(profile_id=profile_id)

    assert payload["generated_connection_loaded"] is True
    assert payload["selected_strongswan_service"] == "strongswan.service"
    assert payload["vici_socket_path"] == "/run/charon.vici"
    assert payload["selected_vici_uri"] == commands.FEDORA_VICI_URI
    assert payload["profile_file_path"] == str(profile_path)
    assert payload["profile_file_exists"] is True
    assert payload["list_conns_returncode"] == 0
    assert payload["list_conns_stderr"] == ""
    assert f"gic-{profile_id}-child" in payload["list_conns_stdout"]

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.models import ConnectionStatus, VpnProfile
from gic_ipsec_client.backend.strongswan import StrongSwanBackend
from gic_ipsec_client.backend.swanctl_paths import SwanctlLayout
from gic_ipsec_client.backend.validators import ProfileValidationError
from gic_ipsec_client.main import main


def _is_swanctl_command(args: tuple[str, ...] | list[str], *tail: str) -> bool:
    return Path(args[0]).name == "swanctl" and tuple(args[1:]) == tail


def test_commands_are_argument_arrays_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commands,
        "resolve_helper_path",
        lambda: "/usr/libexec/gic-ipsec-client/gic-ipsec-helper",
    )
    specs = [
        commands.swanctl_load_all(),
        commands.swanctl_initiate("gic-child"),
        commands.swanctl_terminate("gic-conn"),
        commands.swanctl_list_sas(),
        commands.swanctl_list_conns(),
        commands.journalctl_logs(),
        commands.build_pkexec_helper_command("load-profile"),
    ]

    for spec in specs:
        kwargs = spec.as_subprocess_kwargs()
        assert isinstance(kwargs["args"], list)
        assert kwargs["shell"] is False
        assert all(isinstance(arg, str) for arg in kwargs["args"])


def test_run_command_passes_shell_false(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    class Completed:
        stdout = "ok"
        stderr = ""
        returncode = 0

    def fake_run(**kwargs: object) -> Completed:
        observed.update(kwargs)
        return Completed()

    monkeypatch.setattr(commands.subprocess, "run", fake_run)
    commands.run_command(commands.swanctl_load_all())

    assert observed["shell"] is False
    assert _is_swanctl_command(observed["args"], "--load-all")


def test_runtime_command_timeouts_are_bounded() -> None:
    assert commands.systemctl_is_active("strongswan-starter.service").timeout_seconds == 15
    assert commands.systemctl_start("strongswan-starter.service").timeout_seconds == 15
    assert commands.swanctl_load_all().timeout_seconds == 20
    assert commands.swanctl_initiate("gic-child").timeout_seconds == 60
    assert commands.swanctl_list_sas().timeout_seconds == 15
    assert commands.journalctl_logs().timeout_seconds == 10


def test_swanctl_resolution_prefers_path_then_fedora_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fallback = tmp_path / "usr" / "bin" / "swanctl"
    fallback.parent.mkdir(parents=True)
    fallback.write_text("#!/bin/sh\n", encoding="utf-8")
    fallback.chmod(0o755)
    monkeypatch.setattr(commands, "SWANCTL_FALLBACK_PATHS", (fallback,))

    monkeypatch.setattr(commands.shutil, "which", lambda name: "/custom/bin/swanctl")
    assert commands.resolve_swanctl_path() == "/custom/bin/swanctl"

    monkeypatch.setattr(commands.shutil, "which", lambda name: None)
    assert commands.resolve_swanctl_path() == str(fallback)


def test_installed_fedora_layout_resolves_libexec_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed_helper = Path("/usr/libexec/gic-ipsec-client/gic-ipsec-helper")
    monkeypatch.delenv(commands.HELPER_ENV_VAR, raising=False)
    monkeypatch.setattr(commands, "development_helper_path_allowed", lambda: False)
    monkeypatch.setattr(
        commands,
        "_is_executable_file",
        lambda path: path == installed_helper,
    )

    assert commands.resolve_helper_path() == str(installed_helper)


def test_development_venv_resolves_helper_from_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dev_helper = Path("/home/nick/project/.venv/bin/gic-ipsec-helper")
    monkeypatch.delenv(commands.HELPER_ENV_VAR, raising=False)
    monkeypatch.setattr(commands, "HELPER_FALLBACK_PATHS", ())
    monkeypatch.setattr(commands, "development_helper_path_allowed", lambda: True)
    monkeypatch.setattr(
        commands,
        "command_v",
        lambda name: str(dev_helper) if name == "gic-ipsec-helper" else "",
    )
    monkeypatch.setattr(commands, "_is_executable_file", lambda path: path == dev_helper)

    assert commands.resolve_helper_path() == str(dev_helper)


def test_pkexec_command_uses_absolute_helper_path(monkeypatch: pytest.MonkeyPatch) -> None:
    helper_path = "/usr/libexec/gic-ipsec-client/gic-ipsec-helper"
    monkeypatch.setattr(commands, "resolve_helper_path", lambda: helper_path)

    spec = commands.build_pkexec_helper_command("connect-profile", "--profile-uuid", "uuid")

    assert spec.args == ("pkexec", helper_path, "connect-profile", "--profile-uuid", "uuid")
    assert Path(spec.args[1]).is_absolute()


def test_missing_helper_error_is_user_facing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(commands, "resolve_helper_path", lambda: None)

    with pytest.raises(FileNotFoundError, match=commands.HELPER_NOT_FOUND_MESSAGE):
        commands.build_pkexec_helper_command("load-profile")


def test_helper_installation_diagnostics_reports_polkit_match(tmp_path: Path) -> None:
    helper = tmp_path / "usr" / "libexec" / "gic-ipsec-client" / "gic-ipsec-helper"
    helper.parent.mkdir(parents=True)
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o755)
    policy = tmp_path / "com.gicipsec.client.policy"
    policy.write_text(
        f"""<?xml version="1.0" encoding="UTF-8"?>
<policyconfig>
  <action id="com.gicipsec.client.helper">
    <annotate key="{commands.POLKIT_EXEC_PATH_KEY}">{helper}</annotate>
  </action>
</policyconfig>
""",
        encoding="utf-8",
    )

    payload = commands.helper_installation_diagnostics(
        helper_path=str(helper),
        policy_path=policy,
    )

    assert payload["resolved_helper_path"] == str(helper)
    assert payload["helper_exists"] is True
    assert payload["helper_executable"] is True
    assert payload["polkit_policy_file_path"] == str(policy)
    assert payload["polkit_exec_path"] == str(helper)
    assert payload["helper_matches_polkit_exec_path"] is True


def test_profile_deletion_only_deletes_owned_uuid_files(tmp_path: Path) -> None:
    profile_id = str(uuid4())
    layout = SwanctlLayout(root=tmp_path, source="test", use_secrets_dir=True)
    layout.conf_dir.mkdir()
    layout.secrets_dir.mkdir()
    conf_file = layout.profile_config_path(profile_id)
    secrets_file = layout.profile_secrets_path(profile_id)
    outside_file = tmp_path / "outside.conf"
    conf_file.write_text("config", encoding="utf-8")
    secrets_file.write_text("secret", encoding="utf-8")
    outside_file.write_text("keep", encoding="utf-8")

    deleted = commands.delete_profile_files(profile_id, layout=layout)

    assert set(deleted) == {conf_file, secrets_file}
    assert not conf_file.exists()
    assert not secrets_file.exists()
    assert outside_file.exists()


def test_profile_deletion_rejects_path_injection(tmp_path: Path) -> None:
    with pytest.raises(ProfileValidationError):
        commands.delete_profile_files(
            "../not-a-uuid",
            layout=SwanctlLayout(root=tmp_path, source="test"),
        )


def test_backend_vici_commands_use_privileged_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    class Completed:
        stdout = "Disconnected"
        stderr = ""
        returncode = 0

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        return Completed()

    profile = VpnProfile(
        id="00000000-0000-4000-8000-000000000001",
        profile_name="Helper VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        username="alice",
        eap_identity="alice",
        psk="psk",
        password="password",
        remote_routes=["192.168.20.0/24"],
    )
    monkeypatch.setattr(commands, "run_command", fake_run)
    monkeypatch.setattr(
        commands,
        "resolve_helper_path",
        lambda: "/usr/libexec/gic-ipsec-client/gic-ipsec-helper",
    )

    backend = StrongSwanBackend()
    backend.load_profile()
    backend.connect_profile(profile)
    backend.disconnect_profile(profile)
    status = backend.status_profile(profile)

    assert status == ConnectionStatus.DISCONNECTED
    assert calls
    assert all(call[0] == "pkexec" for call in calls)
    assert not any(call[0] == "swanctl" for call in calls)
    assert all(call[1] == "/usr/libexec/gic-ipsec-client/gic-ipsec-helper" for call in calls)


def test_gui_entrypoint_version_is_headless(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["gic-ipsec-client", "--version"]) == 0

    output = capsys.readouterr().out

    assert output.startswith("gic-ipsec-client ")

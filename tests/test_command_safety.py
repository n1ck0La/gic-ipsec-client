from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.models import ConnectionStatus, VpnProfile
from gic_ipsec_client.backend.strongswan import StrongSwanBackend
from gic_ipsec_client.backend.swanctl_paths import SwanctlLayout
from gic_ipsec_client.backend.validators import ProfileValidationError


def test_commands_are_argument_arrays_without_shell() -> None:
    specs = [
        commands.swanctl_load_all(),
        commands.swanctl_initiate("see-ipsec-child"),
        commands.swanctl_terminate("see-ipsec-conn"),
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
    assert observed["args"] == ["swanctl", "--load-all"]


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

    backend = StrongSwanBackend()
    backend.load_profile()
    backend.connect_profile(profile)
    backend.disconnect_profile(profile)
    status = backend.status_profile(profile)

    assert status == ConnectionStatus.DISCONNECTED
    assert calls
    assert all(call[0] == "pkexec" for call in calls)
    assert not any(call[0] == "swanctl" for call in calls)

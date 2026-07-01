from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.validators import ProfileValidationError


def test_commands_are_argument_arrays_without_shell() -> None:
    specs = [
        commands.swanctl_load_all(),
        commands.swanctl_initiate("gic-child"),
        commands.swanctl_terminate("gic-conn"),
        commands.swanctl_list_sas(),
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
    conf_root = tmp_path / "conf"
    secrets_root = tmp_path / "secrets"
    conf_root.mkdir()
    secrets_root.mkdir()
    conf_file = conf_root / f"{profile_id}.conf"
    secrets_file = secrets_root / f"{profile_id}.secrets"
    outside_file = tmp_path / "outside.conf"
    conf_file.write_text("config", encoding="utf-8")
    secrets_file.write_text("secret", encoding="utf-8")
    outside_file.write_text("keep", encoding="utf-8")

    deleted = commands.delete_profile_files(
        profile_id,
        conf_root=conf_root,
        secrets_root=secrets_root,
    )

    assert set(deleted) == {conf_file, secrets_file}
    assert not conf_file.exists()
    assert not secrets_file.exists()
    assert outside_file.exists()


def test_profile_deletion_rejects_path_injection(tmp_path: Path) -> None:
    with pytest.raises(ProfileValidationError):
        commands.delete_profile_files(
            "../not-a-uuid",
            conf_root=tmp_path / "conf",
            secrets_root=tmp_path / "secrets",
        )

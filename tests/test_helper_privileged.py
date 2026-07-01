from __future__ import annotations

import pytest

from gic_ipsec_client.backend import commands
from gic_ipsec_client.helper import privileged


class Completed:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_initiate_is_blocked_when_child_is_not_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    profile_id = "00000000-0000-4000-8000-000000000001"
    calls: list[tuple[str, ...]] = []

    def fake_run(spec: commands.CommandSpec) -> Completed:
        calls.append(spec.args)
        if spec.args == ("swanctl", "--load-all"):
            return Completed(0, "loaded")
        if spec.args == ("swanctl", "--list-conns"):
            return Completed(0, "other-connection:\n  children:\n    other-child:\n")
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(commands, "run_command", fake_run)

    with pytest.raises(
        privileged.HelperError,
        match="Profile was rendered but strongSwan did not load it",
    ):
        privileged.connect_profile(profile_id)

    assert ("swanctl", "--initiate", "--child", f"gic-{profile_id}-child") not in calls


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
        if spec.args == ("swanctl", "--terminate", "--ike", f"gic-{profile_id}"):
            calls.append("terminate-sa")
            return Completed(0)
        raise AssertionError(f"unexpected command: {spec.args}")

    monkeypatch.setattr(privileged, "revert_resolved_dns", fake_revert)
    monkeypatch.setattr(privileged, "flush_resolved_dns_caches", fake_flush)
    monkeypatch.setattr(privileged, "verify_resolved_dns_after_disconnect", fake_verify)
    monkeypatch.setattr(commands, "run_command", fake_run)

    assert privileged.disconnect_profile(profile_id) == 0
    assert calls == ["restore-dns", "terminate-sa", "flush-dns", "verify-dns"]

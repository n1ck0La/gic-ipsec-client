from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.diagnostics import (
    DiagnosticReport,
    check_dependencies,
    collect_diagnostics,
    export_debug_bundle,
    install_hint,
)
from gic_ipsec_client.backend.models import ConnectionStatus, VpnProfile
from gic_ipsec_client.backend.renderer import RenderedProfile, render_profile_files
from gic_ipsec_client.backend.validators import validate_profile


@dataclass(slots=True)
class BackendResult:
    ok: bool
    message: str
    stdout: str = ""
    stderr: str = ""


class StrongSwanBackend:
    """Thin orchestration layer around strongSwan `swanctl` commands."""

    def check_dependencies(self) -> dict[str, object]:
        return check_dependencies()

    def install_hint(self) -> str:
        return install_hint()

    def render_profile(self, profile: VpnProfile) -> RenderedProfile:
        validate_profile(profile)
        return render_profile_files(profile)

    def load_profile(self) -> BackendResult:
        return self._run(commands.swanctl_load_all(), "Loaded strongSwan configuration.")

    def connect_profile(self, profile: VpnProfile) -> BackendResult:
        validate_profile(profile)
        return self._run(commands.swanctl_initiate(profile.child_name), "Connection initiated.")

    def disconnect_profile(self, profile: VpnProfile) -> BackendResult:
        return self._run(
            commands.swanctl_terminate(profile.connection_name),
            "Connection terminated.",
        )

    def status_profile(self, profile: VpnProfile) -> ConnectionStatus:
        completed = commands.run_command(commands.swanctl_list_sas())
        output = (completed.stdout or "") + (completed.stderr or "")
        if completed.returncode != 0:
            return ConnectionStatus.FAILED
        if profile.connection_name in output:
            return ConnectionStatus.CONNECTED
        return ConnectionStatus.DISCONNECTED

    def delete_profile(self, profile_id: str) -> list[Path]:
        return commands.delete_profile_files(profile_id)

    def collect_logs(self) -> BackendResult:
        return self._run(commands.journalctl_logs(), "Collected strongSwan logs.")

    def collect_diagnostics(
        self,
        *,
        profile: VpnProfile | None = None,
        privacy_mode: bool = False,
    ) -> DiagnosticReport:
        return collect_diagnostics(profile=profile, privacy_mode=privacy_mode)

    def export_debug_bundle(
        self,
        output_dir: Path,
        *,
        profile: VpnProfile | None = None,
        privacy_mode: bool = False,
    ) -> Path:
        return export_debug_bundle(output_dir, profile=profile, privacy_mode=privacy_mode)

    @staticmethod
    def _run(command: commands.CommandSpec, success_message: str) -> BackendResult:
        completed = commands.run_command(command)
        output = (completed.stdout or "").strip()
        error = (completed.stderr or "").strip()
        return BackendResult(
            ok=completed.returncode == 0,
            message=success_message if completed.returncode == 0 else error or output,
            stdout=output,
            stderr=error,
        )

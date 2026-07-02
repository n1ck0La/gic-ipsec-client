from __future__ import annotations

import json
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

    def load_profile(self, *, config_root_override: str = "") -> BackendResult:
        return self._run_helper(
            "load-profile",
            "Loaded strongSwan configuration.",
            *self._config_root_args(config_root_override),
        )

    def connect_profile(
        self,
        profile: VpnProfile,
        *,
        config_root_override: str = "",
    ) -> BackendResult:
        validate_profile(profile)
        return self._run_helper(
            "connect-profile",
            "Connection initiated.",
            "--profile-uuid",
            profile.id,
            *self._config_root_args(config_root_override),
        )

    def disconnect_profile(
        self,
        profile: VpnProfile,
        *,
        config_root_override: str = "",
    ) -> BackendResult:
        return self._run_helper(
            "disconnect-profile",
            "Connection terminated.",
            "--profile-uuid",
            profile.id,
            *self._config_root_args(config_root_override),
        )

    def status_profile(
        self,
        profile: VpnProfile,
        *,
        config_root_override: str = "",
    ) -> ConnectionStatus:
        try:
            completed = commands.run_command(
                commands.build_pkexec_helper_command(
                    "status-profile",
                    "--profile-uuid",
                    profile.id,
                    *self._config_root_args(config_root_override),
                )
            )
        except FileNotFoundError:
            return ConnectionStatus.FAILED
        output = ((completed.stdout or "") + (completed.stderr or "")).strip()
        if completed.returncode != 0:
            return ConnectionStatus.FAILED
        if output == ConnectionStatus.CONNECTED:
            return ConnectionStatus.CONNECTED
        return ConnectionStatus.DISCONNECTED

    def delete_profile(self, profile_id: str, *, config_root_override: str = "") -> list[Path]:
        try:
            completed = commands.run_command(
                commands.build_pkexec_helper_command(
                    "delete-profile",
                    "--profile-uuid",
                    profile_id,
                    *self._config_root_args(config_root_override),
                )
            )
        except FileNotFoundError:
            return []
        if completed.returncode != 0:
            return []
        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            return []
        deleted = payload.get("deleted", [])
        if not isinstance(deleted, list):
            return []
        return [Path(str(path)) for path in deleted]

    def collect_logs(self) -> BackendResult:
        return self._run(commands.journalctl_logs(), "Collected strongSwan logs.")

    def collect_diagnostics(
        self,
        *,
        profile: VpnProfile | None = None,
        privacy_mode: bool = False,
        config_root_override: str = "",
    ) -> DiagnosticReport:
        return collect_diagnostics(
            profile=profile,
            privacy_mode=privacy_mode,
            config_root_override=config_root_override,
        )

    def export_debug_bundle(
        self,
        output_dir: Path,
        *,
        profile: VpnProfile | None = None,
        privacy_mode: bool = False,
        config_root_override: str = "",
    ) -> Path:
        return export_debug_bundle(
            output_dir,
            profile=profile,
            privacy_mode=privacy_mode,
            config_root_override=config_root_override,
        )

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

    @staticmethod
    def _run_helper(subcommand: str, success_message: str, *args: str) -> BackendResult:
        try:
            command = commands.build_pkexec_helper_command(subcommand, *args)
        except FileNotFoundError as exc:
            return BackendResult(ok=False, message=str(exc), stderr=str(exc))
        return StrongSwanBackend._run(
            command,
            success_message,
        )

    @staticmethod
    def _config_root_args(config_root_override: str) -> tuple[str, ...]:
        return ("--config-root", config_root_override) if config_root_override else ()

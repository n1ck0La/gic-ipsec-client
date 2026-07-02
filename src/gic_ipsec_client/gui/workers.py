from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from gic_ipsec_client.backend import commands
from gic_ipsec_client.backend.models import VpnProfile
from gic_ipsec_client.backend.strongswan import StrongSwanBackend


@dataclass(frozen=True, slots=True)
class HelperResult:
    subcommand: str
    returncode: int
    output: str


@dataclass(frozen=True, slots=True)
class ConnectResult:
    render: HelperResult
    connect: HelperResult | None

    @property
    def ok(self) -> bool:
        return self.render.returncode == 0 and bool(
            self.connect and self.connect.returncode == 0
        )

    @property
    def output(self) -> str:
        return "\n".join(
            result.output
            for result in (self.render, self.connect)
            if result is not None and result.output
        )


HelperRunner = Callable[[str, tuple[str, ...]], HelperResult]
BackendFactory = Callable[[], StrongSwanBackend]


def run_helper_command(subcommand: str, args: tuple[str, ...]) -> HelperResult:
    try:
        command = commands.build_pkexec_helper_command(subcommand, *args)
        completed = commands.run_command(command)
    except FileNotFoundError as exc:
        return HelperResult(subcommand=subcommand, returncode=1, output=str(exc))
    except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        return HelperResult(subcommand=subcommand, returncode=1, output=f"Helper failed: {exc}")
    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    return HelperResult(subcommand=subcommand, returncode=completed.returncode, output=output)


class HelperWorker(QObject):
    progress = Signal(str)
    failed = Signal(str)
    finished = Signal(object)

    def __init__(
        self,
        subcommand: str,
        args: tuple[str, ...],
        *,
        progress_message: str,
        helper_runner: HelperRunner | None = None,
    ) -> None:
        super().__init__()
        self._subcommand = subcommand
        self._args = args
        self._progress_message = progress_message
        self._helper_runner = helper_runner or run_helper_command

    def run(self) -> None:
        try:
            self.progress.emit(self._progress_message)
            self.finished.emit(self._helper_runner(self._subcommand, self._args))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class ConnectWorker(QObject):
    progress = Signal(str)
    failed = Signal(str)
    finished = Signal(object)

    def __init__(
        self,
        *,
        request_path: str,
        profile_id: str,
        config_args: tuple[str, ...],
        helper_runner: HelperRunner | None = None,
    ) -> None:
        super().__init__()
        self._request_path = request_path
        self._profile_id = profile_id
        self._config_args = config_args
        self._helper_runner = helper_runner or run_helper_command

    def run(self) -> None:
        try:
            self.progress.emit("Rendering profile...")
            render = self._helper_runner(
                "render-profile",
                ("--request", self._request_path, *self._config_args),
            )
            if render.returncode != 0:
                self.finished.emit(ConnectResult(render=render, connect=None))
                return
            self.progress.emit("Starting connection...")
            connect = self._helper_runner(
                "connect-profile",
                ("--profile-uuid", self._profile_id, *self._config_args),
            )
            self.finished.emit(ConnectResult(render=render, connect=connect))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class DiagnosticsWorker(QObject):
    progress = Signal(str)
    failed = Signal(str)
    finished = Signal(object)

    def __init__(
        self,
        *,
        profile: VpnProfile | None,
        config_root_override: str,
        backend_factory: BackendFactory = StrongSwanBackend,
    ) -> None:
        super().__init__()
        self._profile = profile
        self._config_root_override = config_root_override
        self._backend_factory = backend_factory

    def run(self) -> None:
        try:
            self.progress.emit("Collecting diagnostics...")
            report = self._backend_factory().collect_diagnostics(
                profile=self._profile,
                config_root_override=self._config_root_override,
            )
            self.finished.emit(report)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class DebugBundleWorker(QObject):
    progress = Signal(str)
    failed = Signal(str)
    finished = Signal(object)

    def __init__(
        self,
        *,
        output_dir: Path,
        profile: VpnProfile | None,
        config_root_override: str,
        backend_factory: BackendFactory = StrongSwanBackend,
    ) -> None:
        super().__init__()
        self._output_dir = output_dir
        self._profile = profile
        self._config_root_override = config_root_override
        self._backend_factory = backend_factory

    def run(self) -> None:
        try:
            self.progress.emit("Exporting sanitized debug bundle...")
            archive = self._backend_factory().export_debug_bundle(
                self._output_dir,
                profile=self._profile,
                config_root_override=self._config_root_override,
            )
            self.finished.emit(archive)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))

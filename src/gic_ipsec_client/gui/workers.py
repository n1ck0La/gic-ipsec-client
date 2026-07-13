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
        helper_runner: HelperRunner | None = None,
    ) -> None:
        super().__init__()
        self._request_path = request_path
        self._profile_id = profile_id
        self._helper_runner = helper_runner or run_helper_command

    def run(self) -> None:
        try:
            self.progress.emit("Starting connection...")
            self.finished.emit(self._helper_runner("connect", (self._profile_id,)))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
        finally:
            try:
                Path(self._request_path).unlink(missing_ok=True)
            except OSError:
                pass


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

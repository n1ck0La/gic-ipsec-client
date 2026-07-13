from __future__ import annotations

import inspect
import logging
import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from gic_ipsec_client import __version__
from gic_ipsec_client.backend.models import VpnProfile
from gic_ipsec_client.gui import workers
from gic_ipsec_client.gui.log_viewer import SignalLogHandler
from gic_ipsec_client.gui.main_window import MainWindow
from gic_ipsec_client.gui.workers import ConnectWorker, HelperResult


@pytest.fixture
def app() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture
def profile() -> VpnProfile:
    return VpnProfile(
        id="00000000-0000-4000-8000-000000000001",
        profile_name="Thread Test VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        username="alice",
        eap_identity="alice",
        psk="psk",
        password="password",
        remote_routes=["10.44.0.0/16"],
    )


def _wait_until(
    app: QApplication,
    predicate: object,
    *,
    timeout_seconds: float = 2.0,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        app.processEvents()
        if callable(predicate) and predicate():
            return True
        time.sleep(0.01)
    return False


def _window(
    app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: VpnProfile,
) -> MainWindow:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
    window = MainWindow()
    window.profiles[profile.id] = profile
    window._refresh_profile_list()
    window.profile_list.setCurrentRow(0)
    app.processEvents()
    return window


def test_connect_worker_emits_progress_signals() -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    def fake_helper(subcommand: str, args: tuple[str, ...]) -> HelperResult:
        calls.append((subcommand, args))
        return HelperResult(subcommand=subcommand, returncode=0, output=f"{subcommand} ok")

    worker = ConnectWorker(
        request_path="/tmp/request.json",
        profile_id="00000000-0000-4000-8000-000000000001",
        helper_runner=fake_helper,
    )
    progress: list[str] = []
    results: list[object] = []
    worker.progress.connect(progress.append)
    worker.finished.connect(results.append)

    worker.run()

    assert progress == ["Starting connection..."]
    assert calls == [("connect", ("00000000-0000-4000-8000-000000000001",))]
    assert results


def test_connect_worker_has_no_widget_or_main_window_access() -> None:
    module_source = inspect.getsource(workers)
    worker_source = inspect.getsource(ConnectWorker)

    assert "QtWidgets" not in module_source
    for banned in (
        "MainWindow",
        "QWidget",
        "QTextEdit",
        "QPlainTextEdit",
        "QLabel",
        "QPushButton",
        "QMessageBox",
        "appendPlainText",
        "setPlainText",
        "append_log",
    ):
        assert banned not in worker_source


def test_connect_starts_worker_and_returns_immediately(
    app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: VpnProfile,
) -> None:
    def slow_helper(subcommand: str, args: tuple[str, ...]) -> HelperResult:
        time.sleep(0.25)
        return HelperResult(subcommand=subcommand, returncode=0, output=f"{subcommand} ok")

    monkeypatch.setattr(workers, "run_helper_command", slow_helper)
    window = _window(app, monkeypatch, tmp_path, profile)

    started = time.monotonic()
    window.connect_profile()
    elapsed = time.monotonic() - started

    assert elapsed < 0.15
    assert window._connect_thread is not None
    assert window._connect_worker is not None
    assert _wait_until(app, lambda: window._connect_thread is None, timeout_seconds=2.0)
    window.close()


def test_fake_long_running_connect_does_not_freeze_event_loop(
    app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: VpnProfile,
) -> None:
    def slow_helper(subcommand: str, args: tuple[str, ...]) -> HelperResult:
        time.sleep(0.25)
        return HelperResult(subcommand=subcommand, returncode=0, output=f"{subcommand} ok")

    monkeypatch.setattr(workers, "run_helper_command", slow_helper)
    window = _window(app, monkeypatch, tmp_path, profile)
    timer_fired: list[bool] = []

    QTimer.singleShot(20, lambda: timer_fired.append(True))
    window.connect_profile()

    assert _wait_until(app, lambda: bool(timer_fired), timeout_seconds=0.5)
    assert _wait_until(app, lambda: window._connect_thread is None, timeout_seconds=2.0)
    window.close()


def test_repeated_connect_click_does_not_start_second_helper(
    app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: VpnProfile,
) -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    def slow_helper(subcommand: str, args: tuple[str, ...]) -> HelperResult:
        calls.append((subcommand, args))
        time.sleep(0.25)
        return HelperResult(subcommand=subcommand, returncode=0, output="connected")

    monkeypatch.setattr(workers, "run_helper_command", slow_helper)
    window = _window(app, monkeypatch, tmp_path, profile)

    window.connect_profile()
    window.connect_profile()

    assert _wait_until(app, lambda: window._connect_thread is None, timeout_seconds=2.0)
    assert calls == [("connect", (profile.id,))]
    window.close()


def test_qplaintextedit_logging_uses_signal_handler_only() -> None:
    handler = SignalLogHandler()
    messages: list[str] = []
    handler.emitter.message.connect(messages.append)
    record = logging.LogRecord(
        name="gic",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello from worker",
        args=(),
        exc_info=None,
    )

    handler.emit(record)

    assert messages == ["hello from worker"]
    source = inspect.getsource(SignalLogHandler.emit)
    assert "appendPlainText" not in source
    assert "setPlainText" not in source


def test_about_dialog_shows_package_version(
    app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: VpnProfile,
) -> None:
    messages: list[tuple[str, str]] = []
    window = _window(app, monkeypatch, tmp_path, profile)

    def fake_information(parent: object, title: str, text: str) -> None:
        messages.append((title, text))

    monkeypatch.setattr(QMessageBox, "information", fake_information)

    window.show_about()

    assert messages == [
        (
            "About GIC IPsec Client",
            f"GIC IPsec Client {__version__}\n\nstrongSwan swanctl/VICI desktop client.",
        )
    ]
    window.close()

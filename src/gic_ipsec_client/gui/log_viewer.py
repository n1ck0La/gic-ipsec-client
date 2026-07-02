from __future__ import annotations

import logging
import os

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import QPlainTextEdit, QWidget

from gic_ipsec_client.backend.diagnostics import redact_text


def _assert_gui_thread() -> None:
    if os.environ.get("GIC_DEBUG_QT_THREADS") != "1":
        return
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is not None:
        assert QThread.currentThread() == app.thread()


class LogSignalEmitter(QObject):
    message = Signal(str)


class SignalLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.emitter = LogSignalEmitter()

    def emit(self, record: logging.LogRecord) -> None:
        self.emitter.message.emit(self.format(record))


class LogViewer(QPlainTextEdit):
    append_requested = Signal(str)
    replace_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.append_requested.connect(self.append_log)
        self.replace_requested.connect(self.set_log_text)

    def append_log(self, message: str) -> None:
        _assert_gui_thread()
        self.appendPlainText(redact_text(message).rstrip())

    def set_log_text(self, message: str) -> None:
        _assert_gui_thread()
        self.setPlainText(redact_text(message).rstrip())

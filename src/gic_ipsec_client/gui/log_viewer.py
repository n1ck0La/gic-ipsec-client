from __future__ import annotations

from PySide6.QtWidgets import QPlainTextEdit, QWidget

from gic_ipsec_client.backend.diagnostics import redact_text


class LogViewer(QPlainTextEdit):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

    def append_log(self, message: str) -> None:
        self.appendPlainText(redact_text(message).rstrip())

    def set_log_text(self, message: str) -> None:
        self.setPlainText(redact_text(message).rstrip())

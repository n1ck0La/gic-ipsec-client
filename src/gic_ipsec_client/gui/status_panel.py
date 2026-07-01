from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from gic_ipsec_client.backend.models import ConnectionStatus


class StatusPanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._status = QLabel(ConnectionStatus.DISCONNECTED.value)
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setObjectName("statusLabel")
        layout = QVBoxLayout(self)
        layout.addWidget(self._status)
        self.set_status(ConnectionStatus.DISCONNECTED)

    def set_status(self, status: ConnectionStatus) -> None:
        self._status.setText(status.value)
        colors = {
            ConnectionStatus.DISCONNECTED: "#777777",
            ConnectionStatus.CONNECTING: "#9a6b00",
            ConnectionStatus.CONNECTED: "#0a7a3d",
            ConnectionStatus.FAILED: "#b00020",
        }
        self._status.setStyleSheet(f"font-weight: 700; color: {colors[status]};")

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gic_ipsec_client.backend.models import (
    DEFAULT_ESP_PROPOSALS,
    DEFAULT_IKE_PROPOSALS,
    VpnProfile,
    fortigate_default_profile,
)
from gic_ipsec_client.backend.renderer import render_profile_config, render_secret_config
from gic_ipsec_client.backend.resolved import FORTIGATE_ROUTE_PRESETS
from gic_ipsec_client.backend.validators import ProfileValidationError, validate_profile


def _split_lines(value: str) -> list[str]:
    return [item.strip() for raw in value.splitlines() for item in raw.split(",") if item.strip()]


def _join_lines(values: list[str]) -> str:
    return "\n".join(values)


class ProfileEditor(QDialog):
    def __init__(self, profile: VpnProfile | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("VPN Profile")
        self._profile_id = profile.id if profile else ""

        self.profile_name = QLineEdit()
        self.gateway = QLineEdit()
        self.remote_id = QLineEdit()
        self.local_id = QLineEdit()
        self.username = QLineEdit()
        self.eap_identity = QLineEdit()
        self.psk = QLineEdit()
        self.psk.setEchoMode(QLineEdit.EchoMode.Password)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.transport = QComboBox()
        self.transport.addItems(["udp", "auto", "tcp"])
        self.ike_port = QSpinBox()
        self.ike_port.setRange(1, 65535)
        self.ike_port.setValue(500)
        self.request_virtual_ip = QCheckBox()
        self.tunnel_mode = QComboBox()
        self.tunnel_mode.addItem("Split tunnel: internal routes only", True)
        self.tunnel_mode.addItem("Full tunnel: all traffic through VPN", False)
        self.tunnel_mode.currentIndexChanged.connect(self._update_tunnel_note)
        self.remote_routes = QPlainTextEdit()
        self.remote_routes.setFixedHeight(70)
        self.route_preset = QPushButton("Add FortiGate routes")
        self.route_preset.clicked.connect(self._add_fortigate_routes)
        self.full_tunnel_note = QLabel(
            "Full tunnel requires FortiGate policy from IPsec interface to WAN "
            "with NAT enabled. Create IPsec-to-WAN firewall policy with NAT enabled."
        )
        self.full_tunnel_note.setWordWrap(True)
        self.dns_servers = QPlainTextEdit()
        self.dns_servers.setFixedHeight(55)
        self.dns_search_domains = QPlainTextEdit()
        self.dns_search_domains.setFixedHeight(55)
        self.ike_proposals = QPlainTextEdit()
        self.ike_proposals.setFixedHeight(85)
        self.esp_proposals = QPlainTextEdit()
        self.esp_proposals.setFixedHeight(55)
        self.dpd_enabled = QCheckBox()
        self.notes = QPlainTextEdit()
        self.notes.setFixedHeight(70)
        self.secret_storage = QComboBox()
        self.secret_storage.addItem("Ask every time", "ask")
        self.secret_storage.addItem("Save secrets locally", "keyring")

        self._build_layout()
        self._load_profile(profile or fortigate_default_profile())

    def _build_layout(self) -> None:
        layout = QVBoxLayout(self)
        preset_row = QHBoxLayout()
        preset = QPushButton("FortiGate preset")
        preset.clicked.connect(lambda: self._load_profile(fortigate_default_profile()))
        test_render = QPushButton("Test profile render")
        test_render.clicked.connect(self._test_render)
        preset_row.addWidget(preset)
        preset_row.addWidget(test_render)
        preset_row.addStretch(1)
        layout.addLayout(preset_row)

        form = QFormLayout()
        form.addRow("Profile name", self.profile_name)
        form.addRow("Gateway", self.gateway)
        warning = QLabel(
            "FortiGate PSK+EAP commonly requires remote IKE ID = %any because "
            "the peer may authenticate as its resolved IP instead of the gateway FQDN."
        )
        warning.setWordWrap(True)
        form.addRow(warning)
        form.addRow("Username", self.username)
        form.addRow("EAP identity", self.eap_identity)
        form.addRow("PSK", self.psk)
        form.addRow("Password", self.password)
        form.addRow("Secret storage", self.secret_storage)
        layout.addLayout(form)

        advanced = QGroupBox("Advanced")
        advanced.setCheckable(True)
        advanced.setChecked(False)
        advanced_layout = QFormLayout(advanced)
        advanced_layout.addRow("Local ID", self.local_id)
        advanced_layout.addRow("Strict remote ID", self.remote_id)
        advanced_layout.addRow("Transport", self.transport)
        advanced_layout.addRow("IKE port", self.ike_port)
        advanced_layout.addRow("Request virtual IP", self.request_virtual_ip)
        advanced_layout.addRow("Tunnel mode", self.tunnel_mode)
        advanced_layout.addRow(self.full_tunnel_note)
        advanced_layout.addRow(self.route_preset)
        advanced_layout.addRow(QLabel("Remote routes"), self.remote_routes)
        advanced_layout.addRow(QLabel("DNS servers"), self.dns_servers)
        advanced_layout.addRow(QLabel("DNS search domains"), self.dns_search_domains)
        advanced_layout.addRow(QLabel("IKE proposals"), self.ike_proposals)
        advanced_layout.addRow(QLabel("ESP proposals"), self.esp_proposals)
        advanced_layout.addRow("DPD enabled", self.dpd_enabled)
        advanced_layout.addRow(QLabel("Notes"), self.notes)
        layout.addWidget(advanced)
        self._update_tunnel_note()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_if_valid)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_profile(self, profile: VpnProfile) -> None:
        if not self._profile_id:
            self._profile_id = profile.id
        self.profile_name.setText(profile.profile_name)
        self.gateway.setText(profile.gateway_fqdn_or_ip)
        self.remote_id.setText(profile.remote_id)
        self.local_id.setText(profile.local_id)
        self.username.setText(profile.username)
        self.eap_identity.setText(profile.eap_identity)
        self.psk.setText(profile.psk)
        self.password.setText(profile.password)
        self.transport.setCurrentText(profile.transport)
        self.ike_port.setValue(profile.ike_port)
        self.request_virtual_ip.setChecked(profile.request_virtual_ip)
        index = self.tunnel_mode.findData(profile.split_tunnel_enabled)
        self.tunnel_mode.setCurrentIndex(index if index >= 0 else 0)
        self._update_tunnel_note()
        self.remote_routes.setPlainText(_join_lines(profile.remote_routes))
        self.dns_servers.setPlainText(_join_lines(profile.dns_servers))
        self.dns_search_domains.setPlainText(_join_lines(profile.dns_search_domains))
        self.ike_proposals.setPlainText(
            _join_lines(profile.ike_proposals or list(DEFAULT_IKE_PROPOSALS))
        )
        self.esp_proposals.setPlainText(
            _join_lines(profile.esp_proposals or list(DEFAULT_ESP_PROPOSALS))
        )
        self.dpd_enabled.setChecked(profile.dpd_enabled)
        self.notes.setPlainText(profile.notes)
        self.secret_storage.setCurrentIndex(self.secret_storage.findData(profile.secret_storage))

    def profile(self) -> VpnProfile:
        return VpnProfile(
            id=self._profile_id,
            profile_name=self.profile_name.text().strip(),
            gateway_fqdn_or_ip=self.gateway.text().strip(),
            remote_id=self.remote_id.text().strip(),
            local_id=self.local_id.text().strip(),
            username=self.username.text().strip(),
            eap_identity=self.eap_identity.text().strip(),
            psk=self.psk.text(),
            password=self.password.text(),
            transport=self.transport.currentText(),  # type: ignore[arg-type]
            ike_port=self.ike_port.value(),
            request_virtual_ip=self.request_virtual_ip.isChecked(),
            split_tunnel_enabled=self.tunnel_mode.currentData() is True,
            remote_routes=_split_lines(self.remote_routes.toPlainText()),
            dns_servers=_split_lines(self.dns_servers.toPlainText()),
            dns_search_domains=_split_lines(self.dns_search_domains.toPlainText()),
            ike_proposals=_split_lines(self.ike_proposals.toPlainText()),
            esp_proposals=_split_lines(self.esp_proposals.toPlainText()),
            dpd_enabled=self.dpd_enabled.isChecked(),
            notes=self.notes.toPlainText().strip(),
            secret_storage=self.secret_storage.currentData(),
        )

    def _accept_if_valid(self) -> None:
        try:
            validate_profile(self.profile())
        except ProfileValidationError as exc:
            QMessageBox.warning(self, "Profile error", "\n".join(exc.errors))
            return
        self.accept()

    def _test_render(self) -> None:
        try:
            profile = self.profile()
            rendered = (
                render_profile_config(profile)
                + "\n"
                + render_secret_config(profile, debug=True)
            )
        except ProfileValidationError as exc:
            QMessageBox.warning(self, "Profile error", "\n".join(exc.errors))
            return
        box = QMessageBox(self)
        box.setWindowTitle("Rendered swanctl preview")
        box.setText("Profile renders successfully.")
        box.setDetailedText(rendered)
        box.setIcon(QMessageBox.Icon.Information)
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.exec()

    def _add_fortigate_routes(self) -> None:
        existing = _split_lines(self.remote_routes.toPlainText())
        merged = list(dict.fromkeys([*existing, *FORTIGATE_ROUTE_PRESETS]))
        self.remote_routes.setPlainText(_join_lines(merged))

    def _update_tunnel_note(self) -> None:
        full_tunnel = self.tunnel_mode.currentData() is False
        self.full_tunnel_note.setVisible(full_tunnel)

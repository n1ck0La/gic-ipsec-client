from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
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
        self.full_tunnel_note = QLabel(
            "Full tunnel requires FortiGate policy from IPsec interface to WAN "
            "with NAT enabled. Create IPsec-to-WAN firewall policy with NAT enabled."
        )
        self.full_tunnel_note.setWordWrap(True)
        self.dns_servers = QPlainTextEdit()
        self.dns_servers.setFixedHeight(55)
        self.dns_search_domains = QPlainTextEdit()
        self.dns_search_domains.setFixedHeight(55)
        self.dns_test_names = QPlainTextEdit()
        self.dns_test_names.setFixedHeight(55)
        self.dns_strategy = QComboBox()
        self.dns_strategy.addItems(
            ["auto", "resolved-default-interface", "resolved-lo", "networkmanager", "disabled"]
        )
        self.ike_proposals = QPlainTextEdit()
        self.ike_proposals.setFixedHeight(85)
        self.esp_proposals = QPlainTextEdit()
        self.esp_proposals.setFixedHeight(55)
        self.dpd_enabled = QCheckBox()
        self.notes = QPlainTextEdit()
        self.notes.setFixedHeight(70)
        self.secret_storage = QComboBox()
        self.secret_storage.addItem("Linux Secret Service/keyring", "keyring")
        self.config_root = QComboBox()
        self.config_root.addItems(["auto", "/etc/swanctl", "/etc/strongswan/swanctl"])
        self.dns_interface = QLineEdit()

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

        tabs = QTabWidget()
        general = QWidget()
        general_form = QFormLayout(general)
        general_form.addRow("Profile name", self.profile_name)
        general_form.addRow("Gateway", self.gateway)
        warning = QLabel(
            "FortiGate PSK+EAP commonly requires remote IKE ID = %any because "
            "the peer may authenticate as its resolved IP instead of the gateway FQDN."
        )
        warning.setWordWrap(True)
        general_form.addRow(warning)
        general_form.addRow("Transport", self.transport)
        general_form.addRow("IKE port", self.ike_port)

        auth = QWidget()
        auth_form = QFormLayout(auth)
        auth_form.addRow("Username", self.username)
        auth_form.addRow("EAP identity", self.eap_identity)
        auth_form.addRow("PSK", self.psk)
        auth_form.addRow("Password", self.password)
        auth_form.addRow("Secret storage", self.secret_storage)

        routes = QWidget()
        routes_form = QFormLayout(routes)
        routes_form.addRow("Request virtual IP", self.request_virtual_ip)
        routes_form.addRow("Tunnel mode", self.tunnel_mode)
        routes_form.addRow(self.full_tunnel_note)
        routes_form.addRow(QLabel("Remote routes"), self.remote_routes)

        dns = QWidget()
        dns_form = QFormLayout(dns)
        dns_form.addRow(QLabel("DNS servers"), self.dns_servers)
        dns_form.addRow(QLabel("DNS domains"), self.dns_search_domains)
        dns_form.addRow(QLabel("DNS test names"), self.dns_test_names)
        dns_form.addRow("Linux DNS strategy", self.dns_strategy)

        advanced = QWidget()
        advanced_layout = QFormLayout(advanced)
        advanced_layout.addRow("Local ID", self.local_id)
        advanced_layout.addRow("Strict remote ID", self.remote_id)
        advanced_layout.addRow(QLabel("IKE proposals"), self.ike_proposals)
        advanced_layout.addRow(QLabel("ESP proposals"), self.esp_proposals)
        advanced_layout.addRow("DPD enabled", self.dpd_enabled)
        advanced_layout.addRow("swanctl config root", self.config_root)
        advanced_layout.addRow("DNS interface", self.dns_interface)
        advanced_layout.addRow(QLabel("Notes"), self.notes)

        tabs.addTab(general, "General")
        tabs.addTab(auth, "Authentication")
        tabs.addTab(routes, "Routes")
        tabs.addTab(dns, "DNS")
        tabs.addTab(advanced, "Advanced")
        layout.addWidget(tabs)
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
        self.dns_test_names.setPlainText(_join_lines(profile.dns_test_names))
        self.dns_strategy.setCurrentText(profile.dns.linux_strategy)
        self.ike_proposals.setPlainText(
            _join_lines(profile.ike_proposals or list(DEFAULT_IKE_PROPOSALS))
        )
        self.esp_proposals.setPlainText(
            _join_lines(profile.esp_proposals or list(DEFAULT_ESP_PROPOSALS))
        )
        self.dpd_enabled.setChecked(profile.dpd_enabled)
        self.notes.setPlainText(profile.notes)
        self.secret_storage.setCurrentIndex(self.secret_storage.findData(profile.secret_storage))
        self.config_root.setCurrentText(profile.platform.config_root)
        self.dns_interface.setText(profile.platform.dns_interface)

    def profile(self) -> VpnProfile:
        return VpnProfile(
            id=self._profile_id,
            profile_name=self.profile_name.text().strip(),
            gateway_fqdn_or_ip=self.gateway.text().strip(),
            remote_id=self.remote_id.text().strip(),
            remote_id_mode="custom" if self.remote_id.text().strip() else "any",
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
            dns_test_names=_split_lines(self.dns_test_names.toPlainText()),
            dns_linux_strategy=self.dns_strategy.currentText(),  # type: ignore[arg-type]
            ike_proposals=_split_lines(self.ike_proposals.toPlainText()),
            esp_proposals=_split_lines(self.esp_proposals.toPlainText()),
            dpd_enabled=self.dpd_enabled.isChecked(),
            notes=self.notes.toPlainText().strip(),
            secret_storage=self.secret_storage.currentData(),
            platform_config_root=self.config_root.currentText(),  # type: ignore[arg-type]
            dns_interface=self.dns_interface.text().strip() or "auto",
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

    def _update_tunnel_note(self) -> None:
        full_tunnel = self.tunnel_mode.currentData() is False
        self.full_tunnel_note.setVisible(full_tunnel)

from __future__ import annotations

import json
import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from gic_ipsec_client.backend import commands, secrets
from gic_ipsec_client.backend.diagnostics import redact_text
from gic_ipsec_client.backend.models import ConnectionStatus, VpnProfile
from gic_ipsec_client.backend.strongswan import StrongSwanBackend
from gic_ipsec_client.backend.validators import ProfileValidationError, validate_profile
from gic_ipsec_client.gui.log_viewer import LogViewer
from gic_ipsec_client.gui.profile_editor import ProfileEditor
from gic_ipsec_client.gui.status_panel import StatusPanel


def _config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "gic-ipsec-client"


def _request_dir() -> Path:
    return Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / (
        "gic-ipsec-client/helper-requests"
    )


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("GIC IPsec Client")
        self.resize(980, 620)
        self.backend = StrongSwanBackend()
        self.profiles: dict[str, VpnProfile] = {}
        self.profile_list = QListWidget()
        self.status_panel = StatusPanel()
        self.log_viewer = LogViewer()
        self.last_diagnostics = ""

        self._build_ui()
        self._load_profiles()
        self._refresh_profile_list()
        self.log_viewer.append_log("Ready.")

    def _build_ui(self) -> None:
        toolbar = QToolBar("Profiles")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        add_button = QPushButton("Add")
        add_button.clicked.connect(self.add_profile)
        edit_button = QPushButton("Edit")
        edit_button.clicked.connect(self.edit_profile)
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self.delete_profile)
        toolbar.addWidget(add_button)
        toolbar.addWidget(edit_button)
        toolbar.addWidget(delete_button)

        connect_button = QPushButton("Connect")
        connect_button.clicked.connect(self.connect_profile)
        disconnect_button = QPushButton("Disconnect")
        disconnect_button.clicked.connect(self.disconnect_profile)
        run_diag_button = QPushButton("Run diagnostics")
        run_diag_button.clicked.connect(self.run_diagnostics)
        export_button = QPushButton("Export sanitized debug bundle")
        export_button.clicked.connect(self.export_debug_bundle)
        copy_button = QPushButton("Copy diagnostics summary")
        copy_button.clicked.connect(self.copy_diagnostics_summary)

        action_row = QHBoxLayout()
        action_buttons = (
            connect_button,
            disconnect_button,
            run_diag_button,
            export_button,
            copy_button,
        )
        for button in action_buttons:
            action_row.addWidget(button)
        action_row.addStretch(1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(self.profile_list)
        left_layout.addWidget(self.status_panel)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addLayout(action_row)
        right_layout.addWidget(self.log_viewer)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        self.setCentralWidget(splitter)

    def _load_profiles(self) -> None:
        path = _config_dir() / "profiles.json"
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.profiles = {
                item["id"]: VpnProfile.from_dict(item) for item in payload.get("profiles", [])
            }
        except (OSError, json.JSONDecodeError, TypeError, KeyError) as exc:
            self.log_viewer.append_log(f"Could not load saved profiles: {exc}")

    def _save_profiles(self) -> None:
        _config_dir().mkdir(parents=True, exist_ok=True)
        payload = {
            "profiles": [
                profile.to_dict(include_secrets=False) for profile in self.profiles.values()
            ]
        }
        (_config_dir() / "profiles.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _refresh_profile_list(self) -> None:
        self.profile_list.clear()
        for profile in sorted(self.profiles.values(), key=lambda item: item.profile_name.lower()):
            item = QListWidgetItem(profile.profile_name)
            item.setData(Qt.ItemDataRole.UserRole, profile.id)
            self.profile_list.addItem(item)

    def _selected_profile(self) -> VpnProfile | None:
        item = self.profile_list.currentItem()
        if not item:
            return None
        return self.profiles.get(item.data(Qt.ItemDataRole.UserRole))

    def add_profile(self) -> None:
        editor = ProfileEditor(parent=self)
        if editor.exec() != ProfileEditor.DialogCode.Accepted:
            return
        profile = editor.profile()
        self._persist_profile(profile)

    def edit_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        editor = ProfileEditor(profile, self)
        if editor.exec() != ProfileEditor.DialogCode.Accepted:
            return
        self._persist_profile(editor.profile())

    def _persist_profile(self, profile: VpnProfile) -> None:
        if profile.secret_storage == "keyring":
            try:
                secrets.save_profile_secrets(profile.id, psk=profile.psk, password=profile.password)
                profile.psk = ""
                profile.password = ""
            except secrets.SecretStorageUnavailable as exc:
                QMessageBox.warning(self, "Secret storage unavailable", str(exc))
                profile.secret_storage = "ask"
        self.profiles[profile.id] = profile
        self._save_profiles()
        self._refresh_profile_list()

    def delete_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        self._run_helper("delete-profile", "--profile-uuid", profile.id)
        secrets.delete_profile_secrets(profile.id)
        self.profiles.pop(profile.id, None)
        self._save_profiles()
        self._refresh_profile_list()
        self.log_viewer.append_log(f"Deleted profile {profile.profile_name}.")

    def _profile_with_secrets(self, profile: VpnProfile) -> VpnProfile:
        if profile.psk and profile.password:
            return profile
        if profile.secret_storage == "keyring":
            psk, password = secrets.load_profile_secrets(profile.id)
            profile.psk = psk or ""
            profile.password = password or ""
        return profile

    def connect_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        try:
            profile = self._profile_with_secrets(profile)
            validate_profile(profile)
        except (ProfileValidationError, secrets.SecretStorageUnavailable) as exc:
            QMessageBox.warning(self, "Profile error", str(exc))
            return
        self.status_panel.set_status(ConnectionStatus.CONNECTING)
        request_path = self._write_helper_request(profile)
        render_result = self._run_helper("render-profile", "--request", str(request_path))
        if render_result != 0:
            self.status_panel.set_status(ConnectionStatus.FAILED)
            return
        self._run_helper("load-profile")
        connect_result = self._run_helper("connect-profile", "--profile-uuid", profile.id)
        self.status_panel.set_status(
            ConnectionStatus.CONNECTED if connect_result == 0 else ConnectionStatus.FAILED
        )

    def disconnect_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        result = self._run_helper("disconnect-profile", "--profile-uuid", profile.id)
        self.status_panel.set_status(
            ConnectionStatus.DISCONNECTED if result == 0 else ConnectionStatus.FAILED
        )

    def run_diagnostics(self) -> None:
        report = self.backend.collect_diagnostics(profile=self._selected_profile())
        self.last_diagnostics = report.as_text()
        self.log_viewer.set_log_text(self.last_diagnostics)

    def export_debug_bundle(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Export debug bundle")
        if not directory:
            return
        archive = self.backend.export_debug_bundle(
            Path(directory),
            profile=self._selected_profile(),
        )
        self.log_viewer.append_log(f"Exported sanitized debug bundle: {archive}")

    def copy_diagnostics_summary(self) -> None:
        if not self.last_diagnostics:
            self.run_diagnostics()
        QApplication.clipboard().setText(redact_text(self.last_diagnostics))
        self.log_viewer.append_log("Diagnostics summary copied.")

    def _write_helper_request(self, profile: VpnProfile) -> Path:
        request_dir = _request_dir()
        request_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(request_dir, 0o700)
        request_path = request_dir / f"{profile.id}.json"
        payload = {"action": "render_profile", "profile": profile.to_dict(include_secrets=True)}
        request_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(request_path, 0o600)
        return request_path

    def _run_helper(self, subcommand: str, *args: str) -> int:
        command = commands.build_pkexec_helper_command(subcommand, *args)
        try:
            completed = commands.run_command(command)
        except (OSError, TimeoutError) as exc:
            self.log_viewer.append_log(f"Helper failed: {exc}")
            return 1
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        if output:
            self.log_viewer.append_log(output)
        return completed.returncode

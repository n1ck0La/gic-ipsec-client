from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
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
from gic_ipsec_client.backend.settings import AppSettings, load_app_settings, save_app_settings
from gic_ipsec_client.backend.strongswan import StrongSwanBackend
from gic_ipsec_client.backend.swanctl_paths import DEBIAN_SWANCTL_ROOT, FEDORA_SWANCTL_ROOT
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


class BackgroundTask(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, task: Callable[[], object]) -> None:
        super().__init__()
        self._task = task

    def run(self) -> None:
        try:
            self.finished.emit(self._task())
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("GIC IPsec Client")
        self.resize(980, 620)
        self.backend = StrongSwanBackend()
        self.settings = load_app_settings()
        self.profiles: dict[str, VpnProfile] = {}
        self.profile_list = QListWidget()
        self.status_panel = StatusPanel()
        self.log_viewer = LogViewer()
        self.last_diagnostics = ""
        self.last_helper_output = ""
        self._background_tasks: list[tuple[QThread, BackgroundTask]] = []

        self._build_ui()
        self._load_profiles()
        self._refresh_profile_list()
        self.log_viewer.append_log("Ready.")

    def _build_ui(self) -> None:
        toolbar = QToolBar("Profiles")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        add_button = QPushButton("Add Profile")
        add_button.clicked.connect(self.add_profile)
        edit_button = QPushButton("Edit")
        edit_button.clicked.connect(self.edit_profile)
        clone_button = QPushButton("Clone")
        clone_button.clicked.connect(self.clone_profile)
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self.delete_profile)
        import_button = QPushButton("Import Profile")
        import_button.clicked.connect(self.import_profile)
        export_profile_button = QPushButton("Export")
        export_profile_button.clicked.connect(self.export_profile)
        settings_button = QPushButton("Settings")
        settings_button.clicked.connect(self.edit_settings)
        toolbar.addWidget(add_button)
        toolbar.addWidget(edit_button)
        toolbar.addWidget(clone_button)
        toolbar.addWidget(delete_button)
        toolbar.addWidget(import_button)
        toolbar.addWidget(export_profile_button)
        toolbar.addWidget(settings_button)

        connect_button = QPushButton("Connect")
        connect_button.clicked.connect(self.connect_profile)
        disconnect_button = QPushButton("Disconnect")
        disconnect_button.clicked.connect(self.disconnect_profile)
        self.reconnect_button = QPushButton("Reconnect network interface")
        self.reconnect_button.clicked.connect(self.reconnect_network_interface)
        self.reconnect_button.setVisible(False)
        run_diag_button = QPushButton("Run diagnostics")
        run_diag_button.clicked.connect(self.run_diagnostics)
        test_dns_button = QPushButton("Test DNS")
        test_dns_button.clicked.connect(self.test_dns)
        export_button = QPushButton("Export diagnostics")
        export_button.clicked.connect(self.export_debug_bundle)
        copy_button = QPushButton("Copy diagnostics summary")
        copy_button.clicked.connect(self.copy_diagnostics_summary)

        action_row = QHBoxLayout()
        action_buttons = (
            connect_button,
            disconnect_button,
            self.reconnect_button,
            run_diag_button,
            test_dns_button,
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
        self.disconnect_warning_label = QLabel("Disconnect completed with warnings")
        self.disconnect_warning_label.setObjectName("disconnectWarning")
        self.disconnect_warning_label.setVisible(False)
        self.disconnect_warning_label.setStyleSheet(
            "font-weight: 700; color: #9a6b00; padding: 6px 0;"
        )
        right_layout.addWidget(self.disconnect_warning_label)
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
        if not self.profiles:
            self.log_viewer.append_log("No VPN profiles configured.")
            return
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
        if profile.psk or profile.password:
            try:
                secrets.save_profile_secrets(profile.id, psk=profile.psk, password=profile.password)
            except secrets.SecretStorageUnavailable as exc:
                QMessageBox.warning(self, "Secret storage unavailable", str(exc))
            finally:
                profile.psk = ""
                profile.password = ""
        profile.secret_storage = "keyring"
        self.profiles[profile.id] = profile
        self._save_profiles()
        self._refresh_profile_list()

    def clone_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        payload = profile.to_dict(include_secrets=False)
        payload["id"] = str(uuid4())
        payload["name"] = f"{profile.name} Copy"
        clone = VpnProfile.from_dict(payload)
        self.profiles[clone.id] = clone
        self._save_profiles()
        self._refresh_profile_list()

    def delete_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        profile_id = profile.id
        profile_name = profile.profile_name
        config_args = self._config_root_args()

        def task() -> object:
            return self._run_helper_command(
                "delete-profile",
                "--profile-uuid",
                profile_id,
                *config_args,
            )

        def finished(result: object) -> None:
            code, output = self._coerce_helper_result(result)
            self._record_helper_output(output)
            if code != 0:
                return
            secrets.delete_profile_secrets(profile_id)
            self.profiles.pop(profile_id, None)
            self._save_profiles()
            self._refresh_profile_list()
            self.log_viewer.append_log(f"Deleted profile {profile_name}.")

        self._run_background_task(task, finished, self._background_helper_failed)

    def import_profile(self) -> None:
        file_name, _ = QFileDialog.getOpenFileName(self, "Import profile", "", "JSON (*.json)")
        if not file_name:
            return
        try:
            payload = json.loads(Path(file_name).read_text(encoding="utf-8"))
            profile = VpnProfile.from_dict(payload)
            validate_profile(profile, require_secrets=False)
        except (OSError, json.JSONDecodeError, TypeError, ProfileValidationError) as exc:
            QMessageBox.warning(self, "Import failed", str(exc))
            return
        self.profiles[profile.id] = profile
        self._save_profiles()
        self._refresh_profile_list()

    def export_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Export profile",
            f"{profile.name or profile.id}.json",
            "JSON (*.json)",
        )
        if not file_name:
            return
        Path(file_name).write_text(
            json.dumps(profile.to_dict(include_secrets=False), indent=2, sort_keys=True),
            encoding="utf-8",
        )

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
        profile_id = profile.id
        config_args = self._config_root_args()

        def task() -> object:
            render_code, render_output = self._run_helper_command(
                "render-profile",
                "--request",
                str(request_path),
                *config_args,
            )
            if render_code != 0:
                return {
                    "render_code": render_code,
                    "render_output": render_output,
                    "connect_code": 1,
                    "connect_output": "",
                }
            connect_code, connect_output = self._run_helper_command(
                "connect-profile",
                "--profile-uuid",
                profile_id,
                *config_args,
            )
            return {
                "render_code": render_code,
                "render_output": render_output,
                "connect_code": connect_code,
                "connect_output": connect_output,
            }

        def finished(result: object) -> None:
            payload = result if isinstance(result, dict) else {}
            render_code = int(payload.get("render_code", 1))
            connect_code = int(payload.get("connect_code", 1))
            output = "\n".join(
                part
                for part in (
                    str(payload.get("render_output", "") or ""),
                    str(payload.get("connect_output", "") or ""),
                )
                if part
            )
            self._record_helper_output(output)
            failed = render_code != 0 or connect_code != 0
            self.status_panel.set_status(
                ConnectionStatus.FAILED if failed else ConnectionStatus.CONNECTED
            )
            if not failed:
                self.disconnect_warning_label.setVisible(False)

        self._run_background_task(task, finished, self._background_helper_failed)

    def disconnect_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        profile_id = profile.id
        config_args = self._config_root_args()

        def task() -> object:
            return self._run_helper_command(
                "disconnect-profile",
                "--profile-uuid",
                profile_id,
                *config_args,
            )

        def finished(result: object) -> None:
            code, output = self._coerce_helper_result(result)
            self._record_helper_output(output)
            self.status_panel.set_status(
                ConnectionStatus.DISCONNECTED if code == 0 else ConnectionStatus.FAILED
            )
            self.disconnect_warning_label.setVisible(
                code == 0 and "Disconnect completed with warnings" in self.last_helper_output
            )
            self.reconnect_button.setVisible(
                code != 0 and "Reconnect network interface is available" in self.last_helper_output
            )

        self._run_background_task(task, finished, self._background_helper_failed)

    def reconnect_network_interface(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        profile_id = profile.id

        def task() -> object:
            return self._run_helper_command(
                "reconnect-network-interface",
                "--profile-uuid",
                profile_id,
            )

        def finished(result: object) -> None:
            code, output = self._coerce_helper_result(result)
            self._record_helper_output(output)
            if code == 0:
                self.reconnect_button.setVisible(False)
                self.disconnect_warning_label.setVisible(False)

        self._run_background_task(task, finished, self._background_helper_failed)

    def run_diagnostics(self) -> None:
        profile = self._selected_profile()
        config_root_override = self._config_root_override()
        self.log_viewer.append_log("Running diagnostics...")

        def task() -> object:
            return self.backend.collect_diagnostics(
                profile=profile,
                config_root_override=config_root_override,
            )

        def finished(result: object) -> None:
            if not hasattr(result, "as_text"):
                self.log_viewer.append_log("Diagnostics failed: invalid report.")
                return
            self.last_diagnostics = result.as_text()
            self.log_viewer.set_log_text(self.last_diagnostics)

        self._run_background_task(task, finished, self._background_diagnostics_failed)

    def test_dns(self) -> None:
        self.run_diagnostics()

    def export_debug_bundle(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Export debug bundle")
        if not directory:
            return
        profile = self._selected_profile()
        config_root_override = self._config_root_override()
        output_dir = Path(directory)
        self.log_viewer.append_log("Exporting sanitized debug bundle...")

        def task() -> object:
            return self.backend.export_debug_bundle(
                output_dir,
                profile=profile,
                config_root_override=config_root_override,
            )

        def finished(result: object) -> None:
            self.log_viewer.append_log(f"Exported sanitized debug bundle: {result}")

        self._run_background_task(task, finished, self._background_diagnostics_failed)

    def copy_diagnostics_summary(self) -> None:
        if not self.last_diagnostics:
            self.run_diagnostics()
            self.log_viewer.append_log("Diagnostics are running; copy again when they finish.")
            return
        QApplication.clipboard().setText(redact_text(self.last_diagnostics))
        self.log_viewer.append_log("Diagnostics summary copied.")

    def edit_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.settings = dialog.settings()
        save_app_settings(self.settings)
        selected = self._config_root_override() or "Automatic"
        self.log_viewer.append_log(f"Settings saved. swanctl config root: {selected}")

    def _run_background_task(
        self,
        task: Callable[[], object],
        on_finished: Callable[[object], None],
        on_failed: Callable[[str], None],
    ) -> None:
        thread = QThread(self)
        worker = BackgroundTask(task)
        worker.moveToThread(thread)
        entry = (thread, worker)

        def cleanup() -> None:
            if entry in self._background_tasks:
                self._background_tasks.remove(entry)

        def finished(result: object) -> None:
            try:
                on_finished(result)
            finally:
                thread.quit()

        def failed(message: str) -> None:
            try:
                on_failed(message)
            finally:
                thread.quit()

        thread.started.connect(worker.run)
        worker.finished.connect(finished)
        worker.failed.connect(failed)
        worker.finished.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(cleanup)
        thread.finished.connect(thread.deleteLater)
        self._background_tasks.append(entry)
        thread.start()

    def _background_helper_failed(self, message: str) -> None:
        self.last_helper_output = f"Helper failed: {message}"
        self.log_viewer.append_log(self.last_helper_output)
        self.status_panel.set_status(ConnectionStatus.FAILED)

    def _background_diagnostics_failed(self, message: str) -> None:
        self.log_viewer.append_log(f"Diagnostics failed: {message}")

    def _write_helper_request(self, profile: VpnProfile) -> Path:
        request_dir = _request_dir()
        request_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(request_dir, 0o700)
        request_path = request_dir / f"{profile.id}.json"
        payload = {
            "action": "render_profile",
            "profile": profile.to_dict(include_secrets=True),
            "swanctl_config_root": self._config_root_override(),
        }
        request_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(request_path, 0o600)
        return request_path

    def _run_helper_command(self, subcommand: str, *args: str) -> tuple[int, str]:
        try:
            command = commands.build_pkexec_helper_command(subcommand, *args)
            completed = commands.run_command(command)
        except FileNotFoundError as exc:
            return 1, str(exc)
        except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            return 1, f"Helper failed: {exc}"
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        return completed.returncode, output

    def _record_helper_output(self, output: str) -> None:
        self.last_helper_output = output
        if output:
            self.log_viewer.append_log(output)

    def _coerce_helper_result(self, result: object) -> tuple[int, str]:
        if not isinstance(result, tuple) or len(result) != 2:
            return 1, "Helper failed: invalid helper result."
        code, output = result
        return int(code), str(output or "")

    def _run_helper(self, subcommand: str, *args: str) -> int:
        code, output = self._run_helper_command(subcommand, *args)
        self._record_helper_output(output)
        return code

    def _config_root_override(self) -> str:
        return self.settings.normalized_swanctl_config_root()

    def _config_root_args(self) -> tuple[str, ...]:
        override = self._config_root_override()
        return ("--config-root", override) if override else ()


class SettingsDialog(QDialog):
    def __init__(self, settings: AppSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.root_combo = QComboBox()
        self.root_combo.addItem("Automatic", "")
        self.root_combo.addItem(str(DEBIAN_SWANCTL_ROOT), str(DEBIAN_SWANCTL_ROOT))
        self.root_combo.addItem(str(FEDORA_SWANCTL_ROOT), str(FEDORA_SWANCTL_ROOT))
        current = settings.normalized_swanctl_config_root()
        index = self.root_combo.findData(current)
        self.root_combo.setCurrentIndex(index if index >= 0 else 0)

        form = QFormLayout()
        form.addRow(QLabel("swanctl config root"), self.root_combo)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def settings(self) -> AppSettings:
        return AppSettings(swanctl_config_root=str(self.root_combo.currentData() or ""))

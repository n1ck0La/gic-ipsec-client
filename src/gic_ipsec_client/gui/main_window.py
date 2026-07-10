from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import Qt, QThread, Slot
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

from gic_ipsec_client import __version__
from gic_ipsec_client.backend import secrets
from gic_ipsec_client.backend.diagnostics import redact_text
from gic_ipsec_client.backend.models import ConnectionStatus, VpnProfile
from gic_ipsec_client.backend.settings import AppSettings, load_app_settings, save_app_settings
from gic_ipsec_client.backend.swanctl_paths import DEBIAN_SWANCTL_ROOT, FEDORA_SWANCTL_ROOT
from gic_ipsec_client.backend.validators import ProfileValidationError, validate_profile
from gic_ipsec_client.gui.log_viewer import LogViewer
from gic_ipsec_client.gui.profile_editor import ProfileEditor
from gic_ipsec_client.gui.status_panel import StatusPanel
from gic_ipsec_client.gui.workers import (
    ConnectResult,
    ConnectWorker,
    DebugBundleWorker,
    DiagnosticsWorker,
    HelperResult,
    HelperWorker,
)


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
        self.settings = load_app_settings()
        self.profiles: dict[str, VpnProfile] = {}
        self.profile_list = QListWidget()
        self.status_panel = StatusPanel()
        self.log_viewer = LogViewer()
        self.last_diagnostics = ""
        self.last_helper_output = ""
        self._connect_thread: QThread | None = None
        self._connect_worker: ConnectWorker | None = None
        self._disconnect_thread: QThread | None = None
        self._disconnect_worker: HelperWorker | None = None
        self._reconnect_thread: QThread | None = None
        self._reconnect_worker: HelperWorker | None = None
        self._delete_thread: QThread | None = None
        self._delete_worker: HelperWorker | None = None
        self._diagnostics_thread: QThread | None = None
        self._diagnostics_worker: DiagnosticsWorker | None = None
        self._export_thread: QThread | None = None
        self._export_worker: DebugBundleWorker | None = None
        self._pending_delete_profile_id = ""
        self._pending_delete_profile_name = ""

        self._build_ui()
        self._load_profiles()
        self._refresh_profile_list()
        self._append_log("Ready.")

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
        about_button = QPushButton("About")
        about_button.clicked.connect(self.show_about)
        toolbar.addWidget(add_button)
        toolbar.addWidget(edit_button)
        toolbar.addWidget(clone_button)
        toolbar.addWidget(delete_button)
        toolbar.addWidget(import_button)
        toolbar.addWidget(export_profile_button)
        toolbar.addWidget(settings_button)
        toolbar.addWidget(about_button)

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
            self._append_log(f"Could not load saved profiles: {exc}")

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
        self._assert_ui_thread()
        self.profile_list.clear()
        if not self.profiles:
            self._append_log("No VPN profiles configured.")
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
        if self._delete_thread and self._delete_thread.isRunning():
            self._append_log("Delete already in progress.")
            return
        self._pending_delete_profile_id = profile.id
        self._pending_delete_profile_name = profile.profile_name
        worker = HelperWorker(
            "delete-profile",
            ("--profile-uuid", profile.id, *self._config_root_args()),
            progress_message="Deleting profile...",
        )
        self._start_delete_worker(worker)

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
        if self._connect_thread and self._connect_thread.isRunning():
            self._append_log("Connect already in progress.")
            return
        self._set_status(ConnectionStatus.CONNECTING)
        request_path = self._write_helper_request(profile)
        worker = ConnectWorker(
            request_path=str(request_path),
            profile_id=profile.id,
            config_args=self._config_root_args(),
        )
        self._start_connect_worker(worker)

    def disconnect_profile(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        if self._disconnect_thread and self._disconnect_thread.isRunning():
            self._append_log("Disconnect already in progress.")
            return
        worker = HelperWorker(
            "disconnect-profile",
            ("--profile-uuid", profile.id, *self._config_root_args()),
            progress_message="Disconnecting profile...",
        )
        self._start_disconnect_worker(worker)

    def reconnect_network_interface(self) -> None:
        profile = self._selected_profile()
        if not profile:
            QMessageBox.information(self, "No profile selected", "Select a profile first.")
            return
        if self._reconnect_thread and self._reconnect_thread.isRunning():
            self._append_log("Reconnect already in progress.")
            return
        worker = HelperWorker(
            "reconnect-network-interface",
            ("--profile-uuid", profile.id),
            progress_message="Reconnecting network interface...",
        )
        self._start_reconnect_worker(worker)

    def run_diagnostics(self) -> None:
        profile = self._selected_profile()
        config_root_override = self._config_root_override()
        if self._diagnostics_thread and self._diagnostics_thread.isRunning():
            self._append_log("Diagnostics already in progress.")
            return
        worker = DiagnosticsWorker(
            profile=profile,
            config_root_override=config_root_override,
        )
        self._start_diagnostics_worker(worker)

    def test_dns(self) -> None:
        self.run_diagnostics()

    def export_debug_bundle(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Export debug bundle")
        if not directory:
            return
        profile = self._selected_profile()
        config_root_override = self._config_root_override()
        output_dir = Path(directory)
        if self._export_thread and self._export_thread.isRunning():
            self._append_log("Diagnostics export already in progress.")
            return
        worker = DebugBundleWorker(
            output_dir=output_dir,
            profile=profile,
            config_root_override=config_root_override,
        )
        self._start_export_worker(worker)

    def copy_diagnostics_summary(self) -> None:
        if not self.last_diagnostics:
            self.run_diagnostics()
            self._append_log("Diagnostics are running; copy again when they finish.")
            return
        QApplication.clipboard().setText(redact_text(self.last_diagnostics))
        self._append_log("Diagnostics summary copied.")

    def edit_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.settings = dialog.settings()
        save_app_settings(self.settings)
        selected = self._config_root_override() or "Automatic"
        self._append_log(f"Settings saved. swanctl config root: {selected}")

    def show_about(self) -> None:
        QMessageBox.information(
            self,
            "About GIC IPsec Client",
            f"GIC IPsec Client {__version__}\n\nstrongSwan swanctl/VICI desktop client.",
        )

    def _wire_worker(
        self,
        *,
        thread: QThread,
        worker: HelperWorker | ConnectWorker | DiagnosticsWorker | DebugBundleWorker,
        finished_slot: object,
        failed_slot: object,
        cleanup_slot: object,
    ) -> None:
        worker.moveToThread(thread)
        worker.progress.connect(self._on_worker_progress)
        worker.finished.connect(finished_slot)
        worker.failed.connect(failed_slot)
        worker.finished.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(cleanup_slot)
        thread.finished.connect(thread.deleteLater)

    def _start_connect_worker(self, worker: ConnectWorker) -> None:
        self._assert_ui_thread()
        self._connect_thread = QThread(self)
        self._connect_worker = worker
        self._wire_worker(
            thread=self._connect_thread,
            worker=self._connect_worker,
            finished_slot=self._on_connect_finished,
            failed_slot=self._on_connect_failed,
            cleanup_slot=self._cleanup_connect_worker,
        )
        self._connect_thread.started.connect(self._connect_worker.run)
        self._connect_thread.start()

    def _start_disconnect_worker(self, worker: HelperWorker) -> None:
        self._assert_ui_thread()
        self._disconnect_thread = QThread(self)
        self._disconnect_worker = worker
        self._wire_worker(
            thread=self._disconnect_thread,
            worker=self._disconnect_worker,
            finished_slot=self._on_disconnect_finished,
            failed_slot=self._on_disconnect_failed,
            cleanup_slot=self._cleanup_disconnect_worker,
        )
        self._disconnect_thread.started.connect(self._disconnect_worker.run)
        self._disconnect_thread.start()

    def _start_reconnect_worker(self, worker: HelperWorker) -> None:
        self._assert_ui_thread()
        self._reconnect_thread = QThread(self)
        self._reconnect_worker = worker
        self._wire_worker(
            thread=self._reconnect_thread,
            worker=self._reconnect_worker,
            finished_slot=self._on_reconnect_finished,
            failed_slot=self._on_reconnect_failed,
            cleanup_slot=self._cleanup_reconnect_worker,
        )
        self._reconnect_thread.started.connect(self._reconnect_worker.run)
        self._reconnect_thread.start()

    def _start_delete_worker(self, worker: HelperWorker) -> None:
        self._assert_ui_thread()
        self._delete_thread = QThread(self)
        self._delete_worker = worker
        self._wire_worker(
            thread=self._delete_thread,
            worker=self._delete_worker,
            finished_slot=self._on_delete_finished,
            failed_slot=self._on_delete_failed,
            cleanup_slot=self._cleanup_delete_worker,
        )
        self._delete_thread.started.connect(self._delete_worker.run)
        self._delete_thread.start()

    def _start_diagnostics_worker(self, worker: DiagnosticsWorker) -> None:
        self._assert_ui_thread()
        self._diagnostics_thread = QThread(self)
        self._diagnostics_worker = worker
        self._wire_worker(
            thread=self._diagnostics_thread,
            worker=self._diagnostics_worker,
            finished_slot=self._on_diagnostics_finished,
            failed_slot=self._on_diagnostics_failed,
            cleanup_slot=self._cleanup_diagnostics_worker,
        )
        self._diagnostics_thread.started.connect(self._diagnostics_worker.run)
        self._diagnostics_thread.start()

    def _start_export_worker(self, worker: DebugBundleWorker) -> None:
        self._assert_ui_thread()
        self._export_thread = QThread(self)
        self._export_worker = worker
        self._wire_worker(
            thread=self._export_thread,
            worker=self._export_worker,
            finished_slot=self._on_export_finished,
            failed_slot=self._on_export_failed,
            cleanup_slot=self._cleanup_export_worker,
        )
        self._export_thread.started.connect(self._export_worker.run)
        self._export_thread.start()

    @Slot(str)
    def _on_worker_progress(self, message: str) -> None:
        self._append_log(message)

    @Slot(object)
    def _on_connect_finished(self, result: object) -> None:
        self._assert_ui_thread()
        if not isinstance(result, ConnectResult):
            self._on_connect_failed("Connect failed: invalid worker result.")
            return
        self._record_helper_output(result.output)
        self._set_status(ConnectionStatus.CONNECTED if result.ok else ConnectionStatus.FAILED)
        if result.ok:
            self.disconnect_warning_label.setVisible(False)

    @Slot(str)
    def _on_connect_failed(self, message: str) -> None:
        self._helper_failed(message)

    @Slot(object)
    def _on_disconnect_finished(self, result: object) -> None:
        self._assert_ui_thread()
        code, output = self._coerce_helper_result(result)
        self._record_helper_output(output)
        self._set_status(ConnectionStatus.DISCONNECTED if code == 0 else ConnectionStatus.FAILED)
        self.disconnect_warning_label.setVisible(
            code == 0 and "Disconnect completed with warnings" in self.last_helper_output
        )
        self.reconnect_button.setVisible(
            code != 0 and "Reconnect network interface is available" in self.last_helper_output
        )

    @Slot(str)
    def _on_disconnect_failed(self, message: str) -> None:
        self._helper_failed(message)

    @Slot(object)
    def _on_reconnect_finished(self, result: object) -> None:
        self._assert_ui_thread()
        code, output = self._coerce_helper_result(result)
        self._record_helper_output(output)
        if code == 0:
            self.reconnect_button.setVisible(False)
            self.disconnect_warning_label.setVisible(False)

    @Slot(str)
    def _on_reconnect_failed(self, message: str) -> None:
        self._helper_failed(message)

    @Slot(object)
    def _on_delete_finished(self, result: object) -> None:
        self._assert_ui_thread()
        code, output = self._coerce_helper_result(result)
        self._record_helper_output(output)
        if code != 0:
            return
        profile_id = self._pending_delete_profile_id
        profile_name = self._pending_delete_profile_name
        secrets.delete_profile_secrets(profile_id)
        self.profiles.pop(profile_id, None)
        self._save_profiles()
        self._refresh_profile_list()
        self._append_log(f"Deleted profile {profile_name}.")

    @Slot(str)
    def _on_delete_failed(self, message: str) -> None:
        self._helper_failed(message)

    @Slot(object)
    def _on_diagnostics_finished(self, result: object) -> None:
        self._assert_ui_thread()
        if not hasattr(result, "as_text"):
            self._append_log("Diagnostics failed: invalid report.")
            return
        self.last_diagnostics = result.as_text()
        self._set_log_text(self.last_diagnostics)

    @Slot(str)
    def _on_diagnostics_failed(self, message: str) -> None:
        self._append_log(f"Diagnostics failed: {message}")

    @Slot(object)
    def _on_export_finished(self, result: object) -> None:
        self._assert_ui_thread()
        self._append_log(f"Exported sanitized debug bundle: {result}")

    @Slot(str)
    def _on_export_failed(self, message: str) -> None:
        self._append_log(f"Diagnostics export failed: {message}")

    @Slot()
    def _cleanup_connect_worker(self) -> None:
        self._assert_ui_thread()
        self._connect_worker = None
        self._connect_thread = None

    @Slot()
    def _cleanup_disconnect_worker(self) -> None:
        self._assert_ui_thread()
        self._disconnect_worker = None
        self._disconnect_thread = None

    @Slot()
    def _cleanup_reconnect_worker(self) -> None:
        self._assert_ui_thread()
        self._reconnect_worker = None
        self._reconnect_thread = None

    @Slot()
    def _cleanup_delete_worker(self) -> None:
        self._assert_ui_thread()
        self._delete_worker = None
        self._delete_thread = None
        self._pending_delete_profile_id = ""
        self._pending_delete_profile_name = ""

    @Slot()
    def _cleanup_diagnostics_worker(self) -> None:
        self._assert_ui_thread()
        self._diagnostics_worker = None
        self._diagnostics_thread = None

    @Slot()
    def _cleanup_export_worker(self) -> None:
        self._assert_ui_thread()
        self._export_worker = None
        self._export_thread = None

    def _helper_failed(self, message: str) -> None:
        self._assert_ui_thread()
        self.last_helper_output = f"Helper failed: {message}"
        self._append_log(self.last_helper_output)
        self._set_status(ConnectionStatus.FAILED)

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

    def _assert_ui_thread(self) -> None:
        if os.environ.get("GIC_DEBUG_QT_THREADS") != "1":
            return
        app = QApplication.instance()
        if app is not None:
            assert QThread.currentThread() == app.thread()

    def _append_log(self, message: str) -> None:
        self._assert_ui_thread()
        self.log_viewer.append_log(message)

    def _set_log_text(self, message: str) -> None:
        self._assert_ui_thread()
        self.log_viewer.set_log_text(message)

    def _set_status(self, status: ConnectionStatus) -> None:
        self._assert_ui_thread()
        self.status_panel.set_status(status)

    def _record_helper_output(self, output: str) -> None:
        self._assert_ui_thread()
        self.last_helper_output = output
        if output:
            self._append_log(output)

    def _coerce_helper_result(self, result: object) -> tuple[int, str]:
        if not isinstance(result, HelperResult):
            return 1, "Helper failed: invalid helper result."
        return result.returncode, result.output

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

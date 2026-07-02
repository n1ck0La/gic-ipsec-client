from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from gic_ipsec_client.backend.swanctl_paths import normalize_config_root_override


def config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "see-ipsec-client"


@dataclass(slots=True)
class AppSettings:
    swanctl_config_root: str = ""

    def normalized_swanctl_config_root(self) -> str:
        root = normalize_config_root_override(self.swanctl_config_root)
        return str(root) if root is not None else ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AppSettings:
        value = data.get("swanctl_config_root", "")
        settings = cls(swanctl_config_root=str(value or ""))
        settings.swanctl_config_root = settings.normalized_swanctl_config_root()
        return settings


def load_app_settings(path: Path | None = None) -> AppSettings:
    settings_path = path or config_dir() / "settings.json"
    if not settings_path.exists():
        return AppSettings()
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return AppSettings()
    if not isinstance(payload, dict):
        return AppSettings()
    try:
        return AppSettings.from_dict(payload)
    except ValueError:
        return AppSettings()


def save_app_settings(settings: AppSettings, path: Path | None = None) -> None:
    settings_path = path or config_dir() / "settings.json"
    normalized = AppSettings(
        swanctl_config_root=settings.normalized_swanctl_config_root(),
    )
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        json.dumps(normalized.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from enum import StrEnum
from typing import Any, Literal, TypeAlias
from uuid import uuid4

Transport: TypeAlias = Literal["udp", "tcp", "auto"]
SecretStorageMode: TypeAlias = Literal["ask", "keyring"]

DEFAULT_IKE_PROPOSALS = (
    "aes256-sha256-modp2048",
    "aes128-sha256-modp2048",
    "aes256-sha256-ecp256",
    "aes128-sha256-ecp256",
)
DEFAULT_ESP_PROPOSALS = (
    "aes256-sha256",
    "aes128-sha256",
)


class ConnectionStatus(StrEnum):
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    FAILED = "Failed"


@dataclass(slots=True)
class VpnProfile:
    """User-editable FortiGate-compatible IKEv2 EAP profile."""

    profile_name: str
    gateway_fqdn_or_ip: str
    remote_id: str = ""
    local_id: str = ""
    username: str = ""
    eap_identity: str = ""
    psk: str = ""
    password: str = ""
    transport: Transport = "udp"
    ike_port: int = 500
    request_virtual_ip: bool = True
    split_tunnel_enabled: bool = True
    remote_routes: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    dns_search_domains: list[str] = field(default_factory=list)
    ike_proposals: list[str] = field(default_factory=lambda: list(DEFAULT_IKE_PROPOSALS))
    esp_proposals: list[str] = field(default_factory=lambda: list(DEFAULT_ESP_PROPOSALS))
    dpd_enabled: bool = True
    notes: str = ""
    secret_storage: SecretStorageMode = "ask"
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        self.id = str(self.id or uuid4())
        self.ike_proposals = list(self.ike_proposals or DEFAULT_IKE_PROPOSALS)
        self.esp_proposals = list(self.esp_proposals or DEFAULT_ESP_PROPOSALS)
        self.remote_routes = list(self.remote_routes or [])
        self.dns_servers = list(self.dns_servers or [])
        self.dns_search_domains = list(self.dns_search_domains or [])
        self.eap_identity = self.eap_identity or self.username

    @property
    def connection_name(self) -> str:
        return f"gic-{self.id}"

    @property
    def child_name(self) -> str:
        return f"{self.connection_name}-child"

    def to_dict(self, *, include_secrets: bool = True) -> dict[str, Any]:
        data = asdict(self)
        if not include_secrets:
            data["psk"] = ""
            data["password"] = ""
        return data

    def sanitized_dict(self, *, privacy_mode: bool = False) -> dict[str, Any]:
        data = self.to_dict(include_secrets=False)
        data["psk"] = "<redacted>"
        data["password"] = "<redacted>"
        if privacy_mode:
            data["username"] = "<redacted>"
            data["eap_identity"] = "<redacted>"
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VpnProfile:
        payload = dict(data)
        if "profile_uuid" in payload and "id" not in payload:
            payload["id"] = payload.pop("profile_uuid")
        allowed = {field_info.name for field_info in fields(cls)}
        return cls(**{key: value for key, value in payload.items() if key in allowed})


def fortigate_default_profile() -> VpnProfile:
    return VpnProfile(
        profile_name="FortiGate IKEv2",
        gateway_fqdn_or_ip="vpn.example.com",
        remote_id="",
        local_id="",
        username="",
        eap_identity="",
        transport="udp",
        ike_port=500,
        request_virtual_ip=True,
        split_tunnel_enabled=True,
        remote_routes=[],
        dns_servers=[],
        dns_search_domains=[],
        ike_proposals=list(DEFAULT_IKE_PROPOSALS),
        esp_proposals=list(DEFAULT_ESP_PROPOSALS),
        dpd_enabled=True,
        notes="FortiGate-compatible IKEv2 EAP-MSCHAPv2 profile.",
    )

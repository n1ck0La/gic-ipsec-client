from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import StrEnum
from typing import Any, Literal, TypeAlias
from uuid import uuid4

Transport: TypeAlias = Literal["udp", "tcp", "auto"]
RemoteIdMode: TypeAlias = Literal["any", "fqdn", "ip", "custom"]
SecretStorageMode: TypeAlias = Literal["keyring"]
TrafficMode: TypeAlias = Literal["split", "full"]
DnsStrategy: TypeAlias = Literal[
    "auto",
    "resolved-default-interface",
    "resolved-lo",
    "networkmanager",
    "disabled",
]
ConfigRootMode: TypeAlias = Literal["auto", "/etc/swanctl", "/etc/strongswan/swanctl"]

CONNECTION_PREFIX = "gic-"
LEGACY_CONNECTION_PREFIX = "gic-"

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
class GatewayProfile:
    host: str = ""
    port: int = 500
    transport: Transport = "udp"
    remote_id: str = ""
    remote_id_mode: RemoteIdMode = "any"


@dataclass(slots=True)
class AuthProfile:
    ike_auth: str = "psk"
    eap_method: str = "eap-mschapv2"
    username: str = ""
    eap_identity: str = ""
    secret_storage: SecretStorageMode = "keyring"


@dataclass(slots=True)
class TrafficProfile:
    mode: TrafficMode = "split"
    remote_routes: list[str] = field(default_factory=list)
    request_virtual_ip: bool = True


@dataclass(slots=True)
class DnsProfile:
    enabled: bool = True
    servers: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    test_names: list[str] = field(default_factory=list)
    linux_strategy: DnsStrategy = "auto"


@dataclass(slots=True)
class CryptoProfile:
    ike_proposals: list[str] = field(default_factory=lambda: list(DEFAULT_IKE_PROPOSALS))
    esp_proposals: list[str] = field(default_factory=lambda: list(DEFAULT_ESP_PROPOSALS))
    dpd_enabled: bool = True


@dataclass(slots=True)
class PlatformProfile:
    config_root: ConfigRootMode = "auto"
    dns_interface: str = "auto"


@dataclass(slots=True)
class VpnProfile:
    """GIC IPsec profile with nested persisted schema and legacy flat accessors."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    gateway: GatewayProfile = field(default_factory=GatewayProfile)
    auth: AuthProfile = field(default_factory=AuthProfile)
    traffic: TrafficProfile = field(default_factory=TrafficProfile)
    dns: DnsProfile = field(default_factory=DnsProfile)
    crypto: CryptoProfile = field(default_factory=CryptoProfile)
    platform: PlatformProfile = field(default_factory=PlatformProfile)
    notes: str = ""
    psk: str = ""
    password: str = ""

    def __init__(
        self,
        *,
        id: str | None = None,
        name: str = "",
        profile_name: str = "",
        gateway: GatewayProfile | None = None,
        auth: AuthProfile | None = None,
        traffic: TrafficProfile | None = None,
        dns: DnsProfile | None = None,
        crypto: CryptoProfile | None = None,
        platform: PlatformProfile | None = None,
        gateway_fqdn_or_ip: str = "",
        remote_id: str = "",
        remote_id_mode: RemoteIdMode = "any",
        local_id: str = "",
        username: str = "",
        eap_identity: str = "",
        psk: str = "",
        password: str = "",
        transport: Transport = "udp",
        ike_port: int = 500,
        request_virtual_ip: bool = True,
        split_tunnel_enabled: bool = True,
        remote_routes: list[str] | None = None,
        dns_enabled: bool = True,
        dns_servers: list[str] | None = None,
        dns_search_domains: list[str] | None = None,
        dns_test_names: list[str] | None = None,
        dns_linux_strategy: DnsStrategy = "auto",
        ike_proposals: list[str] | None = None,
        esp_proposals: list[str] | None = None,
        dpd_enabled: bool = True,
        notes: str = "",
        secret_storage: SecretStorageMode = "keyring",
        platform_config_root: ConfigRootMode = "auto",
        dns_interface: str = "auto",
    ) -> None:
        self.id = str(id or uuid4())
        self.name = name or profile_name
        self.gateway = gateway or GatewayProfile(
            host=gateway_fqdn_or_ip,
            port=ike_port,
            transport=transport,
            remote_id=remote_id,
            remote_id_mode=remote_id_mode,
        )
        self.auth = auth or AuthProfile(
            username=username,
            eap_identity=eap_identity or username,
            secret_storage=secret_storage,
        )
        self.traffic = traffic or TrafficProfile(
            mode="split" if split_tunnel_enabled else "full",
            remote_routes=list(remote_routes or []),
            request_virtual_ip=request_virtual_ip,
        )
        self.dns = dns or DnsProfile(
            enabled=dns_enabled,
            servers=list(dns_servers or []),
            domains=list(dns_search_domains or []),
            test_names=list(dns_test_names or []),
            linux_strategy=dns_linux_strategy,
        )
        self.crypto = crypto or CryptoProfile(
            ike_proposals=list(ike_proposals or DEFAULT_IKE_PROPOSALS),
            esp_proposals=list(esp_proposals or DEFAULT_ESP_PROPOSALS),
            dpd_enabled=dpd_enabled,
        )
        self.platform = platform or PlatformProfile(
            config_root=platform_config_root,
            dns_interface=dns_interface,
        )
        self.notes = notes
        self.psk = psk
        self.password = password

    @property
    def profile_name(self) -> str:
        return self.name

    @profile_name.setter
    def profile_name(self, value: str) -> None:
        self.name = value

    @property
    def gateway_fqdn_or_ip(self) -> str:
        return self.gateway.host

    @gateway_fqdn_or_ip.setter
    def gateway_fqdn_or_ip(self, value: str) -> None:
        self.gateway.host = value

    @property
    def remote_id(self) -> str:
        return self.gateway.remote_id

    @remote_id.setter
    def remote_id(self, value: str) -> None:
        self.gateway.remote_id = value
        self.gateway.remote_id_mode = "custom" if value else "any"

    @property
    def local_id(self) -> str:
        return self.auth.eap_identity

    @local_id.setter
    def local_id(self, value: str) -> None:
        if value:
            self.auth.eap_identity = value

    @property
    def username(self) -> str:
        return self.auth.username

    @username.setter
    def username(self, value: str) -> None:
        self.auth.username = value

    @property
    def eap_identity(self) -> str:
        return self.auth.eap_identity or self.auth.username

    @eap_identity.setter
    def eap_identity(self, value: str) -> None:
        self.auth.eap_identity = value

    @property
    def secret_storage(self) -> SecretStorageMode:
        return self.auth.secret_storage

    @secret_storage.setter
    def secret_storage(self, value: SecretStorageMode) -> None:
        self.auth.secret_storage = "keyring" if value != "keyring" else value

    @property
    def transport(self) -> Transport:
        return self.gateway.transport

    @transport.setter
    def transport(self, value: Transport) -> None:
        self.gateway.transport = value

    @property
    def ike_port(self) -> int:
        return self.gateway.port

    @ike_port.setter
    def ike_port(self, value: int) -> None:
        self.gateway.port = value

    @property
    def request_virtual_ip(self) -> bool:
        return self.traffic.request_virtual_ip

    @request_virtual_ip.setter
    def request_virtual_ip(self, value: bool) -> None:
        self.traffic.request_virtual_ip = value

    @property
    def split_tunnel_enabled(self) -> bool:
        return self.traffic.mode == "split"

    @split_tunnel_enabled.setter
    def split_tunnel_enabled(self, value: bool) -> None:
        self.traffic.mode = "split" if value else "full"

    @property
    def remote_routes(self) -> list[str]:
        return self.traffic.remote_routes

    @remote_routes.setter
    def remote_routes(self, value: list[str]) -> None:
        self.traffic.remote_routes = list(value or [])

    @property
    def dns_servers(self) -> list[str]:
        return self.dns.servers if self.dns.enabled else []

    @dns_servers.setter
    def dns_servers(self, value: list[str]) -> None:
        self.dns.servers = list(value or [])
        self.dns.enabled = bool(self.dns.servers or self.dns.domains or self.dns.test_names)

    @property
    def dns_search_domains(self) -> list[str]:
        return self.dns.domains if self.dns.enabled else []

    @dns_search_domains.setter
    def dns_search_domains(self, value: list[str]) -> None:
        self.dns.domains = list(value or [])
        self.dns.enabled = bool(self.dns.servers or self.dns.domains or self.dns.test_names)

    @property
    def dns_test_names(self) -> list[str]:
        return self.dns.test_names

    @dns_test_names.setter
    def dns_test_names(self, value: list[str]) -> None:
        self.dns.test_names = list(value or [])

    @property
    def ike_proposals(self) -> list[str]:
        return self.crypto.ike_proposals

    @ike_proposals.setter
    def ike_proposals(self, value: list[str]) -> None:
        self.crypto.ike_proposals = list(value or DEFAULT_IKE_PROPOSALS)

    @property
    def esp_proposals(self) -> list[str]:
        return self.crypto.esp_proposals

    @esp_proposals.setter
    def esp_proposals(self, value: list[str]) -> None:
        self.crypto.esp_proposals = list(value or DEFAULT_ESP_PROPOSALS)

    @property
    def dpd_enabled(self) -> bool:
        return self.crypto.dpd_enabled

    @dpd_enabled.setter
    def dpd_enabled(self, value: bool) -> None:
        self.crypto.dpd_enabled = value

    @property
    def connection_name(self) -> str:
        return f"{CONNECTION_PREFIX}{self.id}"

    @property
    def legacy_connection_name(self) -> str:
        return f"{LEGACY_CONNECTION_PREFIX}{self.id}"

    @property
    def child_name(self) -> str:
        return f"{self.connection_name}-child"

    @property
    def legacy_child_name(self) -> str:
        return f"{self.legacy_connection_name}-child"

    def to_dict(self, *, include_secrets: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "gateway": {
                "host": self.gateway.host,
                "port": self.gateway.port,
                "transport": self.gateway.transport,
                "remote_id": self.gateway.remote_id,
                "remote_id_mode": self.gateway.remote_id_mode,
            },
            "auth": {
                "ike_auth": self.auth.ike_auth,
                "eap_method": self.auth.eap_method,
                "username": self.auth.username,
                "eap_identity": self.eap_identity,
                "secret_storage": self.auth.secret_storage,
            },
            "traffic": {
                "mode": self.traffic.mode,
                "remote_routes": list(self.traffic.remote_routes),
                "request_virtual_ip": self.traffic.request_virtual_ip,
            },
            "dns": {
                "enabled": self.dns.enabled,
                "servers": list(self.dns.servers),
                "domains": list(self.dns.domains),
                "test_names": list(self.dns.test_names),
                "linux_strategy": self.dns.linux_strategy,
            },
            "crypto": {
                "ike_proposals": list(self.crypto.ike_proposals),
                "esp_proposals": list(self.crypto.esp_proposals),
                "dpd_enabled": self.crypto.dpd_enabled,
            },
            "platform": {
                "config_root": self.platform.config_root,
                "dns_interface": self.platform.dns_interface,
            },
            "notes": self.notes,
        }
        if include_secrets:
            data["auth"]["psk"] = self.psk
            data["auth"]["password"] = self.password
        return data

    def sanitized_dict(self, *, privacy_mode: bool = False) -> dict[str, Any]:
        data = self.to_dict(include_secrets=False)
        if privacy_mode:
            data["auth"]["username"] = "<redacted>"
            data["auth"]["eap_identity"] = "<redacted>"
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VpnProfile:
        payload = dict(data or {})
        if "profile_uuid" in payload and "id" not in payload:
            payload["id"] = payload.pop("profile_uuid")
        if any(key in payload for key in ("gateway", "auth", "traffic", "dns", "crypto")):
            return cls(
                id=str(payload.get("id") or uuid4()),
                name=str(payload.get("name", payload.get("profile_name", ""))),
                gateway=GatewayProfile(**_section(payload, "gateway", GatewayProfile)),
                auth=AuthProfile(**_section(payload, "auth", AuthProfile)),
                traffic=TrafficProfile(**_section(payload, "traffic", TrafficProfile)),
                dns=DnsProfile(**_section(payload, "dns", DnsProfile)),
                crypto=CryptoProfile(**_section(payload, "crypto", CryptoProfile)),
                platform=PlatformProfile(**_section(payload, "platform", PlatformProfile)),
                notes=str(payload.get("notes", "")),
                psk=str(_raw_section(payload, "auth").get("psk", "")),
                password=str(_raw_section(payload, "auth").get("password", "")),
            )
        return cls(
            id=str(payload.get("id") or uuid4()),
            profile_name=str(payload.get("profile_name", payload.get("name", ""))),
            gateway_fqdn_or_ip=str(payload.get("gateway_fqdn_or_ip", "")),
            remote_id=str(payload.get("remote_id", "")),
            remote_id_mode=str(
                payload.get(
                    "remote_id_mode",
                    "custom" if payload.get("remote_id") else "any",
                )
            ),  # type: ignore[arg-type]
            username=str(payload.get("username", "")),
            eap_identity=str(payload.get("eap_identity", "")),
            psk=str(payload.get("psk", "")),
            password=str(payload.get("password", "")),
            transport=str(payload.get("transport", "udp")),  # type: ignore[arg-type]
            ike_port=int(payload.get("ike_port", 500)),
            request_virtual_ip=bool(payload.get("request_virtual_ip", True)),
            split_tunnel_enabled=bool(payload.get("split_tunnel_enabled", True)),
            remote_routes=list(payload.get("remote_routes", []) or []),
            dns_enabled=bool(payload.get("dns_enabled", True)),
            dns_servers=list(payload.get("dns_servers", []) or []),
            dns_search_domains=list(payload.get("dns_search_domains", []) or []),
            dns_test_names=list(payload.get("dns_test_names", []) or []),
            dns_linux_strategy=str(payload.get("dns_linux_strategy", "auto")),  # type: ignore[arg-type]
            ike_proposals=list(payload.get("ike_proposals", []) or DEFAULT_IKE_PROPOSALS),
            esp_proposals=list(payload.get("esp_proposals", []) or DEFAULT_ESP_PROPOSALS),
            dpd_enabled=bool(payload.get("dpd_enabled", True)),
            notes=str(payload.get("notes", "")),
            secret_storage="keyring",
            platform_config_root=str(payload.get("platform_config_root", "auto")),  # type: ignore[arg-type]
            dns_interface=str(payload.get("dns_interface", "auto")),
        )


def _raw_section(payload: dict[str, Any], name: str) -> dict[str, Any]:
    value = payload.get(name, {})
    return dict(value) if isinstance(value, dict) else {}


def _section(payload: dict[str, Any], name: str, section_type: type[Any]) -> dict[str, Any]:
    value = _raw_section(payload, name)
    allowed = {field_info.name for field_info in fields(section_type)}
    return {key: item for key, item in value.items() if key in allowed}


def fortigate_default_profile() -> VpnProfile:
    return VpnProfile(
        name="FortiGate IKEv2",
        gateway_fqdn_or_ip="vpn.example.com",
        remote_id_mode="any",
        request_virtual_ip=True,
        split_tunnel_enabled=True,
        ike_proposals=list(DEFAULT_IKE_PROPOSALS),
        esp_proposals=list(DEFAULT_ESP_PROPOSALS),
        dpd_enabled=True,
        notes="FortiGate-compatible IKEv2 EAP-MSCHAPv2 profile.",
        secret_storage="keyring",
    )

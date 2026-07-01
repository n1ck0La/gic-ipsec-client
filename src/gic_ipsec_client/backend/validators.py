from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import ip_address, ip_network
from uuid import UUID

from gic_ipsec_client.backend.models import VpnProfile

SAFE_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$")
HOST_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$")
PROPOSAL_RE = re.compile(r"^[A-Za-z0-9_+.-]+(?:-[A-Za-z0-9_+.-]+)*$")
SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f{}$`;&|<>]*$")


class ProfileValidationError(ValueError):
    """Raised when profile validation finds one or more user-facing errors."""

    def __init__(self, errors: Iterable[str] | str) -> None:
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


def validate_profile_name(name: str) -> None:
    if not name:
        raise ProfileValidationError("Profile name is required.")
    if not SAFE_PROFILE_NAME_RE.fullmatch(name):
        raise ProfileValidationError(
            "Profile name may contain only letters, numbers, spaces, '.', '_' and '-'."
        )
    if name in {".", ".."}:
        raise ProfileValidationError("Profile name cannot be '.' or '..'.")


def validate_uuid(profile_id: str) -> None:
    try:
        UUID(profile_id)
    except (TypeError, ValueError) as exc:
        raise ProfileValidationError("Profile id must be a UUID.") from exc


def _is_valid_hostname(value: str) -> bool:
    if len(value) > 253 or not DOMAIN_RE.fullmatch(value):
        return False
    return all(HOST_LABEL_RE.fullmatch(label) for label in value.rstrip(".").split("."))


def validate_gateway(value: str) -> None:
    if not value:
        raise ProfileValidationError("Gateway FQDN or IP is required.")
    try:
        ip_address(value)
        return
    except ValueError:
        pass
    if not _is_valid_hostname(value):
        raise ProfileValidationError("Gateway must be a valid IP address or DNS name.")


def validate_cidr(route: str) -> None:
    if "/" not in route:
        raise ProfileValidationError(f"Remote route '{route}' must be in CIDR notation.")
    try:
        ip_network(route, strict=False)
    except ValueError as exc:
        raise ProfileValidationError(f"Remote route '{route}' is not valid CIDR.") from exc


def validate_ip(value: str, *, field_name: str) -> None:
    try:
        ip_address(value)
    except ValueError as exc:
        raise ProfileValidationError(f"{field_name} '{value}' is not a valid IP address.") from exc


def validate_domain(value: str, *, field_name: str) -> None:
    if not _is_valid_hostname(value):
        raise ProfileValidationError(f"{field_name} '{value}' is not a valid DNS domain.")


def validate_proposal(value: str, *, field_name: str) -> None:
    if not PROPOSAL_RE.fullmatch(value):
        raise ProfileValidationError(f"{field_name} proposal '{value}' contains unsafe characters.")


def _validate_safe_text(value: str, *, field_name: str, errors: list[str]) -> None:
    if not SAFE_TEXT_RE.fullmatch(value):
        errors.append(f"{field_name} contains unsafe control or shell metacharacters.")


def validate_profile(profile: VpnProfile, *, require_secrets: bool = True) -> None:
    """Validate a profile before rendering or passing it to privileged code."""

    errors: list[str] = []

    for label, check in (
        ("profile_name", lambda: validate_profile_name(profile.profile_name)),
        ("id", lambda: validate_uuid(profile.id)),
        ("gateway_fqdn_or_ip", lambda: validate_gateway(profile.gateway_fqdn_or_ip)),
    ):
        try:
            check()
        except ProfileValidationError as exc:
            errors.extend(f"{label}: {message}" for message in exc.errors)

    if profile.transport not in {"udp", "tcp", "auto"}:
        errors.append("transport must be one of: udp, tcp, auto.")
    if not 1 <= int(profile.ike_port) <= 65535:
        errors.append("ike_port must be between 1 and 65535.")
    if require_secrets and not profile.psk:
        errors.append("psk is required before rendering strongSwan secrets.")
    if require_secrets and not profile.password:
        errors.append("password is required before rendering strongSwan secrets.")

    identity = profile.eap_identity or profile.username
    if require_secrets and not identity:
        errors.append("username or eap_identity is required for EAP-MSCHAPv2.")

    for field_name, value in (
        ("remote_id", profile.remote_id),
        ("local_id", profile.local_id),
        ("username", profile.username),
        ("eap_identity", profile.eap_identity),
        ("notes", profile.notes),
    ):
        _validate_safe_text(value, field_name=field_name, errors=errors)

    for route in profile.remote_routes:
        try:
            validate_cidr(route)
        except ProfileValidationError as exc:
            errors.extend(exc.errors)

    for dns_server in profile.dns_servers:
        try:
            validate_ip(dns_server, field_name="DNS server")
        except ProfileValidationError as exc:
            errors.extend(exc.errors)

    for domain in profile.dns_search_domains:
        try:
            validate_domain(domain, field_name="DNS search domain")
        except ProfileValidationError as exc:
            errors.extend(exc.errors)

    for proposal in profile.ike_proposals:
        try:
            validate_proposal(proposal, field_name="IKE")
        except ProfileValidationError as exc:
            errors.extend(exc.errors)

    for proposal in profile.esp_proposals:
        try:
            validate_proposal(proposal, field_name="ESP")
        except ProfileValidationError as exc:
            errors.extend(exc.errors)

    if errors:
        raise ProfileValidationError(errors)

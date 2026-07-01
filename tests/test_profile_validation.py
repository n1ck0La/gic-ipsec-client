from __future__ import annotations

import pytest

from gic_ipsec_client.backend.models import VpnProfile
from gic_ipsec_client.backend.validators import ProfileValidationError, validate_profile


def valid_profile() -> VpnProfile:
    return VpnProfile(
        id="00000000-0000-4000-8000-000000000000",
        profile_name="Work VPN",
        gateway_fqdn_or_ip="vpn.example.com",
        remote_id="vpn.example.com",
        username="alice",
        eap_identity="alice",
        psk="super-secret-psk",
        password="user-password",
        remote_routes=["10.0.0.0/8"],
        dns_servers=["10.0.0.53"],
        dns_search_domains=["corp.example.com"],
    )


@pytest.mark.parametrize("name", ["../bad", "bad;rm", "bad/name", "", "."])
def test_profile_validation_rejects_unsafe_names(name: str) -> None:
    profile = valid_profile()
    profile.profile_name = name

    with pytest.raises(ProfileValidationError):
        validate_profile(profile)


def test_profile_validation_rejects_invalid_cidr() -> None:
    profile = valid_profile()
    profile.remote_routes = ["10.0.0.0/not-a-prefix"]

    with pytest.raises(ProfileValidationError) as exc:
        validate_profile(profile)

    assert "CIDR" in str(exc.value)


def test_profile_validation_accepts_fortigate_defaults() -> None:
    validate_profile(valid_profile())


def test_profile_validation_requires_secrets_for_rendering() -> None:
    profile = valid_profile()
    profile.psk = ""

    with pytest.raises(ProfileValidationError) as exc:
        validate_profile(profile)

    assert "psk is required" in str(exc.value)

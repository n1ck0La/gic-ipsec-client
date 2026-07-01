from __future__ import annotations

from gic_ipsec_client.backend.diagnostics import (
    PSK_IDENTITY_MISMATCH_HINT,
    diagnostic_hints,
    redact_mapping,
    redact_text,
)


def test_diagnostics_redaction_catches_password_patterns() -> None:
    text = """
    psk = topsecret
    psksecret fortigate-secret
    password: "hunter2"
    secret = "ike-secret"
    eap password = eap-secret
    """

    redacted = redact_text(text)

    assert "topsecret" not in redacted
    assert "fortigate-secret" not in redacted
    assert "hunter2" not in redacted
    assert "ike-secret" not in redacted
    assert "eap-secret" not in redacted
    assert redacted.count("<redacted>") >= 5


def test_diagnostics_redaction_keeps_username_without_privacy_mode() -> None:
    text = "username = alice\npassword = secret"

    redacted = redact_text(text)

    assert "alice" in redacted
    assert "secret" not in redacted


def test_diagnostics_redaction_privacy_mode_hides_username() -> None:
    text = "username = alice\neap_identity = alice@example.com\npassword = secret"

    redacted = redact_text(text, privacy_mode=True)

    assert "alice" not in redacted
    assert "alice@example.com" not in redacted
    assert "secret" not in redacted


def test_redact_mapping_redacts_nested_secret_keys() -> None:
    payload = {
        "profile": {
            "username": "alice",
            "psk": "psk-value",
            "nested": {"password": "password-value"},
        }
    }

    redacted = redact_mapping(payload)

    assert redacted["profile"]["username"] == "alice"
    assert redacted["profile"]["psk"] == "<redacted>"
    assert redacted["profile"]["nested"]["password"] == "<redacted>"


def test_diagnostics_hint_for_shared_key_identity_mismatch() -> None:
    hints = diagnostic_hints(
        "IKE_AUTH request failed: no shared key found for '192.168.20.8' - '185.244.158.240'"
    )

    assert hints == [PSK_IDENTITY_MISMATCH_HINT]

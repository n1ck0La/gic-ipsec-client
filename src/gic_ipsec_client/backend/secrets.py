from __future__ import annotations

SERVICE_NAME = "gic-ipsec-client"


class SecretStorageUnavailable(RuntimeError):
    """Raised when no secure desktop keyring is available."""


def _get_keyring_module() -> object:
    try:
        import keyring
    except ImportError as exc:
        raise SecretStorageUnavailable("Python keyring is not installed.") from exc
    return keyring


def secure_keyring_available() -> bool:
    try:
        keyring = _get_keyring_module()
        backend = keyring.get_keyring()
    except SecretStorageUnavailable:
        return False
    backend_name = backend.__class__.__name__.lower()
    module_name = backend.__class__.__module__.lower()
    insecure_markers = ("plaintext", "fail", "null")
    return not any(marker in backend_name or marker in module_name for marker in insecure_markers)


def save_profile_secrets(profile_id: str, *, psk: str, password: str) -> None:
    if not secure_keyring_available():
        raise SecretStorageUnavailable(
            "No secure keyring/libsecret backend is available; refusing plaintext secret storage."
        )
    keyring = _get_keyring_module()
    keyring.set_password(SERVICE_NAME, f"{profile_id}:psk", psk)
    keyring.set_password(SERVICE_NAME, f"{profile_id}:password", password)


def load_profile_secrets(profile_id: str) -> tuple[str | None, str | None]:
    if not secure_keyring_available():
        raise SecretStorageUnavailable("No secure keyring/libsecret backend is available.")
    keyring = _get_keyring_module()
    return (
        keyring.get_password(SERVICE_NAME, f"{profile_id}:psk"),
        keyring.get_password(SERVICE_NAME, f"{profile_id}:password"),
    )


def delete_profile_secrets(profile_id: str) -> None:
    if not secure_keyring_available():
        return
    keyring = _get_keyring_module()
    for suffix in ("psk", "password"):
        try:
            keyring.delete_password(SERVICE_NAME, f"{profile_id}:{suffix}")
        except Exception:
            continue

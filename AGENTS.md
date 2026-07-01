# AGENTS.md

GIC is intentionally small and auditable.

- Do not implement IPsec, IKEv2, ESP, cryptography, packet capture, or a password store.
- Use strongSwan `swanctl`/VICI as the backend.
- Keep privileged operations inside `gic-ipsec-helper`.
- Never use `shell=True`; command execution must use argument arrays.
- Validate profile data before rendering strongSwan configuration.
- Redact PSKs and passwords in logs, diagnostics, tests, and debug bundles.
- Keep GUI code separate from backend and helper code.

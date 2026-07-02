# Security Model

GIC IPsec Client is a GUI and orchestration layer around system strongSwan. The
desktop GUI runs as the normal user. Root-only work is delegated to `gic-ipsec-helper`
through `pkexec`.

## Boundaries

- The GUI never writes directly to system `swanctl` config roots.
- The helper accepts structured subcommands only.
- The helper reads JSON request files only from
  `/run/user/<uid>/gic-ipsec-client/helper-requests`.
- Request files must be owned by the invoking user, must not be symlinks, and
  must not be group- or world-writable.
- Rendered config filenames are derived from validated UUIDs.
- Profile deletion accepts UUIDs only and deletes only `gic-<uuid>` files
  under the known system `swanctl` roots.

## Commands

All process execution uses argument arrays. GIC must not call arbitrary shell
strings and must not use `shell=True`.

## Secrets

The GUI can ask for secrets every time or save them through Python keyring with a
secure libsecret-compatible backend. If no secure keyring is available, GIC
warns and refuses plaintext local storage.

Root-side strongSwan secret material exists because strongSwan needs it. Flat
profile files that contain secrets are written by the helper with mode `0600`
and root ownership when the helper runs as root.

Diagnostics and debug bundles redact PSKs, passwords, generic `secret` fields,
and FortiGate `psksecret` lines. Username redaction is available through privacy
mode.

## Out Of Scope

GIC does not implement IPsec, IKEv2, ESP, cryptography, packet capture, a kernel
tunnel, or its own password store.

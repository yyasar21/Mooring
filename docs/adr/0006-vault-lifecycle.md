# ADR-0006: Vault lifecycle — calibration, auto-lock, keyring wrap, export

Status: Accepted · 2026-11-03 (Phase A1)

## Context
ADR-0002 fixed the vault crypto. A1 needs the operational surface around it: KDF cost that
fits the host, locking without user action, optional biometric unlock, and a portable backup
that an independent tool (`age`) can read.

## Decision

### Calibration
- `KdfParams::calibrate(target: Duration, max_m_kib: u32) -> KdfParams` measures Argon2id on
  the host and picks the largest memory cost in `{64, 128, 256, 512, 1024} MiB` (≤ `max_m_kib`,
  ≤ 1/4 of physical RAM, never below `FLOOR`) whose single derivation finishes within
  `target` (default 500 ms, `t = 3`, `p = min(4, available cores)`). Measured on `TEST`-shaped
  params and scaled linearly in memory; the final candidate is verified by one real run.
- The chosen params are stored in the header (already authenticated as AAD). Calibration runs
  once at vault creation and on password change; never silently on unlock.

### Auto-lock
- Policy lives in `nexus_vault::autolock::AutoLockPolicy { idle: Option<Duration>, on_screen_lock: bool, on_sleep: bool, on_window_hidden: bool }`;
  default idle 15 min, all triggers on. `AutoLockClock` tracks the last activity instant and
  answers `should_lock(now)`; it is pure and unit-tested.
- The Tauri layer (`src-tauri/src/autolock.rs`) feeds activity (any IPC command) and OS
  signals (window focus/blur, `tauri::RunEvent`, OS sleep/lock notifications where the
  platform exposes them) into the clock on a 5 s tick and calls `Vault::lock()`; locking emits
  an audit entry `vault.lock` with `reason ∈ {user, idle, screen_lock, sleep, window_hidden}`.
- Open sessions survive a lock (they hold no vault reference, ADR-0004); new sessions and
  reveals require unlock.

### Keyring wrap (opt-in "unlock with Touch ID / Windows Hello")
- When enabled, a second wrap of the DEK is produced under a random 32-byte `WrapKey` and
  stored in the header as `keyring_wrap: Option<Sealed>` (AAD = header AAD ‖ "keyring"). The
  `WrapKey` is stored in the OS keyring (`keyring` crate: macOS Keychain with
  `kSecAccessControlBiometryCurrentSet`, Windows Credential Manager, Secret Service on Linux)
  under service `xyz.homelab.nexus`, account = `vault_id`.
- A1 ships the vault-side wrap only. The OS keyring commands stay unwired until the item
  carries a biometric/user-presence ACL on macOS (data-protection keychain,
  `BiometryCurrentSet`), uses Local persistence on Windows, and is explicit opt-in with a
  warning on Linux (security review ruling a, M1). `change_password` drops the wrap; the Tauri
  command re-wraps, persists, then deletes the stale keyring item and audits it (ruling c).
- Unlock path: OS prompt → `WrapKey` → unwrap DEK. Master password remains mandatory for
  create, change password, export and disabling the wrap; biometric unlock is a convenience,
  not a replacement. Disabling deletes the keyring item and clears `keyring_wrap`.
- Header format bumps to version 2 (adds `vault_id: Uuid`, `keyring_wrap: Option<Sealed>`);
  v1 headers are read and upgraded on the next successful *password* unlock (only the
  password-derived KEK can re-wrap the DEK); if persisting the upgraded header fails the vault
  is locked again (security review L1). Both fields are part of the header AAD.

### Export
- `nexus vault export --age <out>` writes an `age` (v1 format, scrypt passphrase recipient)
  armored file containing a JSON document: header (v2), every credential record with sealed
  fields, folders and connections. The passphrase is a *separate* export password (≥ 12 chars),
  never the master password. The payload is still sealed per field; `age` adds a portable
  outer layer so a backup is readable without Nexus. Import is the reverse and refuses a
  payload whose `vault_id` differs unless `--merge` is given (A3).
- Export scrypt work factor is pinned to log N = 18; import refuses log N > 20 (≈ 1 GiB)
  so a hostile file cannot exhaust memory (ruling d, L5).
- Dependency: `age` crate (RustCrypto primitives, pure Rust, `armor` feature). Justification:
  interoperable, audited, passphrase recipients built in; writing our own container would be
  rolling crypto.
- Test vectors: `crates/nexus-vault/tests/vectors/` holds `header.json`, `sealed.json`
  (record id, field, plaintext, sealed) produced with `KdfParams::TEST` and a fixed password
  from `vectors/README` so the *format* is pinned; and `export.age` with its export
  passphrase so CI (and a human with the `age` CLI) can decrypt and compare.

## Alternatives considered
- Storing the DEK itself in the OS keyring: a keyring dump yields the DEK directly; the
  wrap-key indirection lets the header AAD still bind the wrap. Rejected.
- Deriving the keyring key from the master password: defeats the purpose (no password at
  unlock). Rejected.
- Tarball export of `nexus.db` + header: not independently verifiable. Rejected.

## Security consequences
Biometric unlock widens T2: a process that can read the keyring item under the user's session
*and* the header can unwrap the DEK. Accepted as opt-in, documented in the threat model, and
the biometric ACL on macOS/Windows limits silent reads. Calibration never lowers below the
floor and is bounded by RAM; header parsing enforces a ceiling (`m ≤ 4 GiB, t ≤ 16, p ≤ 16`)
and derivation refuses memory above half of physical RAM, so a hostile header cannot cause OOM.

## Test plan
Calibration monotonic + floor + RAM cap (mock timer); auto-lock clock table tests; header v1 →
v2 upgrade; keyring wrap round trip with an in-memory keyring mock; export/import round trip;
vectors decrypt with the `age` CLI in CI (`tests/vectors.yml`).

# A5 — rust-core R2: biometric unlock (ADR-0022) and `age` backup export / import (ADR-0023)

Branch `worktree-agent-adad73a4b87da9270`, worktree
`/home/claude/nexus/.claude/worktrees/agent-adad73a4b87da9270`, rebased on `main`. Resumed
from an earlier session that a rate limit cut off. Owner decisions applied: 23 (Touch ID
needs a signed build, Windows Hello ships), 24 (3 failures in 10 min), 25 (`keyring` removed),
26 (merge by default, replace behind a typed confirmation), 27 (foreign import needs the source
master password), 28 (trust stores exported and unioned).

## Done

### Biometric unlock (ADR-0022)
- `src-tauri/src/biometric/{mod,macos,windows,linux}.rs`. The store holds or derives the
  32-byte `WrapKey` of ADR-0006. It never sees the master password or the DEK. All shared
  logic lives in `mod.rs` and has unit tests: `BiometricStore` trait, `BioError` /
  `Unavailable` with fixed reasons, `Adapter` (to the vault's `WrapKeyStore`, remembers the
  last OS error), `Prefetched` (the OS prompt runs **without** the vault mutex held),
  `BiometricRuntime` (store + failure window), the HKDF derivation for Windows Hello
  (`HKDF-SHA256(ikm = signature, salt = vault_id, info = "mooring hello v1")`, with a test
  vector) and the challenge `"mooring-hello-v1" ‖ vault_id`. There is also a scriptable
  `memory` store for tests and `test-util`.
- macOS (`TouchIdStore`): the item is in the data-protection keychain with
  `SecAccessControl(AccessibleWhenUnlockedThisDeviceOnly, BIOMETRY_CURRENT_SET)` and is
  created through the safe API of `security-framework` 3.7. A new enrolment deletes the old
  item first and then adds the new one. **Gate:** `biometric::SIGNED_BUILD =
  cfg!(mooring_signed_build)`. An unsigned build answers `unsigned_build` and never touches
  the keychain. A signed build runs one passive probe on a never-created account
  (`errSecMissingEntitlement` → `unsigned_build`). OSStatus mapping: −128 → cancelled;
  −25300 / −25293 → `biometry_changed`; −34018 → unsigned; −25308 → keychain unavailable.
- Windows (`HelloStore`): `KeyCredentialManager::{IsSupportedAsync, RequestCreateAsync
  (ReplaceExisting), OpenAsync, RequestSignAsync, DeleteAsync}`, joined synchronously on the
  blocking pool. Signatures are capped at 1 KiB. `KeyCredentialStatus` mapping: `NotFound` →
  `biometry_changed`, `UserCanceled` → cancelled, `UserPrefersPassword` /
  `SecurityDeviceLocked` → unavailable.
- Linux (`NoStore`): every call answers `no_acl`, and deleting is a no-op.
- `mooring-vault`: new method `WrapKeyStore::create` (by default it draws a random key and
  `put`s it). A deriving store overrides it, so the vault never hands Hello a key.
  `enable_keyring_unlock` now asks the store for the key before it replaces the header.
- Commands (`commands/vault_biometric.rs`): `biometric_status` (passive, works while locked,
  added to `ipc-passive.json`), `biometric_enroll({password})`, `biometric_unlock()`,
  `biometric_disable({password})`. Two app settings: `app.biometric` (the enrolment marker)
  and `app.biometric_suspended` (the reason).
- Auto-disable (`suspend`): this deletes the OS item at once, records the reason and audits
  `vault.biometric_suspended`. Triggers:
  - `failed_attempts`: the 3rd cancel or failure within 10 min. A key that does not open the
    wrap also counts. A success resets the window.
  - `biometry_changed`: the item or key is gone.
  - `password_changed`: from `vault_change_password`.
  - `vault_rotated`: from `vault_join`, and from a `replace` import of a foreign file.

  The inert header wrap is cleared on the next **password** unlock. Re-enrolling clears the
  reason.
- `keyring` removal: `src-tauri/src/keyring_store.rs` is deleted. If a password unlock finds
  a header wrap without the enrolment marker, that wrap is a legacy ADR-0006 keyring wrap. It
  is dropped and audited `keyring.removed`. **The `keyring` crate is now unused in all code**
  (see Decision needed).
- Audit events (`crates/mooring-audit/src/event/a5.rs`): `vault.biometric_enabled`,
  `vault.unlock_biometric`, `vault.biometric_failed {reason}`, `vault.biometric_suspended`,
  `vault.biometric_disabled`, `keyring.removed`, `vault.exported {counts}`,
  `vault.import {mode, foreign, counts}`, `vault.import_refused {code}`. The old
  `VaultExported {format}` variant was never written, so it is gone.

### Export / import (ADR-0023)
- `mooring-vault::export`: new byte-level API `export_age_bytes[_with_work_factor]` /
  `import_age_bytes`. It has the same caps and errors as before, and the v1 vectors are
  unchanged. `Header::check` is now public, so a foreign header passes the ADR-0002 floor and
  ceiling before any KDF runs.
- `mooring-sync::export` (document v2): it holds `{version: 2, header (no keyring_wrap),
  snapshot, exported_at, app_version}`. Tombstones are dropped on export and ignored on
  import. Parsing is hostile-safe: `deny_unknown_fields`, **duplicate JSON keys refused**, one
  id namespace across tables, an acyclic folder graph with a single root, known kinds and
  protocols, sealed blobs must parse, metadata ≤ 64 characters with no control characters,
  plus the snapshot caps. A file that fails any check is refused as a whole.
  `reseal_snapshot(from, to)` refuses on the first secret that does not open. The fuzz entry
  is `mooring_sync::fuzz::fuzz_export_document_json`. A v1 document still parses (`Imported::V1`).
- Commands:
  - `commands/vault_export.rs`: `vault_export_pick` uses the native **save** dialog from Rust
    (`LocalPicker::pick_save`, `.age` is appended) and refuses the app data dir.
    `vault_export_age` needs the unlocked vault and the master password, which is checked
    against a scratch header copy (the live vault is untouched). The export passphrase must
    be ≥ 12 characters and differ from the master password. The file is written to `.part`
    with mode 0600, fsynced and renamed into place. The pick survives refusals.
  - `commands/vault_import.rs`: `vault_import_pick` refuses files over 64 MiB with
    `vault.import_too_large` before reading. `vault_import_inspect` reads, decrypts and
    validates the file and then **holds** the document (`vault_import_hold.rs`: single use,
    10 min, at most 4 held, cleared on lock). A wrong passphrase keeps the pick for 3 tries.
    `vault_import_age` checks the master password. A foreign file needs the source password:
    the foreign header unlocks in memory, every secret is resealed under our DEK, and our
    `vault_id` is kept. Two modes:
    - `merge` keeps our root (the file's root children are moved under it), runs
      `mooring_sync::merge(None, local, file)` and unions the trust stores. A connection or
      credential changed on both sides keeps both copies (the copy is renamed
      `… (imported YYYY-MM-DD)`). A folder changed on both sides follows the merge's rule: the
      newer `updated_at` stays, and the conflict is reported as `last_writer_wins`. Folders
      hold no secret. Credentials whose secrets open to the same plaintext count as
      unchanged (sealing uses random nonces).
    - `replace` (needs `confirm: "REPLACE"`) applies the file's rows and trust files as they
      are.

    Both modes write the store in one transaction through `snapshot::apply`.
  - v1 backups are refused with `vault.import_version`: their records carry no kind or name.
- `Settings::fast_exports` (tests only) sets scrypt log N = 10. Production uses 18.

### IPC
- `guard/table.rs`, `lib.rs` `generate_handler!` and `permissions/mooring-main.toml` gain 9
  rows, all `Scope::Main`. **No capability file changed.** Goldens are re-blessed
  (`ipc-codes.json`, `ipc-manifest.json`, `ipc-passive.json`).
- New codes: `biometric.unavailable`, `biometric.cancelled`, `biometric.failed`,
  `biometric.suspended`, `biometric.not_enrolled`, `biometric.sync_enabled`, `vault.export`,
  `vault.export_passphrase`, `vault.import_format`, `vault.import_passphrase`,
  `vault.import_source_password`, `vault.import_too_large`, `vault.import_version`. Reused
  codes: `input.invalid` (`pick`, `mode`, `confirm`), `vault.unlock`, `vault.locked`.

## UI contract (ui-engineer, mock IPC first)
```
biometric_status() -> { available, enabled, platform: "macos"|"windows"|"linux",
  label: "Touch ID"|"Windows Hello"|null,
  reason: "ok"|"no_acl"|"unsigned_build"|"keychain_unavailable"|"not_enrolled"|"suspended",
  suspendedReason: "failed_attempts"|"password_changed"|"biometry_changed"|"vault_rotated"|null }
biometric_enroll({ password }) -> BiometricStatus      # vault unlocked; OS prompt
biometric_unlock() -> "unlocked"                         # vault locked; OS prompt; no secret crosses
biometric_disable({ password }) -> BiometricStatus       # works locked or unlocked
vault_export_pick() -> { pickId, name } | null
vault_export_age({ pickId, password, exportPassphrase }) -> { bytes, credentials, connections, folders }
vault_import_pick() -> { pickId, name, bytes } | null
vault_import_inspect({ pickId, exportPassphrase }) -> { vaultId, sameVault, exportedAt, appVersion,
  counts: { folders, connections, credentials, trust }, needsSourcePassword }
vault_import_age({ pickId, password, sourcePassword|null, mode: "merge"|"replace", confirm|null })
  -> { mode, added, updated, conflicts: [{ kind, id, name, resolution: "kept_both"|"last_writer_wins"|"kept_edit" }], skipped }
```
- Show the `reason` texts in Settings. `unsigned_build` → "Touch ID needs a signed build".
  `no_acl` → explain that Linux has no biometric ACL. Show `biometric.suspended` once after a
  password unlock (`suspendedReason`). Never start a prompt without a user action.
- In the `replace` flow the UI asks the user to type `REPLACE` and sends it as `confirm`.
  Rust enforces this. Offer an export first.
- `biometric.sync_enabled`: enrolment is refused while sync is configured (ADR-0017 §2
  forbids a header wrap in the bucket).
- **Names differ from ADR-0022 §2 (`vault_biometric_*`).** These are the names in the R2 brief
  (`biometric_*`, `enroll`). Rename on either side if the orchestrator prefers the ADR names.
- `vault_import_age` takes no `exportPassphrase`: the passphrase is used once in `inspect`.

## Left open
- **Fuzz:** `fuzz/` belongs to qa. It needs to wire `export_document_json` →
  `mooring_sync::fuzz::fuzz_export_document_json`. A proptest stand-in runs in the sync tests.
- Real-hardware checks (ADR-0022 test plan, manual gate):
  - Windows: is the Hello signature deterministic on every KSP? The derivation depends on it.
    If it is not, unlock answers `biometric.failed` and suspends after 3 tries, so it fails
    safe. The fallback is a stored challenge, which needs header v3.
  - macOS: the Touch ID flows in a signed build, and `security find-generic-password` must
    fail from Terminal.
- macOS and Windows modules are written against the crate sources and cannot be compiled on
  Linux. The CI matrix must compile them, which needs Decision needed item 1.
- The enrolment prompt (`create`) still runs while the vault mutex is held, inside
  `enable_keyring_unlock`. The unlock prompt does not. Splitting enrolment would need a vault
  API change.
- On a `replace` of a *same-vault* file the biometric enrolment stays: the DEK and the id are
  unchanged.

## Decision needed (orchestrator, manifests)
1. **`src-tauri/Cargo.toml`: `security-framework = { version = "3.7", features = ["OSX_10_15"] }`.**
   Without this, `PasswordOptions::use_protected_keychain` does not exist and the macOS build
   fails. It used to come in through `keyring`'s `apple-native-keyring-store/protected`.
2. Remove `keyring` from `src-tauri/Cargo.toml` and from `[workspace.dependencies]`, then
   regenerate the lockfile (`zbus` goes with it). No code uses it any more.
3. Add `[lints.rust] unexpected_cfgs = { level = "warn", check-cfg = ['cfg(mooring_signed_build)'] }`
   to `src-tauri/Cargo.toml`, then drop the item-level `#[allow(unexpected_cfgs)]`.
4. Release engineer: build Developer-ID-signed macOS bundles with
   `RUSTFLAGS="--cfg mooring_signed_build"`. They must also carry the `keychain-access-groups`
   entitlement (ADR-0018 A1).
5. Security review: the T-BIO and R-BIO-PROMPT rows; the 9 new `mooring-main` permissions;
   the new gate / reason matrix.

## Test evidence
Run on Linux in this worktree after `git rebase main` (c2c77a2), with the shared
`CARGO_TARGET_DIR`. Sources were re-touched before every run because sibling worktrees
write artifacts with the same fingerprints.
- `cargo fmt --all --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. A second
  `-p mooring-app --all-targets` run after the last test edits is also clean.
- `MOORING_BLESS=1 cargo test -p mooring-app --lib golden`: blessed `ipc-codes.json`,
  `ipc-manifest.json` and `ipc-passive.json`.
- `cargo test -p mooring-vault -p mooring-app -p mooring-sync -p mooring-audit`: all green.

  | Suite | Result |
  | --- | --- |
  | mooring-app lib | 406 passed, 1 ignored (pre-existing) |
  | mooring-app e2e_flow | 51 passed |
  | mooring-audit | 37 passed |
  | mooring-sync lib | 41 passed |
  | mooring-sync fuzz_corpus / hostile_blob / hostile_s3 | 4 / 7 / 5 passed |
  | mooring-vault lib | 56 passed, 2 ignored |
  | mooring-vault integration tests (autolock, calibration, fuzz corpus, proptest, vectors) | 3 / 7 / 3 / 2 / 3 passed |

- New tests:
  - `biometric::tests`: HKDF vector, cross-checked with Python's `hmac`.
  - `vault_biometric_tests`: 11 tests (status matrix, enrol / unlock, 3-in-10-min rule,
    spread failures, `biometry_changed`, `password_changed`, disable, legacy wrap,
    `vault_rotated`, wrong key).
  - `vault_export_tests`: 4. `vault_import_tests`: 6 (same-vault merge, foreign with the
    source password, replace confirmation, trust union, hostile files, v1 refusal and lock).
  - `vault_import_hold`: 1. mooring-sync `export_tests`: 8, including the proptest
    stand-in for the fuzz target.
  - mooring-vault: byte API and the deriving-store test.
  - `e2e_flow::gate_matrix`: 6 new vault-gated rows (`vault_gated_codes_a5_vault`);
    `biometric_status`, `biometric_unlock` and `biometric_disable` are in `NOT_GATED`
    with reasons.
- macOS and Windows code is not compiled here (Linux host). See Decision needed item 1.

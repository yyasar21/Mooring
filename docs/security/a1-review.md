# A1 security review — vault lifecycle (ADR-0006) and mooring-store (ADR-0005)

Reviewer: security-reviewer · 2026-11-03 · Range `240f611..6a0acd0` (`crates`, `src-tauri`,
`Cargo.toml`, `Cargo.lock`). `mooring-app` was **not compiled** (no WebView toolchain here).

## Verdict: `BLOCKER` (superseded: see [Re-review](#re-review--fix-round-b256dcd1e76c3a), now `APPROVE WITH NITS`)

There are two blockers, B1 and B2. Both are latent. No IPC command reaches either path yet: the
keyring and import commands are not wired. Both break a guarantee that the next A1 step (Tauri
wiring of keyring, export and import) relies on, and each fix is about 10 lines. The code
already on `main` can stay there. **The keyring, export and import commands must not be wired
until B1 and B2 are fixed and tested.** Everything else is approved, with the nits below.

## Blockers

### B1 — A failed keyring enable/disable leaves a locked vault unlocked
- **Where:** `crates/mooring-vault/src/keyring.rs:104-116` (`enable_keyring_unlock`) and
  `:142-153` (`disable_keyring_unlock`).
- **What:** `unlock_with_kek` (line 105 / 143) puts the DEK into `self.dek`. The function then
  returns early with `?` when `store.put` (line 112) or `store.delete` (line 146) fails, so the
  `if was == VaultState::Locked { self.dek = None }` restore never runs. Reproduced against
  HEAD with a scratch crate:
  ```
  enable(locked, failing store)  -> Err(Keyring("denied")), state after = Unlocked
  disable(locked, failing store) -> Err(Keyring("denied")), state after = Unlocked
  ```
  The UI and auto-lock believe the vault is locked while the DEK sits in RAM. That breaks the
  "DEK dropped on lock" mitigation (T2). An OS keyring that refuses access (a common case:
  Secret Service locked, Keychain prompt cancelled) triggers it. The same early return also
  leaves a v1 header upgraded in memory (new `vault_id`) on the error path, which contradicts
  the comment "the header is left untouched".
  The test `enable_requires_password_and_failed_store_changes_nothing` checks only the header,
  and only on an unlocked vault, so it misses this.
- **Fix:** snapshot the header and state before calling `unlock_with_kek`, and restore both on
  *every* exit path:
  ```rust
  let (was, before) = (self.state(), self.header.clone());
  let result = (|| -> Result<(), VaultError> {
      let kek = self.unlock_with_kek(password)?;
      /* … existing body up to and including `self.header = header;` … */
      Ok(())
  })();
  if result.is_err() { self.header = before; }
  if was == VaultState::Locked { self.dek = None; }
  result
  ```
  (A private `fn …_inner(&mut self, …)` works if the closure fights the borrow checker.) Use
  the same shape in `disable_keyring_unlock`. Tests: for both functions, starting from a
  **locked** vault with the `Broken` store, assert `state() == Locked` and an unchanged header
  afterwards. Also add one test that starts from a v1 header.

### B2 — No KDF ceiling when reading a header (hostile header or import → OOM/CPU DoS)
- **Where:** `crates/mooring-vault/src/kdf.rs:49-56` (`KdfParams::validate`, floor only), called
  from `format.rs:158` (`Header::check`) and therefore from `Header::from_bytes`
  (`format.rs:122`) and `import_age` (`export.rs:138`).
- **What:** `validate` enforces only the floor and Argon2's own limits (`m` up to `u32::MAX`
  KiB = 4 TiB, `t` up to `u32::MAX`, `p` up to 2^24-1). A header with
  `{m_kib: u32::MAX, t: u32::MAX, p: 0xFFFFFF}` passes `Header::from_bytes`; this was
  reproduced against HEAD. `derive_kek` then runs `vec![Block; m/1]` and either aborts the
  process (`panic = "abort"`, allocation failure) or triggers the OOM killer, or it spins for
  effectively ever. ADR-0006 §Security consequences promises the opposite: "bounded by RAM so
  a hostile header cannot cause OOM". The import path is the important one: `import_age` takes
  a file from outside, and A3 merge will unlock the header inside it. A local header (T1/T2
  with write access) is a lesser case, because that attacker can also delete the file.
- **Fix:**
  1. `kdf.rs`: add
     `pub const CEILING: Self = Self { m_kib: 4 * 1024 * 1024, t: 16, p: 16 };` (4 GiB, 4× the
     largest calibration candidate). In `validate`, reject any field above it with
     `VaultError::KdfParams("above the maximum ceiling".into())`.
  2. `derive_kek`: before allocating, refuse `m_kib` above half of `physical_ram_kib()` (when
     known) with `VaultError::KdfParams("needs more memory than this host has".into())`. A
     header calibrated on a 64 GiB machine then fails cleanly on an 8 GiB laptop instead of
     swapping it to death.
  3. Tests: `structural_checks` gets `m_kib = u32::MAX`, `t = 17` and `p = 17` → `KdfParams`.
     An `import_age` test with such a header → `Export("invalid vault header in export")`.
     `calibrate_with` output always passes `validate` (already true by construction; assert
     it).

## Findings (non-blocking)

| ID | Sev | Where | Finding | Fix |
| --- | --- | --- | --- | --- |
| M1 | Medium | `src-tauri/src/keyring_store.rs:20-22` | `keyring::Entry::new` (v1 API) gives no access to store modifiers. On **Windows** the item is created with `CRED_PERSIST_ENTERPRISE` (the `windows-native-keyring-store` default), so in a domain with roaming profiles the wrap key **roams to other machines**. On **macOS** the v1 feature uses the legacy file keychain (`apple-native-keyring-store/keychain`), so no biometric ACL is possible. See decision (a). | Depend on `keyring-core` + the per-platform stores directly (the `keyring` 4 crate docs themselves advise this for apps), and build entries with `Entry::new_with_modifiers(SERVICE, id, &{"persistence": "Local"})` on Windows. Required before keyring unlock is exposed. |
| M2 | Medium | `src-tauri/src/lib.rs:28`, `crates/mooring-store/src/lib.rs:56` | The data dir is created with `create_dir_all` and `mooring.db`/`-wal`/`-shm` with SQLite defaults, so the umask applies (usually `0755`/`0644` on Linux and macOS). The plaintext inventory (hosts, names, usernames, topology) is then readable by other local accounts. The audit log is `0600`; the store should match. | Unix: create the data dir with `DirBuilder::new().mode(0o700)` (std `os::unix::fs::DirBuilderExt`, no unsafe), and `set_permissions(0o600)` on `mooring.db` before `Connection::open`. SQLite copies the db file's mode to `-wal`/`-shm`. Windows: the per-user AppData ACL is enough. Add a unix-only test. |
| L1 | Low | `src-tauri/src/commands.rs:129-134` | With a v1 header, if `save_header` fails after `unlock` the command returns `state.io`, but the vault stays **unlocked** in memory with a fresh, unpersisted `vault_id`. Each retry or restart mints another id, and the store's `set_vault_id` would later answer `VaultIdMismatch`. | On a `save_header` error, call `vault.lock()` before returning the error, so the next attempt starts clean. Also covers the UI/state mismatch. |
| L2 | Low | `src-tauri/src/state.rs:53-60` | The header write does tmp + rename without `sync_all`. The header is the *only* copy of the wrapped DEK: a crash right after the automatic v1→v2 rewrite (or a password change) can leave an empty or torn file and lose the vault. Pre-existing A0 code, but A1 now triggers it without user action. | `File::create(tmp)` → `write_all` → `sync_all` → rename; keep the previous header as `vault.header.json.bak` until the next successful unlock. |
| L3 | Low | `Cargo.toml:35` | `argon2` lacks the `zeroize` feature, so the Argon2 initial hash and final block hash (password-derived) are not wiped. The 256 MiB–1 GiB work area is not wiped either way through `hash_password_into`. | Add `"zeroize"` to the `argon2` features. Optionally call `hash_password_into_with_memory` with a buffer wiped after use. |
| L4 | Low | `crates/mooring-store/migrations/0001_init.sql:60-65` | The `secure_delete` pragma wipes freed b-tree pages, but FTS5 keeps deleted tokens in segment pages until a merge unless the FTS5 `secure-delete` option is on. The full rebuild on every open bounds the residue to one session; with WAL, deleted rows also persist in `-wal` until checkpoint. | Migration `0002`: `INSERT INTO search(search, rank) VALUES ('secure-delete', 1);` (bundled SQLite 3.54.1 supports it). On close: `PRAGMA wal_checkpoint(TRUNCATE)`. |
| L5 | Low | `crates/mooring-vault/src/export.rs:59-61` | The export uses age's per-host calibrated scrypt work factor, which can exceed the import cap of 2^20 on a fast machine. See decision (d). | Pin it: `export_age` calls `export_age_inner(doc, passphrase, Some(EXPORT_SCRYPT_LOG_N))` with `pub const EXPORT_SCRYPT_LOG_N: u8 = 18;`. Add a test that the stanza says `18`. |
| N1 | Nit | `crates/mooring-vault/src/crypto.rs:34` | `encrypt(..).unwrap_or_default()` silently produces an empty ciphertext. It fails closed on open, but the data is lost without an error. | Return `Result<Sealed, VaultError>` and map to `VaultError::Tampered` or a new `Seal` variant. It is unreachable in practice (plaintext above 256 GiB); this is about clarity. |
| N2 | Nit | `crates/mooring-vault/src/vault.rs` tests | A v1-relabelled-as-v2 forgery is tested, but the reverse is not: v2 → v1 downgrade with `vault_id`/`keyring_wrap` stripped. It is refused today by the AAD mismatch. | Add the test so a future change to `aad()` cannot open a downgrade path. |
| N3 | Nit | `crates/mooring-vault/src/export.rs` | Nothing enforces the "export passphrase ≠ master password" rule (ADR-0006). | The export command needs the master password anyway (ADR-0006), so compare the two there in constant time (`subtle`, already transitive) and refuse equality. |
| N4 | Nit | `crates/mooring-vault/src/keyring.rs:34` | The `MemoryWrapKeyStore` doc says "for platforms without a keyring". That invites a production fallback which would silently make keyring unlock a no-op. | Say "tests only" in the doc, or gate it behind `#[cfg(any(test, feature = "test-util"))]`. |

## Rulings on the four open decisions (vault handoff)

**(a) Keyring item without a biometric ACL → HOLD the OS keyring commands; SHIP the vault side.**
The crate-level wrap (`keyring_wrap`, AAD binding, `WrapKeyStore`) is approved as-is, after B1.
Do **not** wire `vault_keyring_enable` / `vault_unlock_keyring` on a platform until that
platform has the property ADR-0006 assumed:
- *macOS:* use `security-framework` (already transitive via `apple-native-keyring-store`, safe
  API, no unsafe in our code). Call `passwords::set_generic_password_options` with
  `PasswordOptions::set_access_control(SecAccessControl::create_with_protection(Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly), AccessControlOptions::BIOMETRY_CURRENT_SET.bits()))`.
  `apple-native-keyring-store`'s `protected` feature with the `access-policy=require-user-presence`
  modifier is the off-the-shelf alternative. It gives `USER_PRESENCE` (biometry *or* device
  passcode), not `BiometryCurrentSet`. Acceptable if the ADR is amended. Both need the
  data-protection keychain, so the app must be signed with a `keychain-access-groups`
  entitlement (release-engineer dependency).
- *Windows:* Credential Manager has no per-item ACL; any process as the user can call
  `CredRead`. For a Windows Hello gate, derive the `WrapKey` from a Hello key instead of
  storing it: create a `KeyCredentialManager` credential (`windows` crate, WinRT), then call
  `RequestSignAsync` on a fixed per-vault challenge. RSA PKCS#1 v1.5 signatures are
  deterministic, so `HKDF-SHA256(signature, info = vault_id ‖ "mooring-keyring")` gives the same
  `WrapKey` every time. Until then, Windows keyring unlock stays off. At minimum it must use
  `persistence=Local` (M1).
- *Linux:* Secret Service has no biometric ACL; an unlocked collection is readable by any
  process on the session bus. Ship it **off by default**, behind an explicit opt-in with a
  warning that keyring unlock there means "anyone running as you can unlock the vault".
- Recorded as risk R-T2-KR in the threat model.

**(b) v1→v2 header upgrade on password unlock → APPROVED.** Only the KEK can re-seal the v1
wrap, so the upgrade has to happen on a password unlock. Downgrade is not possible: a v2
header relabelled v1 fails the AAD check, and a v1 header relabelled v2 is tested. Conditions:
L1 (lock on persist failure) and L2 (durable write). Amend ADR-0006: "on the next successful
password unlock".

**(c) `change_password` drops the keyring wrap → APPROVED; do not auto-re-wrap.** A password
change does **not** rotate the DEK (ADR-0002). A stale keyring item plus an *old* header backup
therefore still yields the DEK; that is equivalent to old-password + old-header, and it must
not outlive the change. The Tauri `vault_change_password` command must, in order:
re-wrap → persist header → `store.delete(vault_id)` (best effort, audit `vault.keyring_disabled`
with `reason=password_change`, and warn the UI if the delete fails). Auto-re-wrap is rejected:
it would read the keyring item (a biometric prompt) inside a password change, and it would
carry keyring trust across a change that users often make *because* they suspect compromise.
Re-enabling generates a fresh `WrapKey` (`put` replaces).

**(d) Import scrypt cap 2^20 → APPROVED, and pin the export to 2^18 (L5).** 2^20 at r = 8 is
1 GiB and a few seconds: an acceptable worst case for a hostile file, and it is checked before
any work (age `ExcessiveWork`; covered by `hostile_inputs_are_refused`). Pin the export to
log N = 18, the same fixed value as the reference Go `age` CLI. That way a backup made on a
fast machine always imports on a slow one, with two steps of headroom for files produced by
other `age` tools. Offline guessing cost is carried by the ≥ 12-char passphrase rule, not by
per-host tuning.

## Checklist results

**1. Secret flow — pass.**
- Every new `tracing` call in the diff (24 lines grepped) logs ids, counts, KDF params, column
  names or fixed strings, never values.
- `VaultError` variants: `Keyring` and `Export` carry fixed strings. `Format` carries serde
  messages about the plaintext header. `StoreError` never echoes values (a test proves this
  for oversized secrets).
- `Debug` is hand-written for `Vault`, `MemoryWrapKeyStore` and `Store`. `Header` derives
  `Debug`, but it holds only ciphertext.
- `IpcError` maps the 3 new variants to stable codes, and their messages are the fixed strings.
- `open_credential_secret` and `import_age` return or use `Zeroizing` buffers. `import_age`
  copies the passphrase into age's own `SecretString` (zeroized on drop).
- Test fixtures: `nexus-test-vector-password` and `nexus-export-vector-passphrase` are
  intentional and documented in `tests/vectors/README.md`. The store tests use dummy literals.
  `gitleaks` is not installed here, so it was not run; allow-list
  `crates/mooring-vault/tests/vectors/` in `.gitleaks.toml` (orchestrator).

**2. Trust boundaries — pass (not compiled).**
- No new `#[tauri::command]`. The registered set (`lib.rs`) is unchanged.
- `vault_lock` now parses its reason through `LockReason::parse`. That is stricter than
  before (closed set; unknown → `user`) and adds `window_hidden`.
- `vault_unlock` persists the upgraded header (see L1).
- `keyring_store` is compiled in but unreachable (`#[allow(dead_code)]`).
- Capabilities and CSP are untouched.

**3. Crypto — pass, apart from B2, L3 and L5.**
- Primitives are RustCrypto only: argon2, chacha20poly1305, scrypt via age, hkdf/hmac/sha2.
  The `secret-service` backend uses its `crypto-rust` feature (aes/cbc/hkdf), and no
  `openssl` is in the lockfile.
- Nonces: a 24-byte random nonce per seal (`crypto.rs:20`). `seal_with_nonce` with a fixed
  nonce is used only by `seal_with` and the `#[cfg(test)]` vectors.
- AAD:
  - v1 AAD is byte-identical to A0 (tested).
  - v2 appends `0x1F ‖ vault_id(16)` and `0x1F ‖ {0 | 1 ‖ nonce ‖ ct}` for `keyring_wrap`.
    This is unambiguous: fixed-length fields, and the variable field comes last.
  - The keyring wrap AAD is the header AAD with `keyring_wrap = None`, then `‖ 0x1F ‖
    "keyring"`. That gives domain separation from the password wrap, and the binding to KDF
    params, salt and vault id is tested.
  - Moving the wrap to another vault id fails (tested).
- Zeroization: DEK, KEK and WrapKey are `Zeroizing`, and the DEK is cloned only into
  `Zeroizing`. L3 for Argon2 internals.
- Floor: still enforced on read, before derivation.
- Calibration (`kdf.rs:93-139`): candidates 64–1024 MiB, capped by min(caller cap, RAM/4),
  never below the floor, `p` clamped to 1..=4. One probe, then real verification stepping
  down. Tests cover monotonicity, the caps, the floor, lane clamping and thrash step-down.
  `vault_create` still uses `KdfParams::DEFAULT` (not wired), which is fine.
- scrypt import cap: see (d).

**4. Parsers — pass (B2 aside).**
- `Header::from_bytes`: 64 KiB cap, then structural checks (magic, version range, kdf name,
  salt and nonce lengths, v1/v2 field consistency, nil id).
- `import_age`: 64 MiB input cap, `.take(cap + 1)` on the decrypted stream, payload cap,
  scrypt cap, header re-check. serde_json has a recursion limit of 128 for the opaque
  `folders`/`connections`.
- The proptest stand-in (256 cases, 4 prefixes) covers both parsers. A real `cargo-fuzz`
  target for `import_age` and `Header::from_bytes` is **still owed** (CLAUDE.md rule). It is
  tracked as an open item, and the A1 phase exit requires it.

**5. Dependencies — conditionally approved.** `cargo-deny` and `cargo-audit` are **not
installed** in this environment, so neither was run. CI `make check` must be green before the
A1 exit. The lockfile grew from 463 to 606 packages. No git sources; no `openssl` or
`native-tls`. Every license below is on the `deny.toml` allow-list.

| Crate | Version | License | `unsafe` (own src) | Reached from | Notes |
| --- | --- | --- | --- | --- | --- |
| `age` / `age-core` | 0.12.1 / 0.12.0 | MIT OR Apache-2.0 | 0 / 1 (`from_utf8_unchecked`) | mooring-vault | Actively maintained (str4d). Pulls hpke, ml-kem, p256, x25519-dalek, i18n-embed and rust-embed, although only scrypt is used. Accepted: there is no slimmer feature set; revisit if an `age` "scrypt-only" feature appears. I am not aware of a published third-party audit of the Rust crate. |
| `keyring` | 4.2.0 (+ keyring-core 1.0.1, apple-native 1.0.2, windows-native 1.1.0, zbus-secret-service 1.0.1) | MIT OR Apache-2.0 | 0 / 0 / 0 / 21 (Win32 FFI) / 0 | mooring-app only | Maintained. The Linux backend brings zbus + secret-service (RustCrypto). M1: switch to `keyring-core` + explicit stores. |
| `sysinfo` | 0.40.1 (`default-features = false`, `system`) | MIT | 668 (OS FFI) | mooring-vault | Large unsafe surface used only for total RAM. Accepted because `forbid(unsafe_code)` rules out a local `sysctl`/`GlobalMemoryStatusEx` call. Keep the feature set minimal. |
| `rusqlite` + `libsqlite3-sys` (`bundled`) | 0.41.1 / 0.39.1, SQLite 3.54.1 | MIT (SQLite: public domain) | 504 / 6 | mooring-store | C code, outside the crypto allow-list but not crypto. Accepted per ADR-0005. Track SQLite CVEs through cargo-audit and Dependabot. |

Duplicate major versions (hkdf 0.12/0.13, sha2 0.10/0.11, aes) are a `multiple-versions = warn`
item, not a blocker.

**6. Store — pass, with M2 and L4.**
- Every query is parameterised. The only `format!` calls interpolate static column lists or
  `SecretField::column()`, a closed enum.
- FTS sanitiser:
  - Each whitespace token is a quoted literal with `"` doubled, plus `*`.
  - Operator-only tokens are dropped.
  - Caps: 256 chars, 16 tokens, limit 1..=200.
  - Covered by 11 injection queries.
- Sealed columns bind credential id + column name as AAD. A swap between rows or between
  columns → `Tampered` (tested).
- `secure_delete` and `foreign_keys` are verified after they are set. Downgrade is refused.
- The cycle-bounded recursive CTE is sound.
- Plaintext inventory at rest is an **accepted risk**. It is recorded in the threat model and
  conditioned on M2.

## Test evidence (this review)

```
cargo test -p mooring-vault -p mooring-store
  mooring-store: 16 + 7 + 7 + 4 + 4 passed
  mooring-vault: 40 passed (2 ignored) + 2 proptest + 3 vectors passed
cargo clippy -p mooring-vault -p mooring-store --all-targets -- -D warnings   clean
cargo fmt --check (reviewed crates)                                         clean
cargo tree -i age|keyring|sysinfo|rusqlite --workspace                      see table
scratch crate against HEAD (outside the repo): B1 and B2 reproduced (output above)
```
Not run: cargo-deny, cargo-audit, cargo-geiger, gitleaks and semgrep (not installed); the
mooring-app build; the macOS/Windows keyring backends.

## Re-review — fix round `b256dcd..1e76c3a`

Reviewer: security-reviewer · 2026-11-03.
- Range: `git diff b256dcd..1e76c3a -- crates src-tauri Cargo.toml`. That is the fix commits
  `77342e2..399911e`, the merge `fb7cebf` and the build tweak `1e76c3a`.
- Also read: `docs/handoff/a1-rust-core-fixes.md`.
- `mooring-app` was again **not compiled** (no WebView toolchain). The src-tauri changes were
  checked by reading only.

### Verdict: `APPROVE WITH NITS`

This covers the A1 items 1–2 code on `main` (vault lifecycle, `mooring-store`). Both blockers are
fixed. Each fix has a test that starts from the failing condition. The nits below do not block.

Wiring gates after this round:
- **Export and import commands:** may now be wired. N3 must land in the same PR as
  `vault_export`.
- **Keyring commands:** stay on **HOLD**, per ruling (a), M1 and R-T2-KR. B1 was one of the
  conditions; the others still stand.
- **L2** (durable header write): must land before A1 exit, and before any further command that
  rewrites the header (keyring enable/disable, change password).

### Per-finding results

| ID | Result | Evidence (code · test) |
| --- | --- | --- |
| **B1** | **Fixed** | `keyring.rs:103-122`, `with_password_kek`: snapshots `(state, header)` before `unlock_with_kek`. It restores the header on every `Err`, and the lock state on every exit. The body runs inside `and_then`, so a `?` can no longer skip the restore. Both `enable_keyring_unlock` and `disable_keyring_unlock` use it. Tests: `failed_enable_on_locked_vault_stays_locked` and `failed_disable_on_locked_vault_stays_locked` (state `Locked`, header unchanged, `seal` refused); `failed_keyring_change_on_v1_header_keeps_v1_header` (no in-memory upgrade, plus the successful upgrade-and-enable from a locked v1 vault). |
| **B2** | **Fixed** | `kdf.rs:51`: `CEILING = {4 GiB, 16, 16}`. It is enforced in `validate` (`kdf.rs:54`), which `Header::from_bytes`, `import_age` and `derive_kek` all call. `derive_kek_with_ram` (`kdf.rs:196-205`) refuses `m_kib > RAM/2` before Argon2 allocates. Tests: `ceiling_is_enforced`, `derive_refuses_more_than_half_of_ram`, `structural_checks` (+3 cases), `import_refuses_hostile_kdf_cost_in_header` (raw age file, bypasses the export-side check), `calibrate_output_always_validates`, and QA `header_with_absurd_kdf_cost_is_refused_at_parse` (no longer ignored). The worst case a header can force is now 4 GiB × 16 passes: bounded, on the order of tens of seconds. See N5. |
| **L1** | **Fixed** (src-tauri uncompiled) | `Vault::unlock_persisting` (`vault.rs:130`): if the header needed an upgrade and `persist` fails, it restores the v1 header and **locks**. `commands.rs:132` calls it via `save_header_bytes`. Test: `unlock_persisting_locks_and_restores_when_persist_fails` (failure, retry, v2 with no persist, wrong password with no persist). |
| **L3** | **Fixed** | `argon2` has `features = ["zeroize"]` in `crates/mooring-vault/Cargo.toml` only. `argon2_zeroize_feature_is_enabled` is a compile-time proof: `Block: Zeroize` exists only with the feature. The work area is still not wiped, which the original review allowed as optional. |
| **L4** | **Fixed; deviation accepted (ruling below)** | Migration `0002` sets FTS5 `secure-delete` (test: `fts_secure_delete_is_on`). `Store::checkpoint` runs `optimize`, then `wal_checkpoint(TRUNCATE)` (`schema.rs:109-125`). It runs from `close()`, and best effort from `Drop` (file stores only). Test: `deleted_rows_do_not_linger_after_close` searches the closed db file for a marker string and asserts an empty `-wal`. |
| **L5** | **Fixed** | `EXPORT_SCRYPT_LOG_N = 18` (`export.rs:31`), used by `export_age` (`export.rs:65`). Tests: `export_age_writes_pinned_work_factor` (parses the de-armored stanza), `export_pins_work_factor_below_import_cap` (const assert 18 < 20). |
| **M2** | **Fixed** (app dir uncompiled) | `restrict_db_file` (`mooring-store/src/lib.rs:126`) creates the db file with mode `0600` at `O_CREAT`, so there is no window at the default umask, and it tightens an existing file. SQLite copies that mode to `-wal`/`-shm`. `create_private_dir` (`src-tauri/src/lib.rs:47`) uses `DirBuilder` mode `0700`, then `set_permissions` for an existing dir. Test: `database_files_are_owner_only` (db, sidecars, loose file tightened). `create_private_dir` has no test yet; add one when `mooring-app` gets a test harness. |
| **N1** | **Fixed** | `seal_with`/`seal_with_nonce` return `Result`. Failure is `VaultError::Seal` (fixed message, IPC code `vault.seal`). All callers propagate it. Test: `seal_returns_ciphertext_or_error`. The failure branch (> 256 GiB) is not exercised, which is acceptable. |
| **N2** | **Fixed** | `v2_header_downgraded_to_v1_is_refused`: the stripped header parses as v1, fails with `Unlock`, stays `Locked`, and is not upgraded. |
| **N3** | **Deferred, accepted** | There is no call site yet. Condition: implement it in the `vault_export` PR. Compare the `Zeroizing` UTF-8 bytes with `subtle::ConstantTimeEq`, and refuse equality with a fixed-string error. `subtle` is **pre-approved** as a direct dependency of `mooring-app` or `mooring-vault`: it is RustCrypto, already in the lockfile, and adds no new transitive crate. |
| **N4** | **Fixed (doc)** | The doc now says "tests only, never a fallback". Not gating it behind a feature is accepted, because the `mooring-store` integration tests use it. Condition: once the keyring commands are wired, `src-tauri` must not reference it (0 references today, grepped). |
| A1-QA-2 | **Fixed** | `set_vault_id` refuses nil and records nothing. Unit test and `nil_vault_id_is_refused` (no longer ignored). |
| Validators (store decision 2) | **Approved** | A single implementation in `mooring-core`. Hosts now refuse control characters, which closes a terminal-escape vector (`host\x1b[31m`) for the A2 terminal UI. Errors never echo the input (tested). `store_and_core_agree_on_limits` guards against drift between the two crates. |
| `[profile.dev.package.scrypt] opt-level = 3` | **Approved** | Dev profile only; release unchanged. No code or dependency change. |

### Ruling — L4: `contentless_delete = 1` versus FTS5 `secure-delete`

I confirmed the rust-core finding in a scratch script outside the repo (Python `sqlite3`,
SQLite 3.53.1):

```
mode                      after delete    after optimize   still matches
contentless_delete=1      token present   gone             no
contentless + 'delete'    gone            gone             no
external content          gone            gone             no
crash path (no optimize; next open runs 'delete-all' + rebuild): marker gone from the file
```

**Decision: keep as-is.** That is `contentless_delete = 1`, plus `optimize` +
`wal_checkpoint(TRUNCATE)` on close/drop, plus the existing full rebuild on open.

- **Drop `contentless_delete`: rejected.** Every delete would then go through the FTS5
  `'delete'` command, which needs the exact old token values. Three triggers would have to
  rebuild the old tag string at the right moment: the update trigger, the tag-delete trigger,
  and the FK-cascaded tag delete. If they get it wrong, FTS5 does not raise an error. It
  silently corrupts the index. That would trade a correctness risk for confidentiality on data
  that is already plaintext.
- **`optimize` after every delete: rejected.** It rewrites the whole index (O(index)) on every
  delete. Renames and tag edits are delete + insert through triggers, so that would be most
  edits. It would shorten the residue window from "the session" to "one statement", and that
  buys nothing against the relevant threat. The residue is the tokens of a deleted
  connection's name, host and tags: **the same class of data as the live inventory, which is
  accepted plaintext at rest (R-INV)**. An attacker who can read `mooring.db` during a session
  (T1 with the device on, or T2) already reads the whole current topology.
- **The bound:** residue lasts one session at most.
  - A clean exit runs `optimize`; the `secure_delete` pragma then wipes the freed pages, and
    the WAL is truncated.
  - A crash or `panic = "abort"` skips `Drop`. The next open then runs `'delete-all'` and a
    rebuild, and I verified that removes the residue from the file.

Conditions:
1. When the store is wired, src-tauri must call `Store::close()` from `RunEvent::Exit` and own
   the store's lifetime explicitly. Do not rely on the `Drop` of a value in Tauri managed state,
   which may never run.
2. Architect: add one line to ADR-0005 and R-INV: "deleted inventory may persist in FTS
   segments until close or next open".

Freed filesystem blocks of the truncated `-wal` are a filesystem-level matter, out of scope,
and covered by R-INV.

### New findings (non-blocking)

| ID | Sev | Where | Finding | Fix |
| --- | --- | --- | --- | --- |
| N5 | Nit | `crates/mooring-vault/src/vault.rs:155-156` | `unlock_with_kek` maps **every** `derive_kek` error to `VaultError::Unlock`. The new B2 RAM refusal ("needs more memory than this host has") therefore reaches the user as "wrong password". There is no OOM any more, but the user cannot tell why unlock fails and may keep retrying or reset the vault. No test covers it. | `.map_err(\|e\| match e { VaultError::KdfParams(_) => e, _ => VaultError::Unlock })`. This is safe: `KdfParams` depends only on the public header, never on the password, so it is no oracle. Test it through a RAM hook (for example a `cfg(test)` `unlock_with_ram`) and assert `KdfParams`. |
| N6 | Nit | `crates/mooring-store/src/lib.rs:83-85`, `:146` | `close(self)` runs `checkpoint()`, and then `Drop` runs it again: a second `optimize` and a second truncate. Harmless, but it doubles the close cost, and an error on the second run is only logged. | Set a `closed` flag in `close()` that `Drop` checks, or keep `conn` in an `Option` that `close` takes. |

### Still open (carried forward)

- **M1** (`keyring-core` + explicit stores, Windows `persistence=Local`, macOS ACL). It blocks
  the keyring commands only.
- **L2** (`sync_all` + `.bak` on the header write). `save_header_bytes`
  (`src-tauri/src/state.rs:58-65`) still does `write` + `rename` without `sync_all`. Required
  before A1 exit.
- `cargo-fuzz` targets for `Header::from_bytes` and `import_age`. Owed for A1 exit.
- cargo-deny, cargo-audit, gitleaks and semgrep are not installed here. CI `make check` must be
  green, and `mooring-app` must be built on macOS, Windows and Linux.

### Test evidence (re-review)

```
worktree agent-a4fd903c4e7869598, HEAD 1e76c3a, Linux, 2026-11-03
cargo test -p mooring-vault -p mooring-store                                         exit 0
  mooring-store  lib 18 · credentials 7 · crud 7 · migrations 6 · search 4
               tree_edges 8 · vault_store_integration 6 (0 ignored)
  mooring-vault  lib 52 (2 ignored, intentional: calibrate_real_host_smoke, regenerate_vectors)
               autolock_table 3 · calibration_props 7 (0 ignored) · proptest_round_trip 2
               vectors 3
cargo clippy -p mooring-vault -p mooring-store -p mooring-core --all-targets -- -D warnings   clean
cargo fmt --all -- --check                                                               clean
FTS5 experiment (scratchpad, outside the repo): table above
```
Not run: cargo-deny, cargo-audit, gitleaks, semgrep (not installed); the `mooring-app` build.

## Review 4 — A1 exit (ADR-0010)

The full review is in [a1-review-4.md](a1-review-4.md), filed one review per file like reviews
[2](a1-review-2.md) and [3](a1-review-3.md). Range `main...a1-exit` (30 commits), 2026-11-04.

**Verdict: `BLOCKER`.**
- **B-4:** the SFTP commands take any absolute local path from the WebView. A compromised
  WebView can read any user file and write server-chosen files into any user-writable
  directory.
  - Fix: open the dialog in Rust and pass single-use `pickId`s.
  - The capability returns to `core:default`.
  - Needs an ADR-0010 amendment.
- **Before the A1 tag:**
  - M-8: `forward_list` polling defeats the idle lock.
  - M-9: ruling `BLUR_GRACE = 60 s`, with Mooring's own dialog exempt.
  - M-10: a lock orphans sessions and forwards in Rust; external forwards close on lock.
- **M-11:** the kubeconfig fuzz gate from review 3 is not met.
- **Low:** L-15..L-18. **Nits:** N-10..N-16.
- Everything else is approved: forwarding exposure (M-2 cleared), the SFTP fan-out bound (M-3
  cleared), L-7, rustls/ring with no aws-lc, the RFC 5424 formatter, and the QA-F1 fix.

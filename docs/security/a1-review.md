# A1 security review — vault lifecycle (ADR-0006) and nexus-store (ADR-0005)

Reviewer: security-reviewer · 2026-11-03 · Range `240f611..6a0acd0` (`crates`, `src-tauri`,
`Cargo.toml`, `Cargo.lock`). `nexus-app` was **not compiled** (no WebView toolchain here).

## Verdict: `BLOCKER`

There are two blockers, B1 and B2. Both are latent. No IPC command reaches either path yet: the
keyring and import commands are not wired. Both break a guarantee that the next A1 step (Tauri
wiring of keyring, export and import) relies on, and each fix is about 10 lines. The code
already on `main` can stay there. **The keyring, export and import commands must not be wired
until B1 and B2 are fixed and tested.** Everything else is approved, with the nits below.

## Blockers

### B1 — A failed keyring enable/disable leaves a locked vault unlocked
- **Where:** `crates/nexus-vault/src/keyring.rs:104-116` (`enable_keyring_unlock`) and
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
- **Where:** `crates/nexus-vault/src/kdf.rs:49-56` (`KdfParams::validate`, floor only), called
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
| M2 | Medium | `src-tauri/src/lib.rs:28`, `crates/nexus-store/src/lib.rs:56` | The data dir is created with `create_dir_all` and `nexus.db`/`-wal`/`-shm` with SQLite defaults, so the umask applies (usually `0755`/`0644` on Linux and macOS). The plaintext inventory (hosts, names, usernames, topology) is then readable by other local accounts. The audit log is `0600`; the store should match. | Unix: create the data dir with `DirBuilder::new().mode(0o700)` (std `os::unix::fs::DirBuilderExt`, no unsafe), and `set_permissions(0o600)` on `nexus.db` before `Connection::open`. SQLite copies the db file's mode to `-wal`/`-shm`. Windows: the per-user AppData ACL is enough. Add a unix-only test. |
| L1 | Low | `src-tauri/src/commands.rs:129-134` | With a v1 header, if `save_header` fails after `unlock` the command returns `state.io`, but the vault stays **unlocked** in memory with a fresh, unpersisted `vault_id`. Each retry or restart mints another id, and the store's `set_vault_id` would later answer `VaultIdMismatch`. | On a `save_header` error, call `vault.lock()` before returning the error, so the next attempt starts clean. Also covers the UI/state mismatch. |
| L2 | Low | `src-tauri/src/state.rs:53-60` | The header write does tmp + rename without `sync_all`. The header is the *only* copy of the wrapped DEK: a crash right after the automatic v1→v2 rewrite (or a password change) can leave an empty or torn file and lose the vault. Pre-existing A0 code, but A1 now triggers it without user action. | `File::create(tmp)` → `write_all` → `sync_all` → rename; keep the previous header as `vault.header.json.bak` until the next successful unlock. |
| L3 | Low | `Cargo.toml:35` | `argon2` lacks the `zeroize` feature, so the Argon2 initial hash and final block hash (password-derived) are not wiped. The 256 MiB–1 GiB work area is not wiped either way through `hash_password_into`. | Add `"zeroize"` to the `argon2` features. Optionally call `hash_password_into_with_memory` with a buffer wiped after use. |
| L4 | Low | `crates/nexus-store/migrations/0001_init.sql:60-65` | The `secure_delete` pragma wipes freed b-tree pages, but FTS5 keeps deleted tokens in segment pages until a merge unless the FTS5 `secure-delete` option is on. The full rebuild on every open bounds the residue to one session; with WAL, deleted rows also persist in `-wal` until checkpoint. | Migration `0002`: `INSERT INTO search(search, rank) VALUES ('secure-delete', 1);` (bundled SQLite 3.54.1 supports it). On close: `PRAGMA wal_checkpoint(TRUNCATE)`. |
| L5 | Low | `crates/nexus-vault/src/export.rs:59-61` | The export uses age's per-host calibrated scrypt work factor, which can exceed the import cap of 2^20 on a fast machine. See decision (d). | Pin it: `export_age` calls `export_age_inner(doc, passphrase, Some(EXPORT_SCRYPT_LOG_N))` with `pub const EXPORT_SCRYPT_LOG_N: u8 = 18;`. Add a test that the stanza says `18`. |
| N1 | Nit | `crates/nexus-vault/src/crypto.rs:34` | `encrypt(..).unwrap_or_default()` silently produces an empty ciphertext. It fails closed on open, but the data is lost without an error. | Return `Result<Sealed, VaultError>` and map to `VaultError::Tampered` or a new `Seal` variant. It is unreachable in practice (plaintext above 256 GiB); this is about clarity. |
| N2 | Nit | `crates/nexus-vault/src/vault.rs` tests | A v1-relabelled-as-v2 forgery is tested, but the reverse is not: v2 → v1 downgrade with `vault_id`/`keyring_wrap` stripped. It is refused today by the AAD mismatch. | Add the test so a future change to `aad()` cannot open a downgrade path. |
| N3 | Nit | `crates/nexus-vault/src/export.rs` | Nothing enforces the "export passphrase ≠ master password" rule (ADR-0006). | The export command needs the master password anyway (ADR-0006), so compare the two there in constant time (`subtle`, already transitive) and refuse equality. |
| N4 | Nit | `crates/nexus-vault/src/keyring.rs:34` | The `MemoryWrapKeyStore` doc says "for platforms without a keyring". That invites a production fallback which would silently make keyring unlock a no-op. | Say "tests only" in the doc, or gate it behind `#[cfg(any(test, feature = "test-util"))]`. |

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
  deterministic, so `HKDF-SHA256(signature, info = vault_id ‖ "nexus-keyring")` gives the same
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
  `crates/nexus-vault/tests/vectors/` in `.gitleaks.toml` (orchestrator).

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
| `age` / `age-core` | 0.12.1 / 0.12.0 | MIT OR Apache-2.0 | 0 / 1 (`from_utf8_unchecked`) | nexus-vault | Actively maintained (str4d). Pulls hpke, ml-kem, p256, x25519-dalek, i18n-embed and rust-embed, although only scrypt is used. Accepted: there is no slimmer feature set; revisit if an `age` "scrypt-only" feature appears. I am not aware of a published third-party audit of the Rust crate. |
| `keyring` | 4.2.0 (+ keyring-core 1.0.1, apple-native 1.0.2, windows-native 1.1.0, zbus-secret-service 1.0.1) | MIT OR Apache-2.0 | 0 / 0 / 0 / 21 (Win32 FFI) / 0 | nexus-app only | Maintained. The Linux backend brings zbus + secret-service (RustCrypto). M1: switch to `keyring-core` + explicit stores. |
| `sysinfo` | 0.40.1 (`default-features = false`, `system`) | MIT | 668 (OS FFI) | nexus-vault | Large unsafe surface used only for total RAM. Accepted because `forbid(unsafe_code)` rules out a local `sysctl`/`GlobalMemoryStatusEx` call. Keep the feature set minimal. |
| `rusqlite` + `libsqlite3-sys` (`bundled`) | 0.41.1 / 0.39.1, SQLite 3.54.1 | MIT (SQLite: public domain) | 504 / 6 | nexus-store | C code, outside the crypto allow-list but not crypto. Accepted per ADR-0005. Track SQLite CVEs through cargo-audit and Dependabot. |

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
cargo test -p nexus-vault -p nexus-store
  nexus-store: 16 + 7 + 7 + 4 + 4 passed
  nexus-vault: 40 passed (2 ignored) + 2 proptest + 3 vectors passed
cargo clippy -p nexus-vault -p nexus-store --all-targets -- -D warnings   clean
cargo fmt --check (reviewed crates)                                         clean
cargo tree -i age|keyring|sysinfo|rusqlite --workspace                      see table
scratch crate against HEAD (outside the repo): B1 and B2 reproduced (output above)
```
Not run: cargo-deny, cargo-audit, cargo-geiger, gitleaks and semgrep (not installed); the
nexus-app build; the macOS/Windows keyring backends.

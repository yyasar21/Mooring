# A1 · rust-core · fix round for items 1–2 (review BLOCKER + QA bugs)

Branch `worktree-agent-ab7bdf31a451c2c0f`, on top of `b256dcd` (main, A1 security review).
Not merged. Inputs: `docs/security/a1-review.md`, `docs/handoff/a1-qa-engineer.md`,
ADR-0006. Linux host, no WebView toolchain: **`nexus-app` (src-tauri) was not compiled.**
`cargo check -p nexus-app` stops at the missing `gdk-3.0` pkg-config, as before.

## Done

| Finding | Commit | What |
| --- | --- | --- |
| **B2** / A1-QA-1 | `77342e2` | `KdfParams::CEILING = { m_kib: 4 GiB, t: 16, p: 16 }`, enforced in `validate` (therefore in `Header::from_bytes`, `import_age` and `export_age`). `derive_kek` refuses `m_kib > RAM/2` before allocating ("needs more memory than this host has"). The RAM size is injectable through `derive_kek_with_ram`, and the sysinfo query is cached in a `OnceLock`. The QA test `calibration_props::header_with_absurd_kdf_cost_is_refused_at_parse` is no longer `#[ignore]`d. |
| **B1** | `e761d72` | `enable_keyring_unlock` and `disable_keyring_unlock` now run through a private `Vault::with_password_kek`. It snapshots the state and header, restores the header on every error, and restores the lock state on every exit. |
| A1-QA-2 | `3aed6d5` | `Store::set_vault_id` refuses the nil UUID with `Invalid { field: "vault_id" }` and records nothing. `vault_store_integration::nil_vault_id_is_refused` is no longer `#[ignore]`d. |
| L1 | `75933ed` | New `Vault::unlock_persisting(password, persist)`. On a v1→v2 upgrade it passes the new header to `persist`. If `persist` fails, the v1 header is restored, the vault is **locked**, and the error is returned. `vault_unlock` (src-tauri) uses it through the new `AppState::save_header_bytes`. |
| L3 | `30846a5` | `argon2` gets the `zeroize` feature in `crates/nexus-vault/Cargo.toml` only; the workspace dependency is unchanged. `Cargo.lock` gains one line: the `zeroize` edge under argon2, with no new crate. |
| L4 | `f369b9b` | Migration `0002_fts_secure_delete.sql` sets the FTS5 `'secure-delete'` option (schema v2). **Finding:** `search` is `contentless_delete = 1`, which records deletes as tombstones, and the option has **no effect** in that mode (verified: deleted tokens stayed in `search_data`). `Store::checkpoint()` therefore also runs an FTS `'optimize'` merge, then `PRAGMA wal_checkpoint(TRUNCATE)`. It is called from `Store::close()` and, best effort, from `Drop for Store` (file stores only). |
| L5 | `52203f6` | `pub const EXPORT_SCRYPT_LOG_N: u8 = 18`, used by `export_age`. The import cap stays `MAX_IMPORT_SCRYPT_LOG_N = 20`. |
| M2 | `415dbf9` | `Store::open` creates or tightens `nexus.db` to `0600` before SQLite opens it; SQLite copies that mode to `-wal`/`-shm`. In src-tauri, `create_private_dir` creates the app data dir with `DirBuilder` mode `0700` and tightens an existing dir; this is uncompiled. Both are `#[cfg(unix)]`; Windows relies on the AppData ACL. |
| Store decision 2 | `fa749b6` | `nexus-core` now exports `MAX_NAME`, `MAX_HOST`, `MAX_TAG`, `MAX_TAGS` and `validate_name`, `validate_host`, `validate_tag`. They return trimmed output, and their errors never echo the input. `nexus-store` re-exports the limits and validates through the core functions. The copies had drifted: core accepted control characters in hosts. Core now refuses them, which is a behaviour change in `Connection::new`. |
| N1 | `399911e` | `seal_with`/`seal_with_nonce` return `Result`. An AEAD failure becomes the new `VaultError::Seal`, mapped to IPC code `vault.seal` (src-tauri, uncompiled). |
| N2 | `399911e` | Test: a v2 header relabelled as v1, with `vault_id`/`keyring_wrap` stripped, parses but does not unlock and is not upgraded. |
| N4 | `399911e` | The `MemoryWrapKeyStore` doc says "tests only, never a fallback". It is not feature-gated: `nexus-store` integration tests use it, and gating it would mean a Cargo feature plus a dev-dependency change. |

Each fix has a test that fails before the fix and passes after. This was checked by reverting the
implementation file and running the new tests for B2, B1 and M2 (under umask 022). For L4, the
first version of the test failed until the FTS merge was added.

## Left open

- **N3** (export passphrase ≠ master password, constant-time). There is no export command yet,
  so there is no call site. It also needs `subtle` as a direct dependency (orchestrator plus
  security approval). Do it when `vault_export` is wired.
- **L2** (durable header write: `sync_all` + `.bak`) was not in this round's list. It is still
  open, and `state.rs` is unchanged apart from `save_header_bytes`.
- **M1** (keyring v1 API, Windows roaming, macOS ACL): not in scope. The keyring commands stay
  unwired, as the review requires.
- **src-tauri is uncompiled.** The changes are in `commands.rs` (`unlock_persisting`,
  `V::Seal`), `state.rs` (`save_header_bytes`, `Header` import) and `lib.rs`
  (`create_private_dir`). Run `make app-check` on the Mac or Windows.
- **Test time:** `export_age` now always does a real scrypt at 2^18. In debug builds
  `vault_store_integration::export_import…` takes about 2 min and
  `export::tests::export_age_writes_pinned_work_factor` about 40 s. See decision 2.
- No fuzz target yet for `Header::from_bytes`/`import_age` (owed, phase exit).

## Decision needed

1. **L4 / ADR-0005:** `contentless_delete = 1` makes the FTS5 `secure-delete` option a no-op.
   The fix relies on the `optimize` merge at close, so deleted names stay in the index pages
   for the rest of the session (on disk once checkpointed). The alternatives are: drop
   `contentless_delete`, so deletes must pass the old values (`'delete'` command) and
   secure-delete applies immediately; or run `optimize` after every delete. The
   security-reviewer should choose.
2. **Test cost of the pinned export work factor:** either add `[profile.dev.package.scrypt]
   opt-level = 3` (root `Cargo.toml`, orchestrator), or add a `test-util` feature in
   nexus-vault that exposes `export_age_inner` with a low work factor for the
   `nexus-store` integration test.
3. `Connection::new` now refuses control characters in hosts, matching what the store already
   enforced. If the UI relies on the old behaviour, the ui-engineer should know.

## Test evidence (2026-11-03, this worktree, HEAD `399911e`)

```
cargo fmt --all -- --check                                                  → clean
cargo clippy --workspace --exclude nexus-app --all-targets -- -D warnings   → Finished, 0 warnings
cargo test --workspace --exclude nexus-app
  nexus-audit 7 · nexus-core 8 · proto-* 0
  nexus-store  lib 18 · credentials 7 · crud 7 · migrations 6 · search 4 · tree_edges 8
               vault_store_integration 6 (nil_vault_id_is_refused un-ignored)
  nexus-vault  lib 52 + 2 ignored (calibrate_real_host_smoke, regenerate_vectors — intentional)
               autolock_table 3 · calibration_props 7 (header_with_absurd_kdf_cost… un-ignored)
               proptest_round_trip 2 · vectors 3
  → 138 passed, 0 failed, 2 ignored (both intentional)
cargo check -p nexus-app → fails at gdk-3.0 pkg-config (no WebView toolchain; not compiled)
```

New tests: `kdf::{ceiling_is_enforced, derive_refuses_more_than_half_of_ram,
calibrate_output_always_validates, argon2_zeroize_feature_is_enabled}`,
`format::structural_checks` (+3 ceiling cases),
`export::{import_refuses_hostile_kdf_cost_in_header, export_age_writes_pinned_work_factor,
export_pins_work_factor_below_import_cap}`,
`keyring::{failed_enable_on_locked_vault_stays_locked,
failed_disable_on_locked_vault_stays_locked,
failed_keyring_change_on_v1_header_keeps_v1_header}`,
`vault::{unlock_persisting_locks_and_restores_when_persist_fails,
v2_header_downgraded_to_v1_is_refused}`, `crypto::seal_returns_ciphertext_or_error`,
`schema::fts_secure_delete_is_on`,
`migrations::{deleted_rows_do_not_linger_after_close, database_files_are_owner_only}`,
`model::{public_validators, connection_new_refuses_control_chars_in_host}`,
`connections::store_and_core_agree_on_limits`.

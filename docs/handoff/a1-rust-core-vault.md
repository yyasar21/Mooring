# A1 · rust-core · vault lifecycle (ADR-0006)

Branch `worktree-agent-a6fe075f819c48bcf`, on top of `240f611`. Not merged.

## Done

| Item | Where | Notes |
| --- | --- | --- |
| KDF calibration | `crates/mooring-vault/src/kdf.rs` | `KdfParams::calibrate(target, max_m_kib)`: candidates 64–1024 MiB, ≤ cap, ≤ ¼ RAM (`sysinfo`), never below `FLOOR`, `t=3`, `p=min(4, cores)`. One probe at the floor cost, scaled linearly; the chosen candidate is verified by a real run, stepping down if it is too slow. The timer is injectable: `calibrate_with(target, max, HostLimits, impl FnMut(KdfParams) -> Duration)`. Real-host smoke test is `#[ignore]`. |
| Auto-lock | `src/autolock.rs` | `AutoLockPolicy` (15 min, all triggers on), `LockReason` {User, Idle, ScreenLock, Sleep, WindowHidden} with stable `as_str`/`parse`, `LockEvent`, `AutoLockClock::{touch, signal, should_lock, reset}`. Pure; table tests. |
| Header v2 | `src/format.rs`, `src/vault.rs` | `FORMAT_VERSION = 2`, adds `vault_id: Uuid` and `keyring_wrap: Option<Sealed>`, both in `aad()`. A v1 header keeps its exact A0 AAD, still parses (serde default), reports `needs_upgrade()`, and is upgraded in memory on the next password `unlock` (new `vault_id`, DEK re-wrapped). The KDF floor check is unchanged. Structural checks reject v2 fields in a v1 header and a nil id in a v2 header. |
| Keyring wrap | `src/keyring.rs` | `WrapKeyStore` trait, `MemoryWrapKeyStore`, `Vault::{enable_keyring_unlock, unlock_with_keyring, disable_keyring_unlock}`. Wrap AAD = `aad()` of the header without the wrap ‖ 0x1F ‖ `"keyring"`. Enable and disable need the master password, keep the vault's locked/unlocked state, and leave the header untouched if the store fails. `change_password` clears the wrap (it is bound to the old salt). |
| OS adapter | `src-tauri/src/keyring_store.rs` | `OsWrapKeyStore` over `keyring = "4"` (service `xyz.homelab.mooring`, account = vault id). Errors map to fixed strings. **Not wired into any command yet** (`#[allow(dead_code)]` on the module). |
| Export/import | `src/export.rs` | `ExportDocument { header, credentials: Vec<ExportedRecord>, folders, connections }` (the last two are opaque `serde_json::Value`). `export_age` writes armored age v1 with an scrypt recipient. `import_age` takes armored or binary input, caps input and payload at 64 MiB, refuses scrypt `log_n > 20` before doing the work, and re-checks the header. Passphrase ≥ 12 chars. Errors are `VaultError::Export(&'static str)`. |
| Vectors | `tests/vectors/`, `src/vectors.rs`, `tests/vectors.rs` | `header.json`, `sealed.json` (6 cases incl. empty, Unicode, 0..=255), `export.age`, `README.md`, `age_decrypt.py`. Regenerate with `cargo test -p mooring-vault --lib -- --ignored regenerate_vectors`. header and sealed are deterministic; a unit test fails if they drift. |
| Audit hook | `Vault::lock_with_reason` | Returns the `LockReason`; `vault_lock` now parses its reason with `LockReason::parse` (unknown → `user`, `window_hidden` accepted) and audits `reason.as_str()`. No `mooring-audit` dependency in the vault. |
| Tauri glue | `src-tauri/src/commands.rs` | `IpcError` codes for the new variants (`vault.keyring_unavailable`, `vault.keyring`, `vault.export`); `vault_unlock` persists the header when a v1 → v2 upgrade happened. |
| Rules | — | `#![forbid(unsafe_code)]` kept; no `unwrap` in library code; `tracing` only; hand-written `Debug` for `MemoryWrapKeyStore`; every new file < 500 lines (largest: `vault.rs` 367). |

Manifest changes (crate manifests only, all `{ workspace = true }`): mooring-vault gets `sysinfo`,
`uuid` and `age`; mooring-app gets `keyring` and `zeroize`. Cargo.lock changed only through cargo.

## Left open

- **mooring-app has not been compiled.** This machine has no WebView toolchain. The changes in
  `commands.rs` and `lib.rs` are small. `keyring_store.rs` was type-checked and passed
  `clippy::pedantic -D warnings` in a standalone scratch crate against `keyring 4.2.0` on
  Linux. The macOS and Windows store backends have not been built. Run `make app-check` on
  each OS.
- **Workspace member `crates/mooring-store` is missing from the tree**, but the root
  `Cargo.toml` lists it, so every `cargo` command fails at HEAD. To run the gates I made a
  local, **uncommitted** empty stub. I removed it from Cargo.lock before every commit and
  deleted it at the end. The orchestrator must add the crate (ADR-0005) or drop it from
  `members`/`default-members` before the merge.
- `src-tauri/src/autolock.rs` (the 5 s tick, window and OS sleep/lock signals → `AutoLockClock`
  → `lock_with_reason`) and the keyring and export commands are not built yet. They need IPC
  and capability review (ADR-0003) and a `vault_id` merge policy for `--merge` (A3).
- Calibration is not wired in. `vault_create` still uses `KdfParams::DEFAULT`. Wire it up as
  `KdfParams::calibrate(CALIBRATION_TARGET, 1024 * 1024)` on a blocking thread, because it
  takes about 1–2 s.
- The macOS biometric ACL (`kSecAccessControlBiometryCurrentSet`) is **not** set. The plain
  `keyring::Entry` API does not expose it. Getting it needs `apple-native-keyring-store`
  modifiers or a direct Security-framework call. See Decision needed 2.
- There is no cargo-fuzz target: cargo-fuzz and nightly are not installed here. As a stand-in,
  a proptest (`export::tests::arbitrary_input_never_panics`) runs hostile bytes through
  `import_age` and `Header::from_bytes`. A real `fuzz/` target for both parsers is still owed.
- CI verification of the vectors with the `age` CLI (`tests/vectors.yml`) belongs to qa.
  `age_decrypt.py` is ready for it.

## Decision needed

1. **Header upgrade trigger.** ADR-0006 says "upgraded on next write". I upgrade on the next
   successful *password* unlock, because the v1 DEK wrap can only be re-sealed with the KEK,
   and the app persists the result right away. A v1 vault cannot use keyring unlock until
   then. Confirm, or amend the ADR.
2. **Biometric ACL on macOS/Windows.** Ship A1 with a plain Keychain/Credential Manager item
   (any process running as the user can read it without a prompt, which widens T2 more than
   the ADR assumes), or block keyring unlock until the ACL is implemented? The security
   reviewer should decide.
3. **Keyring wrap vs password change.** `change_password` now drops the keyring wrap (it is
   bound to the old salt). The Tauri layer must also delete the stale keyring item. The
   alternative is to re-wrap automatically if the store is reachable. Pick one.
4. **Export scrypt cost.** `export_age` uses age's default work factor (~1 s on the exporting
   machine). `import_age` caps at `log_n = 20` (about 1 GiB). An export made on a much faster
   machine could exceed that cap. Raise the cap, or pin the export's `log_n`?
5. **Gitleaks.** The vector passwords are committed on purpose. There is no `.gitleaks.toml`
   yet. Allow-list `crates/mooring-vault/tests/vectors/` if the scan flags them.

## Test evidence

Run inside the worktree (with the uncommitted `mooring-store` stub present):

```
$ cargo fmt --all && cargo clippy -p mooring-vault --all-targets -- -D warnings && cargo test -p mooring-vault
    Finished `dev` profile [unoptimized + debuginfo] target(s)
     Running unittests src/lib.rs
test kdf::tests::calibrate_real_host_smoke ... ignored, real Argon2 runs with up to 1 GiB; run with --ignored --release
test vectors::tests::regenerate_vectors ... ignored, writes crates/mooring-vault/tests/vectors/*; run on purpose only
test result: ok. 40 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
     Running tests/proptest_round_trip.rs
test result: ok. 2 passed; 0 failed; 0 ignored
     Running tests/vectors.rs
test result: ok. 3 passed; 0 failed; 0 ignored
   Doc-tests mooring_vault
test result: ok. 0 passed; 0 failed; 0 ignored
```

Additional checks:

- `cargo clippy --workspace --exclude mooring-app --all-targets -- -D warnings`: clean.
- `cargo test -p mooring-vault --release --lib -- --ignored calibrate_real_host_smoke`: ok in
  0.48 s (2 cores, 8 GiB RAM).
- Interop: `python3 crates/mooring-vault/tests/vectors/age_decrypt.py .../export.age` with the
  **age v1.1.1 CLI** exits 0. The decrypted JSON's `header` equals `header.json`, and all 6
  `credentials[].fields` equal `sealed.json`.
- `keyring_store.rs`: `cargo clippy -- -W clippy::pedantic -D warnings` in a standalone scratch
  crate (mooring-vault + keyring 4.2.0), Linux only: clean.

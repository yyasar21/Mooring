# A1 — rust-core: `mooring-store` (ADR-0005)

## Done
- New crate `crates/mooring-store` (`[lints] workspace = true`, `#![forbid(unsafe_code)]`, no
  unwrap/println in lib code, `tracing` for logs). Modules: `schema` (pragmas, migration runner,
  `setting`), `folders`, `connections`, `credentials`, `search` (FTS + inheritance), `error`,
  `util`. All files < 500 lines.
- `Store::open(path)` / `Store::open_in_memory()`: `foreign_keys=ON` (verified after setting),
  `secure_delete=ON`, `busy_timeout` 5 s, WAL + `synchronous=NORMAL` for files only. Pending
  migrations run in one `IMMEDIATE` transaction; `schema_version` written last; a newer DB
  returns `StoreError::Downgrade`. `vault_id()` / `set_vault_id()` (UUID validated and
  normalised; idempotent for the same id, `VaultIdMismatch` for a different one).
- Schema v1 `migrations/0001_init.sql` exactly per ADR-0005, plus: CHECK on `kind` and `port`,
  FK indexes, a partial unique index enforcing one root folder, `ON DELETE CASCADE` for
  folder→sub-folder/connection→tag, `ON DELETE SET NULL` for credential references (deleting a
  credential falls back to inheritance). FTS5 `search` is contentless (`contentless_delete=1`,
  `unicode61 remove_diacritics 2`) over name + host + tags, synced by 5 triggers; rebuilt on
  every open because it keys on the implicit `connection.rowid`, which `VACUUM` may renumber.
- CRUD: folders (create, root, get, list, children, rename, sort, default credential, move with
  the `mooring_core::tree` rules — parent exists, root immovable, no self/descendant move, bounded
  walk refuses an already-cyclic chain — delete with cascade; root not deletable), connections
  (create/update/get/list-by-folder/delete; re-validated even though `Connection` fields are
  public), tags (`set_tags` replace; trimmed, deduplicated, sorted).
- Credentials: `CredentialKind {Password, SshKey, Certificate}`, `CredentialMeta` (no secrets),
  `SecretField {Secret, Secret2}`. `create_credential(&vault, &meta, secret, secret2)` seals
  with record id = credential id, field = column name; stored as JSON `Sealed`.
  `open_credential_secret` returns `Zeroizing<Vec<u8>>`. Also `get_credential`,
  `list_credentials` (meta only), `update_credential_meta`, `replace_credential_secret`,
  `delete_credential`. Secrets capped at 64 KiB, usernames at 256 chars.
- `effective_credential(connection_id)`: override → nearest ancestor `default_credential` →
  `None`, via one recursive CTE bounded by the folder count; a cyclic chain is an error.
- `search(query, limit)`: each whitespace token becomes a quoted FTS5 string (`"` doubled)
  plus `*`, tokens are ANDed; tokens without an alphanumeric are dropped; query capped at
  256 chars / 16 tokens; limit clamped to `1..=200`; bm25 then name ordering. Returns
  `ConnectionHit { id, folder, name, host, protocol }`.
- Validation: name ≤ 120 (same rules as `mooring_core`), host ≤ 2048 bytes without
  whitespace/control chars, tag ≤ 64 chars, ≤ 50 tags, port ≠ 0. Every query is parameterised;
  the only `format!` in SQL inserts static column lists or `SecretField::column()`.
- `StoreError` (thiserror): `Sqlite`, `Vault(#[from] VaultError)`, `Invalid`, `NotFound`, `Tree`,
  `Downgrade`, `VaultIdMismatch`, `Corrupt`; `From<MooringError>`. No variant carries values.

## Left open
- `Cargo.lock` gained rusqlite + libsqlite3-sys and their deps when the crate built; it is
  **not committed** (lockfile owned by the orchestrator). Run `cargo build -p mooring-store` once
  after merging and commit the lock.
- No cargo-fuzz target: the store parses no untrusted wire input. The FTS sanitiser is covered
  by unit + injection tests; a fuzz target for `fts_query` could be added if security asks.
- `Store` is `Send`, not `Sync`; `mooring-app` should hold it in a `Mutex` (A1 Tauri wiring).
- Migration from v1 → v2 test is only possible once a v2 script exists; the runner and
  `schema_version` ordering are tested.
- `Connection` in `mooring_core` has no `updated_at`; the column is written but not returned.

## Decision needed
- `vault_id` source: ADR-0006 puts it in vault header v2 (in progress in another worktree). The
  store takes it as a caller-supplied UUID string so it does not depend on the new header API.
  Once header v2 lands, the app should call `set_vault_id(header.vault_id)` on first open and
  refuse to open a store whose id differs.
- `mooring_core` has no public validator for host/tag limits (only private `check_name` and the
  `Connection::new` checks). The store duplicates the rules in `util.rs`/`connections.rs`.
  Suggest exposing `mooring_core::model::{validate_name, validate_host, validate_tag}` and caps
  as `pub const`, then switching the store to them.
- Deleting the root folder is refused (one-root invariant). Confirm that is the desired UX.

## Test evidence
Commands run in the worktree on 2026-11-03 (Linux, cargo 1.97.0):

```
cargo fmt --all                                            → no changes outside the crate
cargo clippy -p mooring-store --all-targets -- -D warnings   → Finished, 0 warnings
cargo test -p mooring-store
  unittests src/lib.rs   16 passed
  tests/credentials.rs    7 passed (incl. proptest seal/open, 32 cases)
  tests/crud.rs           7 passed
  tests/migrations.rs     4 passed
  tests/search.rs         4 passed
  doc-tests               0
  total                  38 passed, 0 failed
```

Covered: migration from empty, idempotent file reopen, downgrade refusal, WAL on file,
garbage file → error; pragmas; folder/connection/tag round trips and validation; cascade on
folder delete (incl. FTS index); move cycle refusal and an already-corrupt cyclic tree;
inheritance (none, root fallback, nearest wins, override wins, fallback after credential
delete); search by name/host/tag/AND, index sync on update/tag/delete, 11 FTS-operator and
quote injection queries, limit clamp; sealed value moved between rows and between columns →
`Vault(Tampered)`; locked vault; oversized secret error does not echo the value.

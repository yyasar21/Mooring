# A3 rust-core — S1 vault sync (`crates/mooring-sync`)

Branch: worktree of `a3` @ 24b2b88. Spec: ADR-0017 §1–5, owner decisions 10–11.

## Done
- **`mooring-vault`**: `Vault::derive_subkey(salt, info) -> SubKey` (HKDF-SHA256 over the DEK,
  `hkdf` 0.13, already in the lockfile). `SubKey` is opaque (`seal`, `seal_with_nonce`, `open`),
  zeroized, `Debug` = `SubKey(..)`. The DEK still never leaves the crate.
- **`mooring-store`**: `sync_rows.rs` — `export_sync_rows() -> SyncRows` (folders, connections
  with tags/roles/options, credentials with sealed secrets verbatim), `replace_sync_rows(&SyncRows)`
  (one transaction, deferred FKs, ids/names/hosts/protocols/timestamps validated, schema CHECKs
  for kinds/roles/JSON), `sync_setting` / `set_sync_setting` for device-local `sync.*` keys.
  Export is refused while `credential_reseal_pending` is set. Adds `serde` (workspace) to the store.
- **`mooring-sync`** (new crate):
  - `blob` — `MSY1` layout (table in `blob.rs`), `decode_msy1(&[u8])` pure/total/capped,
    `encode_msy1`, `open_msy1`, `sync_key(&Vault)`, `blob_hash`. Vectors in `test-vectors/`
    (`MOORING_BLESS=1` regenerates).
  - `snapshot` — `Snapshot` (canonical JSON: alphabetical struct fields + `BTreeMap`s, sorted
    unique trust lines, `deny_unknown_fields`), `from_store(&Store, trust_dir, vault_id, device)`,
    `apply(&Store, trust_dir, &Snapshot)`, tombstones (`derive_tombstones`, newest 20 000 kept).
    Trust stores: `known_hosts` + every `CertProtocol::ALL` file (decision 10).
  - `merge` — three-way per record id; field-wise for disjoint edits; true conflicts keep both
    copies for connections/credentials (remote copy: new id, ` (conflict from <device>)`, secrets
    re-sealed to the new id); folders last-writer-wins (reported); delete vs edit keeps the edit;
    without a base, tombstones vs `updated_at` decide; trust files merge as line sets; `fixup`
    repairs roots, cycles, dangling folder/credential references.
  - `backend` — `ObjectStore` trait; `S3Backend` (rusty-s3 0.11 presign with `if-match` /
    `if-none-match` / `x-amz-meta-*` **in the signed headers**, mooring-http transport with
    `CertProtocol::Sync`, a read client with retries and a write client with
    `max_attempts = 1`); `MemoryStore` (test knobs: ignore conditionals, yield, raw get/put/delete);
    `Remote<S>` layout `<prefix>/<vault_id>/{header,current,history/<counter:020>}`, `probe()` /
    `require_conditional_writes()` (create, re-create must 412, wrong `If-Match` must 412, right
    `If-Match` must pass, delete).
  - `SyncEngine` — `run` / `resolve_fork` with rollback and fork hard stops (persisted alarm,
    audited, sticky until resolved), ancestry walk through `history/` (≤ 10 hops, each hop
    hash-checked), fast-forward, merge-then-push, apply only after the conditional write wins,
    ≤ 3 attempts on 412. History keeps the last 10.
  - `fuzz` — `fuzz_msy1`, `fuzz_snapshot_json`.

## API for the Tauri `sync_*` commands (ADR-0017 §5)
```rust
// sync_set / sync_probe
let s3 = S3Backend::new(&S3Config { endpoint, region, bucket, path_style,
    known_certs_path: data_dir.join("known_sync_certs"), ca_pem, allow_plaintext_loopback: false },
    &S3Credentials { access_key_id, secret_access_key, session_token })?;   // no I/O
let remote = Remote::new(s3, &prefix, vault.vault_id())?;
remote.probe().await? /* -> bool */;  remote.require_conditional_writes().await?; // sync.unsupported_backend

// sync_now
let local = StoreLocal { store, vault, trust_dir: &data_dir, device_name };     // or your own LocalSide
match SyncEngine::default().run(&local, &remote, &audit_sink).await {
    Ok(Outcome::Pushed { counter } | Outcome::Pulled { counter } | Outcome::NoChange { counter }) => …,
    Ok(Outcome::Merged { counter, conflicts }) => … // conflicts: [{ kind, id, name, resolution }]
    Err(e) => IpcError { code: e.code(), .. }  // sync.rollback / sync.fork (e.is_alarm()), sync.conflict, …
}
// fork / rollback resolution (new IPC, e.g. sync_resolve({ keep: "local" | "remote" }))
SyncEngine::default().resolve_fork(&local, &remote, Keep::Remote, &audit_sink).await?;

// sync_status (passive): mooring_sync::load_state(store)? -> LocalState { device_id, last_counter,
//   last_pull_unix, last_push_unix, remote_device, remote_created_unix, alarm }
// sync_disable({ deleteRemote }): remote.delete_all(state.last_counter).await?; clear_state(store)?
```
- `AuditSink::record(&SyncAudit)`: map `event.name()` (`sync.push { counter, bytes }`,
  `sync.pull`, `sync.merge { counter, conflicts }`, `sync.rollback_refused`, `sync.fork`,
  `sync.alarm_resolved`) into `AuditLog`. No secret material in any event.
- `LocalSide` methods are synchronous; implement it over `AppState` by locking store / vault
  inside each method (do not hold `MutexGuard`s across the engine's awaits; `StoreLocal`
  borrows and is therefore not `Send`). The free functions `header_object`, `load_state`,
  `reseal_secret`, `snapshot::{from_store, apply}` do the work.
- Error codes: `sync.format`, `sync.too_large`, `sync.tampered`, `sync.wrong_vault`,
  `sync.header_mismatch`, `sync.rollback`, `sync.fork`, `sync.conflict`,
  `sync.unsupported_backend`, `sync.backend`, `sync.keyring_header`, `sync.invalid`,
  `sync.store`, `sync.vault`, `vault.locked`, `sync.io`, plus `http.*` (trust prompt etc.).

## Left open
- **Workspace**: `crates/mooring-sync` added to `members` / `default-members` and `rusty-s3`
  0.11.0 (`default-features = false, features = ["rustcrypto"]`, BSD-2) to `Cargo.lock` —
  orchestrator-owned files; please review/keep on merge. Security review of the new dependency.
- TODO(merge): `src/tests/s3_mock.rs` checks presign shape and signed-header coverage only;
  swap for `mooring-testsrv::s3` (full SigV4, rollback/fork knobs) when QA lands it. QA: cargo-fuzz
  targets for `mooring_sync::fuzz::{fuzz_msy1, fuzz_snapshot_json}`; MinIO in CI.
- Not in the snapshot yet: secret sources (E1 has no table yet); per-device settings by design.
- `vault_join` must start from an **empty store** (no "All connections" root created first),
  otherwise the joining device's own root merges in as an extra folder under the remote root.
- Trust files are rewritten directly (`<name>.sync-tmp` + rename, 0600). The Tauri layer must
  serialise `apply` with `KnownCerts` writers and drop any in-memory trust caches afterwards.
- The sealed base lives in the `setting` table as hex JSON (≈ 2× snapshot size, cap 160 MiB).
- `mooring-http::put_raw` retries on connect errors/timeouts/5xx; we avoid it with a second
  client (`max_attempts = 1`). A per-call `retry: false` in mooring-http would be cleaner.

## Decision needed
- **HKDF inputs**: implemented as in ADR-0017 §2 (`salt = vault_id`, `info = "mooring sync v1"`),
  not the task's `info = "mooring-sync-v1" ‖ vault_id`. Equivalent separation; pinned by vectors.
- **Keyring wrap**: the header's `keyring_wrap` is part of the password wrap's AAD, so it cannot
  be stripped without the KEK. Sync refuses (`sync.keyring_header`) while it is enabled.
- **Password change**: a blob is accepted only when the remote header equals this device's
  header (`sync.header_mismatch` otherwise). Changing the password on one device stops sync on
  the others until they adopt the new header — belongs to the A4 password-change rework.
- Folders resolve true conflicts by last-writer-wins instead of duplicating (no secrets inside).

## Test evidence
`cargo fmt --all && cargo clippy -p mooring-sync -p mooring-vault -p mooring-store --all-targets
-- -D warnings` clean; `cargo test -p mooring-sync -p mooring-vault -p mooring-store` green.
mooring-sync 32: vectors (committed blob + snapshot, decrypt), canonical encoding, round trip,
tamper per header field / nonce / body / counter, HKDF domain separation (info, salt, other
vault, DEK ≠ subkey), caps + invariants, proptests (decode never panics, any bit flip rejected,
valid headers decode); merge matrix (disjoint edits, true conflict → both copies, add/add,
delete/modify, delete/delete, tombstones without base, folder LWW, credential re-seal opens
under the copy id, trust line sets, fixups); engine (push/pull/no-change incl. trust file,
merge with a secret conflict on two devices, two engines racing → one `If-None-Match` winner +
merge, equal-counter fork + resolve remote, foreign history fork + resolve local, rollback and
vanished object, tampered blob / swapped header / foreign vault, probe refusal, locked vault);
S3 over HTTP mock (conditional writes, HEAD/GET/DELETE, Content-Length cap, probe pass/refuse,
two devices racing over HTTP with a real 412, config validation, no secret in `Debug`).
mooring-vault +2 (`subkey`), mooring-store +3 (`sync_rows`).

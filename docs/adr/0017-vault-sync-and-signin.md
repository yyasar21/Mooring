# ADR-0017: Vault sync to S3-compatible storage, and the A3 sign-in items

Status: Accepted · 2026-11-04 (Phase A3; extends ADR-0002, ADR-0005, ADR-0006, ADR-0014)

## Context
The roadmap lists for A3 "vault sync: client-side encrypted blob to S3-compatible storage with
conflict detection" and "optional sign-in with Active Directory (LDAPS) and FIDO2 `hmac-secret`
as a vault second factor", with "sync integrity (AEAD with version counters)" and "LDAP
injection" as security focus. Today the vault is `KEK = Argon2id(password)` → wrapped random
DEK → per-field XChaCha20-Poly1305 (ADR-0002); inventory is plaintext in `mooring.db` (R-INV);
the keyring wrap is on HOLD until each OS has a biometric ACL (R-T2-KR, a1-orchestrator).

## Decision — sync

### 1. What is synced
A **logical snapshot**, not the SQLite file: folders, connections, options, tags, credential
rows (fields plaintext + secrets still sealed under the DEK, unchanged), secret sources,
`known_hosts` and `known_*_certs` entries (owner decision 3), tombstones. Not synced: the audit
log (a per-device chain), settings that are per device (auto-lock, syslog, window state),
web-session cookie stores, the keyring wrap. Encoding: canonical JSON (sorted keys), one
document, ≤ 64 MiB before encryption.

### 2. Blob format `MSY1` (one object per vault, plus a header object)
```
magic "MSY1" | ver u8 = 1 | vault_id [16] | device_id [16] | counter u64 | parent_counter u64
| parent_hash [32] | header_hash [32] | created_unix u64 | nonce [24] | ciphertext (+16 tag)
```
- `sync_key = HKDF-SHA256(ikm = DEK, salt = vault_id, info = "mooring sync v1")` (`hkdf` 0.13
  is in the lockfile); XChaCha20-Poly1305 from `mooring-vault` (RustCrypto); AAD = every byte
  before `nonce`. No compression (length leaks are accepted, compression oracles are not).
- `counter` is the vault's sync generation (+1 per push); `parent_*` name the blob this one was
  built on; `parent_hash` = SHA-256 of that blob's full bytes. `header_hash` = SHA-256 of the
  vault header object (below), so a swapped header cannot pair with a blob.
- Objects under `<prefix>/<vault_id>/`: `header` (the ADR-0002 header **without** the keyring
  wrap; needed by a new device to unlock), `current` (the latest `MSY1`), `history/<counter>`
  (the last 10). The bucket operator gets the Argon2id-protected header (same offline-guessing
  exposure as a stolen backup, T1) and ciphertext sizes, nothing else.
- Parsers read the fixed header first, check `ver`, `vault_id` and the size cap (Content-Length
  **and** a streamed hard cap) before allocating the body (review 5 allocation-before-check).

### 3. Push, pull and conflicts
- Local state (in `mooring.db`, device-only): `sync.last_counter`, `sync.last_hash`,
  `sync.base` (the last synced plaintext snapshot, re-sealed under the DEK as one secret for
  three-way merges), `device_id`.
- **Push**: build `counter = remote.counter + 1`, `parent = remote`; upload `current` with a
  conditional write `If-Match: <ETag of the remote current>` (first push: `If-None-Match: *`).
  `412 Precondition Failed` = someone pushed in between → pull, merge, retry (≤ 3).
- **Pull**: verify AEAD; `counter < last_counter` → **hard stop** "SYNC ROLLBACK" (audited,
  never applied); `counter == last_counter` with a different hash → **fork** alarm (two devices
  published the same generation; refuse, show both); `parent_hash == last_hash` and no local
  changes → fast-forward; otherwise → merge.
- **Merge** (three-way against `sync.base`, per row id): changed on one side → take it;
  changed on both → keep both (the remote copy is renamed "… (conflict <device>)" for folders,
  connections and credentials; never a silent overwrite of a secret); delete vs edit → keep the
  edit, report it. The result is a new push. The UI shows a conflict list after every merge.
- **Backends without conditional writes are refused**: setup probes `If-None-Match: *` on a
  probe key twice (the second must return 412). AWS S3, MinIO and Ceph RGW recent releases pass;
  others are tested by the probe, not by a list.
- Triggers: pull after unlock and every 15 min while unlocked; push 30 s after the last local
  change. Sync needs the DEK, so nothing runs while locked. Freshness: a new device can be served
  an old but valid blob (freeze); the UI shows "last pushed by <device> at <time>" (R-SYNC-FREEZE).

### 4. Backend client
- `rusty-s3` 0.11.0 (BSD-2-Clause, 2026-10-27, sans-IO SigV4 signing on RustCrypto `hmac`/
  `sha2`) + `mooring-http` for transport (our verifier, `known_sync_certs`, caps, path-style or
  virtual-host URLs, custom endpoint, region). New kind **`s3_access_key`** (fields:
  `access_key_id`, `region?`; secrets: `secret_access_key`, `session_token?`) amends ADR-0009;
  it is valid only as the sync credential.
- Rejected: `object_store` 0.14.2 (Apache-2.0/MIT) — its `aws` feature pulls `aws-lc-rs`
  (banned) and `reqwest`; `aws-sdk-s3` — very large Smithy runtime, `aws-lc-rs` by default.

### 5. IPC
```
sync_get() -> SyncConfig|null      sync_status() -> { lastPull, lastPush, counter, state, conflicts }  # passive
sync_set({ endpoint, bucket, prefix, region, pathStyle, credentialId, options: { caPem|null } }) -> SyncConfig
sync_probe() -> { conditionalWrites: bool, error|null }
sync_now()   -> SyncReport { pulled, pushed, merged, conflicts: [{ kind, id, name }] }
sync_disable({ deleteRemote: bool }) -> void
vault_join({ endpoint, bucket, prefix, region, accessKeyId, secretAccessKey, password }) -> VaultStatus
```
`vault_join` creates a local vault from a remote header + blob on a fresh device (secrets
inward only). Audit: `sync.push { counter, bytes }`, `sync.pull`, `sync.merge { conflicts }`,
`sync.rollback_refused`, `sync.fork`, `sync.config_changed` (warning). Error codes:
`sync.conflict`, `sync.rollback`, `sync.fork`, `sync.unsupported_backend`, `sync.too_large`.

## Decision — sign-in items (recommendation: neither ships in A3)

### 6. AD / LDAPS sign-in → not as vault auth
- The vault key comes from the master password. An LDAP bind yields a yes/no from a server, not
  key material, so it cannot protect anything against T1 (the disk is decrypted with the
  password alone) and a local check is bypassed by a patched binary. Making it real means the
  directory holds a key share: that is a KMS/escrow design (Phase B with the agent/relay).
- What LDAPS **can** do usefully: a *directory lookup* to import computers and users into
  connections and `domain_user` credentials. That is an importer, so it moves to **A4** with
  the other importers and its own small ADR: LDAPS only (no StartTLS downgrade, no simple bind
  in clear), our verifier, RFC 4515 filter and RFC 4514 DN escaping for every user value (LDAP
  injection), result caps, read-only search. Dependency then: `ldap3` 0.12.1 (MIT/Apache-2.0)
  with `default-features = false, features = ["tls-rustls-ring"]` — **its last release is
  2025-09-18, older than our 12-month rule**, so it needs an exception or an alternative.

### 7. FIDO2 `hmac-secret` second factor → Phase B (or a late A4 ADR)
- The sound design is `KEK = HKDF(Argon2id(password) ‖ hmac-secret(salt))` with factor slots in
  a header v3, multi-key enrolment and recovery codes. It changes the vault format, which must
  be designed once together with the keyring/biometric ACL work that is on HOLD (R-T2-KR).
- Every implementation path needs OS FFI or C: Windows lets non-admin apps reach security keys
  only through `webauthn.dll` (the `windows` crate, `unsafe`); macOS/Linux raw HID needs IOKit /
  hidraw via `hidapi` (C). `ctap-hid-fido2` 3.6.1 (MIT, 2026-11-02, maintained) builds on
  `hidapi`; `authenticator` (Mozilla) and `webauthn-authenticator-rs` are MPL-2.0 (not on our
  licence allow-list). Each would need an `unsafe`/C exception ADR (as R-RDP-FFI).
- Recommendation: one "unlock factors" ADR (keyring ACL + biometrics + FIDO2) after A4.

## Alternatives considered
- Syncing the SQLite file: leaks plaintext inventory to the bucket and merges nothing. Rejected.
- `age` export as the sync format (ADR-0006): no counter, parent or AAD binding; good for
  backups, not for conflict detection. Rejected for sync, kept for export.
- Last-writer-wins without a base: silently loses edits and secrets. Rejected.
- A lock object instead of conditional writes: races and stale locks. Rejected.

## Security consequences
- T1/T3 at the bucket: confidentiality and integrity by AEAD under a DEK-derived key; rollback
  and fork detected per device; freeze and size leaks remain (R-SYNC-FREEZE, R-SYNC-SIZE).
- R-SYNC-HDR: the header in the bucket exposes Argon2id-guessing to the operator; an old header
  in history plus an old password opens the vault (ADR-0002 accepted risk: no DEK rotation).
- Every device that unlocks holds the same DEK; removing a device needs a DEK rotation
  (not in A3; owner question 4).

## Test plan
- Unit: `MSY1` encode/decode vectors, AAD tamper per field (proptest bit flips), rollback, fork,
  fast-forward, merge matrix (edit/edit, edit/delete, delete/delete, secret edit/edit),
  header-hash mismatch, size caps before allocation.
- Integration: an S3 mock in `mooring-testsrv` with ETags and conditional writes (and a mode
  without them → `sync.unsupported_backend`); two in-process devices racing pushes; MinIO in CI
  if the qa owner adds it (`#[ignore]` otherwise).
- Fuzz: `sync_blob_parse`, `sync_snapshot_json`, `s3_error_xml` (the `quick-xml` path).

## Open questions for the owner
1. Confirm: LDAPS sign-in dropped, directory lookup moves to the A4 importers (with an `ldap3`
   maintenance exception or another crate).
2. Confirm: FIDO2 `hmac-secret` moves to the post-A4 "unlock factors" ADR.
3. Sync trust stores (`known_hosts`, `known_*_certs`) between devices (proposed: yes)?
4. Is DEK rotation (needed to remove a device or a leaked header) in scope for A3?
5. Keep 10 blobs of history in the bucket (proposed), or none?

## Owner decisions (2026-11-04)
10. Synced vaults share their trust stores: `known_hosts` and every `known_*_certs` file are part
    of the snapshot; a trust decision made on one device is a trust decision on all.
11. DEK rotation is out of scope for A3 (A4 with the password-change rework).
12. LDAPS as vault auth and FIDO2 `hmac-secret` move out of A3 as recommended: LDAPS becomes a
    directory-lookup importer in A4; FIDO2 goes to the post-A4 "unlock factors" ADR with the
    keyring ACL. The roadmap is updated accordingly.

## Sources
crates.io API (2026-11-04): `rusty-s3` 0.11.0, `object_store` 0.14.2 (and its `Cargo.toml`:
`aws` → `aws-lc-rs`), `ldap3` 0.12.1 (and its `Cargo.toml` features), `ctap-hid-fido2` 3.6.1;
AWS S3 conditional writes (`If-None-Match`, `If-Match`) documentation; RFC 4514, RFC 4515;
CTAP 2.1 `hmac-secret` extension.

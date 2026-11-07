# ADR-0023: Vault export and import in the app (`age`)

Status: Accepted 2026-11-07 (owner decisions: 26 merge default, replace behind typed confirmation; 27 foreign import requires the source master password; 28 trust stores exported and unioned) · 2026-11-07 (Phase A5 / v0.2.0; completes ADR-0006 §Export; builds on
ADR-0010 §SFTP pick pattern, ADR-0013, ADR-0017 §1/§3, ADR-0019 plan pattern)

## Context
`mooring-vault::export` ships `export_age(doc, passphrase)` / `import_age(bytes, passphrase)`
(age v1, scrypt log N = 18 out, ≤ 20 in, 64 MiB caps, fixed error strings) with CI vectors
decrypted by the `age` CLI. `ExportDocument { header, credentials: Vec<ExportedRecord>,
folders: Value, connections: Value }` predates the store: `folders`/`connections` are opaque and
nothing fills them. No Tauri command exists (`ipc-codes.json` already reserves `vault.export`);
the roadmap row reads "library done". Since A3 the vault has a canonical logical view,
`mooring_sync::Snapshot` (folders, connections, credentials with sealed secrets, secret
sources via options, trust stores, tombstones) and a three-way `merge` with a conflict report
(ADR-0017 §3). Review 4 (B-4) fixed the rule that local paths never cross IPC: native dialogs
open from Rust and the UI sees a `pickId` and a display name.

## Decision

### 1. Document v2 (`mooring-vault`, rust-core)
```rust
pub struct ExportDocument { pub version: u32 /* 2 */, pub header: Header,
                            pub snapshot: mooring_sync::Snapshot, pub exported_at: String,
                            pub app_version: String }
```
- `snapshot` replaces the three legacy fields; `mooring-vault` cannot depend on `mooring-sync`
  (cycle: sync seals with vault), so the document moves to a new small module
  `mooring_sync::export` that wraps `mooring_vault::export::{export_age, import_age}` over
  `serde_json` bytes; the vault crate keeps the age container and its vectors. v1 documents
  (the committed vectors) stay readable: credentials only, folders/connections ignored with a
  report line. `header` is exported **without** `keyring_wrap` (ADR-0022: per device).
- Secrets stay sealed under the exporting vault's DEK (ADR-0006). Nothing in the file is
  plaintext beyond the inventory metadata that `mooring.db` already holds (R-INV).

### 2. Commands (src-tauri `commands/vault_export.rs`; vault must be unlocked)
```
vault_export_pick()  -> { pickId, name } | null              # native save dialog from Rust (*.age)
vault_export_age({ pickId, password, exportPassphrase }) -> { bytes, credentials, connections, folders }
vault_import_pick()  -> { pickId, name, bytes } | null       # native open dialog; file read in Rust
vault_import_inspect({ pickId, exportPassphrase }) -> ImportInspect { vaultId, sameVault, exportedAt,
                        appVersion, counts, needsSourcePassword }
vault_import_age({ pickId, exportPassphrase, sourcePassword|null, mode: "merge"|"replace",
                   password }) -> ImportReport { added, updated, conflicts: [{kind,id,name}], skipped }
```
- Export needs the **master password** (ADR-0006: "export … require the master password") and a
  separate export passphrase (≥ 12 chars, must differ from the master password — compared in
  Rust, never stored). The file is written atomically (`.part` + rename, L-16 pattern), mode
  0600, and audited `vault.exported { credentials, connections, folders }` (no path).
- Import reads the file in Rust (cap 64 MiB before decrypt), decrypts into `Zeroizing`, and
  holds the parsed document under the `pickId` for ≤ 10 min, single use, cleared on lock
  (ADR-0019 plan pattern). The pick is bound to `main`.
- **Same vault** (`snapshot.vault_id == ours`): sealed blobs open under our DEK; no source
  password. **Foreign vault**: the file's header + `sourcePassword` derive the foreign KEK →
  DEK in memory (`Zeroizing`, KDF ceiling and floor of ADR-0002 apply to the foreign header),
  every secret is opened and resealed under our DEK (`Reseal` as in sync), then the foreign DEK
  is dropped. Records keep their ids; `vault_id` stays ours.
- `merge` runs `mooring_sync::merge(base = None, local, remote = file, …)`: new ids added, same
  id changed on both sides → both kept, the imported copy renamed "… (imported <date>)", never a
  silent overwrite of a secret; tombstones in the file are ignored (a backup never deletes).
  Trust stores union. `replace` deletes every local folder, connection, credential and trust
  entry first, then applies the file, in one store transaction; it requires the master password
  twice in the UI (typed confirmation) and audits `vault.import { mode: replace }` as a warning.
  Both modes are one transaction; a failure leaves the store untouched.
- Sync (ADR-0017) sees an import as ordinary local changes; `replace` bumps the sync generation
  like any push. The keyring/biometric wrap is dropped on `replace` with a foreign file
  (`vault_rotated`, ADR-0022 §2) because the DEK does not change but the inventory does not
  belong to the enrolment — conservative, re-enrol afterwards.
- Error codes: `vault.export` (write failed), `vault.export_passphrase` (weak / equals master),
  `vault.import_format`, `vault.import_passphrase`, `vault.import_source_password`,
  `vault.import_too_large`, `vault.import_version`, `input.invalid "pick"` (reused).

### 3. Capabilities
None. `dialog:*` and `fs:*` stay out of every capability (ADR-0010); the two pick commands
use the `tauri-plugin-dialog` Rust API with `oneshot`, as `sftp_pick_local` does.

## Alternatives considered
- Letting the UI choose the path and pass it to Rust: rejected in review 4 (B-4), stays rejected.
- Plaintext JSON/CSV export "for other tools": secrets in the clear on disk; the age file plus
  the documented format is what a human needs to read a backup without Mooring. Rejected.
- Export of the SQLite file: ADR-0017 rejected it for sync; same reasons here (plaintext
  inventory, no verifiable structure, settings and audit leak).
- Import without a source password by shipping the foreign DEK in the file: the file would open
  every secret with the export passphrase alone, collapsing two factors into one. Rejected.
- Merge by name instead of id: duplicates on rename; ids are stable across devices (ADR-0017).

## Security consequences
- T1: an export file is an offline target with the same strength as the vault (scrypt N = 2¹⁸
  outer layer, Argon2id inner header); users are told to treat it as the vault. The export
  passphrase is never the master password (enforced).
- T4: a crafted file reaches the age parser (fuzzed since A1 exit), the JSON snapshot parser
  (`deny_unknown_fields`, caps per ADR-0009 §5 applied on import, ≤ 64 MiB, ≤ 100 000 records)
  and the foreign header parser (ADR-0002 ceiling: `m ≤ 4 GiB`, refuses above half of RAM).
  A hostile `replace` file can wipe the inventory: the typed confirmation and the audit warning
  are the guard; backups remain the user's responsibility (the UI offers an export first).
- T5: can start an export or import flow but never sees a path, bytes or passphrase outcome
  beyond counts; both commands need the master password typed by the user.
- Secrets pass IPC inward only (passwords); the file content never crosses IPC.

## UI
Settings → Vault → "Backup": Export (choose file → master password + export passphrase →
summary) and Import (choose file → passphrase → inspect card: same/foreign vault, counts,
source password field when foreign → Merge / Replace with typed `REPLACE` → report with the
conflict list). Strings in English; no path shown except the display name.

## Test plan
- Unit: v1/v2 document round trip; vectors unchanged; passphrase == master refused; foreign
  reseal (two in-memory vaults); merge report (add / both-changed / tombstone ignored); replace
  transaction rollback on a mid-apply failure; caps (64 MiB + 1, record count); pick expiry and
  single use; `keyring_wrap` absent from the written file.
- E2E (mock transport): both flows, conflict list rendered, typed confirmation gate.
- Fuzz: `export_document_json` (snapshot parser from decrypted bytes); `import_age` exists.
- Manual gate per OS: native save/open dialogs (docs/qa/native-dialogs.md rows added).

## Owner decisions needed
26. Import default: `merge` with a conflict report (recommended) — `replace` stays available
    behind the typed confirmation, or is removed entirely.
27. Foreign-vault import requires the source master password (recommended) rather than a
    "trust the file" option.
28. Trust stores (`known_hosts`, `known_*_certs`) included in exports and unioned on import
    (recommended, consistent with owner decision 10).

# ADR-0005: Local storage — SQLite with sealed columns

Status: Accepted · 2026-11-03 (Phase A1)

## Context
A1 needs a durable store for folders, connections, tags and credentials with credential
inheritance down the tree, per-connection overrides and full-text search. The vault (ADR-0002)
seals individual fields; it does not say where records live. The audit log (ADR-0002 §audit)
needs a stable home too.

## Decision
- One SQLite database per application: `$APP_DATA/mooring.db` (`rusqlite`, `bundled` feature,
  WAL, `foreign_keys=ON`, `secure_delete=ON`). The vault header stays in
  `$APP_DATA/vault.header.json`; the audit log stays per-app in `$APP_DATA/audit.jsonl` and
  carries `vault_id` (random UUID stored in the header, A1) in every entry. A1 supports exactly
  one vault per app; multi-vault is a later ADR.
- New crate `crates/mooring-store`. It owns the schema, migrations and queries. It never derives
  keys: callers pass an unlocked `&mooring_vault::Vault` to seal/open fields.
- Schema v1 (all ids are UUID text, timestamps RFC 3339 UTC):
  - `folder(id PK, parent_id FK NULL, name, default_credential_id FK NULL, sort, created_at, updated_at)`
  - `connection(id PK, folder_id FK, name, protocol, host, port NULL, credential_id FK NULL, created_at, updated_at)`
  - `connection_tag(connection_id FK, tag) PK(connection_id, tag)`
  - `credential(id PK, name, kind, username, created_at, updated_at)` plus sealed columns
    `secret BLOB` (JSON `Sealed`), `secret2 BLOB NULL` (second secret: SSH key passphrase,
    certificate private key). `kind ∈ {password, ssh_key, certificate}`.
  - `setting(key PK, value)` — `schema_version`, `vault_id`.
  - `search` FTS5 virtual table (contentless, `connection` name + host + tags), kept in sync by
    triggers.
- Deleted search tokens may linger in the FTS index until the store is closed (`optimize` +
  WAL truncate on close) or next opened (rebuild); the app must call `Store::close()` on exit.
  Retention bound: one session. Inventory metadata is accepted plaintext at rest (R-INV).
- Sealed columns use the vault's record/field AAD: record id = credential id, field name =
  column name. A sealed value cannot be moved between rows or columns.
- Migrations: numbered SQL scripts embedded with `include_str!`, applied inside one transaction,
  `schema_version` written last. Downgrade is refused.
- Credential resolution: `Store::effective_credential(connection_id)` walks the folder chain
  via `mooring_core::tree` (connection override → nearest folder `default_credential`). The UI
  gets credential ids and names only (ADR-0003).
- Inputs are validated with `mooring_core` constructors before they reach SQL; every query is
  parameterised; sizes capped (name 120, host 2048, tag 64, max 50 tags).

## Alternatives considered
- sled / redb: no FTS, no SQL migrations tooling, weaker inspection story. Rejected.
- One JSON file sealed as a whole: no partial reads, whole-file rewrite per change. Rejected.
- SQLCipher: whole-DB encryption duplicates the vault's per-field AEAD and adds a C crypto
  dependency outside the allow-list. Rejected; inventory metadata (hosts, names) is accepted
  as plaintext at rest in A1 — revisit if the threat model upgrades T1.

## Security consequences
Secret columns are AEAD-sealed and bound to row + column. `secure_delete` overwrites freed
pages. The store has no key material; a stolen `mooring.db` without the header + password yields
inventory metadata only (accepted risk, documented in the threat model).

## Test plan
Migrations from empty and from v1; CRUD round trips; inheritance resolution (override beats
folder, nearest folder wins, root fallback none); FTS search by name/host/tag; sealed column
cannot be opened under another row id; foreign-key cascade on folder delete; proptest on
seal/open through the store.

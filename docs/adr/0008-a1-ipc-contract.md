# ADR-0008: A1 IPC contract (store, credentials, sessions)

Status: Accepted · 2026-11-03 (Phase A1, items 3–5)

## Context
The UI (ADR-0003: untrusted) needs commands for the connection tree, credentials, sessions and
the audit viewer. This ADR is the interface proposal both `rust-core` (src-tauri) and
`ui-engineer` (apps/desktop/src/lib/ipc.ts) implement independently; the UI ships a mock
transport for `vite dev` / vitest so it does not wait for the Rust side.

## Decision
All commands return `IpcError { code, message }` on failure (codes are stable strings,
`<area>.<reason>`); inputs are size-capped per ADR-0005; ids are UUID strings; times RFC 3339.
Secrets cross IPC **inward only** (`credential_create.secret`, `vault_unlock.password`,
`session_answer.text`); nothing returns a secret.

### Tree
```
tree_list()                                     -> { folders: Folder[], connections: ConnectionSummary[] }
folder_create({ parentId, name })               -> Folder
folder_rename({ id, name })                     -> Folder
folder_move({ id, parentId })                   -> Folder
folder_set_default_credential({ id, credentialId|null }) -> Folder
folder_delete({ id })                           -> void          # cascades; root refused (tree.root)
connection_create({ folderId, name, protocol, host, port|null, credentialId|null, tags }) -> ConnectionSummary
connection_update({ id, ...same fields })       -> ConnectionSummary
connection_move({ id, folderId })               -> ConnectionSummary
connection_delete({ id })                       -> void
connection_search({ query, limit })             -> ConnectionHit[]   # { id, name, host, folderId, protocol }
```
`Folder = { id, parentId|null, name, defaultCredentialId|null, sort }`
`ConnectionSummary = { id, folderId, name, protocol, host, port|null, credentialId|null, effectiveCredentialId|null, tags, createdAt, updatedAt }`

### Credentials (metadata only outward)
```
credential_list()                               -> CredentialMeta[]   # { id, name, kind, username, createdAt, updatedAt }
credential_create({ name, kind, username, secret, secret2|null }) -> CredentialMeta   # kind: password|ssh_key|certificate
credential_update_meta({ id, name, username })  -> CredentialMeta
credential_replace_secret({ id, secret, secret2|null }) -> void
credential_delete({ id })                       -> void
credential_copy_password({ id })                -> { clearsInMs: 30000 }   # Rust writes clipboard, schedules clear, audits credential.copied
```

### Sessions (ADR-0004 events over a Tauri `Channel<SessionEvent>`)
```
session_open({ connectionId, size: {width,height}, onEvent: Channel<SessionEvent> }) -> { sessionId }
session_send({ sessionId, input: SessionInput })   -> void     # Bytes | Resize | Answer{id,text} | Pointer | Key
session_close({ sessionId })                       -> void
session_list()                                     -> { sessionId, connectionId, protocol, state, openedAt }[]
```
`SessionEvent` and `SessionInput` are the `mooring_core::session` serde shapes (`kind`-tagged
snake_case). Byte payloads (`SessionEvent::Bytes.data`, `SessionInput::Bytes.data`) are base64
strings on the wire in both directions (Tauri channels and command arguments serialise JSON).
`SessionInput::Answer { id, text }` carries a user-typed answer inward; `text` is a
`SecretString` on the Rust side and never serialised back.
`window_detach({ sessionId })` (UI tab "detach to window") is reserved: it needs its own window
label + capability (ADR-0003) and a security review, so it ships in A2; until then it returns
`ipc.unknown` and the UI keeps the tab.

### Audit
```
audit_tail({ limit, before|null })               -> AuditEntry[]   # newest first, limit ≤ 500
audit_verify()                                   -> { ok, entries, brokenAt|null }
```

### Vault (unchanged from A0 plus)
```
vault_change_password({ current, next })         -> VaultStatus
vault_status()                                   -> "missing" | "locked" | "unlocked"
```
Keyring and export commands are held (ADR-0006 / security review) and are not part of A1 UI.

### Wire conventions
Command arguments and returned objects use camelCase keys (Tauri's default `rename_all`).
`folder_delete` cascades without a typed confirmation; the UI confirms once in a dialog.

### Error codes used by the UI
`vault.locked`, `vault.unlock`, `vault.weak_password`, `tree.root`, `tree.cycle`,
`tree.not_found`, `input.invalid`, `credential.not_found`, `session.not_found`,
`session.failed`, `store.io`, `ipc.unknown`.

## Consequences
The UI can be built and tested against `MockTransport` implementing the same `Ipc` interface;
switching to Tauri is one import. Every command gets an input-validation test on the Rust side.

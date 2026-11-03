# Audit log

Mooring records security-relevant actions in an append-only, **hash-chained** log. Each entry
contains the SHA-256 hash of the previous one, so deleting, reordering or editing any entry
breaks the chain from that point on — and Mooring tells you where.

## Viewing

Open it with **Audit log** in the top bar or `mod Shift Y`. The view shows the newest entries
first, with a filter for event, host and credential, and a badge such as
**Chain intact, 10 entries**. The status bar at the bottom shows the chain status too. The
audit log needs an unlocked vault, because its entries reveal your inventory.

## What is recorded

| Event | When | Details |
| --- | --- | --- |
| Vault created | First start | — |
| Vault unlocked | Successful unlock | — |
| Vault locked | Lock | reason: `user`, `idle`, `screen_lock`, `sleep`, `window_hidden` |
| Password changed | Master password changed | — |
| Credential used | A secret is read for a connection or copied | credential id, purpose (`connect`, `copy`), connection |
| Session opened | A session is established | connection, protocol, server key fingerprint |
| Session closed | A session ends | connection, reason |
| Host trust decision | A host key is accepted, rejected or changed | host, presented fingerprint, decision; for `changed` also the expected fingerprint |
| Vault exported | Export (when available in the app) | format |

**Secrets are never written to the log** — not passwords, not keys, not answers you typed into
a prompt. Values that look like secrets are redacted before writing.

## Where it lives

The log is the file `audit.jsonl` in Mooring's application data directory: one JSON object
per line, readable with any text tool, file mode `0600` on macOS and Linux. One log serves the
whole application; each entry is tied to the vault through its `vault_id`.

## Verifying

Mooring verifies the chain when you open the view and every 60 seconds while the status bar
is visible. If verification fails, the badge turns magenta and names the first broken entry.
A broken chain means the file was modified outside Mooring, partially restored from a backup,
or damaged. Keep a copy of the file for investigation before doing anything else.

## Limits

- A local attacker with your user rights can delete the whole file or truncate it. Hash
  chaining detects edits, not complete removal of the tail. A **syslog mirror** to a log server
  you control is planned, so a copy exists outside your machine.
- Auth success and failure details are kept in the developer log (`MOORING_LOG`), not the
  audit log.

# Audit log

Mooring records security-relevant actions in an append-only, **hash-chained** log. Each entry
contains the SHA-256 hash of the previous one, so deleting, reordering or editing any entry
breaks the chain from that point on — and Mooring tells you where.

## Viewing

Open it with **Audit** in the navigation rail, `mod 3` or `mod Shift Y`. The view shows the
newest entries first in a table, with a badge such as **Chain intact, 10 entries**. The status
bar at the bottom shows the chain status too. The audit log needs an unlocked vault, because its
entries reveal your inventory.

### Filters

The filter bar above the table narrows what you see:

- **Filter audit entries**: free text, matched against the event, hosts and credential names.
- **Event type**, **Connection** and **Time** (any time, last hour, 24 hours, 7 or 30 days).
- **Clear filters** resets them; "N of M loaded entries" shows how many rows match.

Filters apply to the entries already loaded (200 per page). Use **Load older entries** to reach
further back, then filter again.

### Entry details

Select a row (or press `Enter` on it) to open the entry in a side panel: the event name and
code, the local and UTC time, each detail on its own line with names shown next to their ids,
and the hash of the previous entry. `Esc` or **Close entry details** returns to the row.

A credential's detail page has an **Audit** tab with the entries that name it (from the last
500 entries).

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
| Vault exported / imported | Backup export or import, or a refused import | counts, mode (`merge`, `replace`), whether the file came from another vault |
| Biometric unlock | Enabled, used, failed, suspended or disabled | reason (never a key) |
| Jump host opened / closed | Each hop of a [jump host](jump-hosts.md) chain | connection, hop, the hop's host key, close reason |
| Security-key sign-in | An SSH security key or smart card signs in | key fingerprint, backend, outcome |
| Smart card PIN asked | The PIN dialog was answered or cancelled | key fingerprint, outcome (never the PIN) |
| RD Gateway sign-in | A connection through an [RD Gateway](rd-gateway.md) | gateway, method, outcome; Basic sign-ins as a warning |
| Secret lease | A dynamic Vault credential is issued, renewed, fails to renew or is revoked | engine (never the lease id) |
| Forward refused | The web jump-host proxy refused a target outside the allowed list | connection, target |

This list shows the main events; the view names every event it records.

**Secrets are never written to the log** — not passwords, not keys, not answers you typed into
a prompt. Values that look like secrets are redacted before writing.

## Where it lives

The log is the file `audit.jsonl` in Mooring's application data directory: one JSON object
per line, readable with any text tool, file mode `0600` on macOS and Linux. One log serves the
whole application; each entry is tied to the vault through its `vault_id`.

## Verifying

Mooring verifies the chain when you open the view and every 60 seconds while the status bar
is visible. If verification fails, the badge turns red and names the first broken entry.
A broken chain means the file was modified outside Mooring, partially restored from a backup,
or damaged. Keep a copy of the file for investigation before doing anything else.

## Limits

- A local attacker with your user rights can delete the whole file or truncate it. Hash
  chaining detects edits, not complete removal of the tail. Turn on the **syslog mirror**
  (Settings → Syslog mirror) to keep a copy on a log server you control.
- There is no export from the view yet; the file itself is plain JSON lines.
- Auth success and failure details are kept in the developer log (`MOORING_LOG`), not the
  audit log.

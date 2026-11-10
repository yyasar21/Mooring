# A5 · ui-engineer · audit filters in Rust and "Export…"

Worktree `/home/claude/nexus/.claude/worktrees/agent-a14119a46a01c251c`, branch
`worktree-agent-a14119a46a01c251c`, from `a0d4c79` (includes rust-core `db98d59`). Spec: the UI
contract in `a5-rust-core-audit-export.md`. Closes the W3 (`a5-ui-harbor-w3.md`) Left open item
"Audit filters are client-side" and Decision needed 1 on the UI side. No cargo run, no manifest,
lockfile, capability or e2e change, no new dependency. `invoke()` is still only in `lib/ipc.ts`.

## Done

- **IPC** (`lib/ipc.types.audit.ts`, `lib/ipc.ts`):
  - `AuditFilterInput`, `AuditTailPage`, `AuditExportFormat`, `AuditExportResult`, the limits
    (32 events, 128 characters of text, 128-byte connection id, `AUDIT_SCAN_CAP` 50 000).
  - `auditSearch({ limit, before, filter })` calls `audit_tail` with `filter` and decodes
    `{ entries, scannedTo, done }` (`decodeAuditPage`; a missing `scannedTo` reads as done).
    `auditTail` (no filter, bare array) is unchanged.
  - `auditExport({ format, filter? })` calls `audit_export` and decodes `{ count, cancelled }`.
    Not in `POLLED_COMMANDS` (user activity).
- **Audit view** (`components/audit/`):
  - `useAuditLog.ts`: without a filter it pages `audit_tail` as before ("Load older entries").
    With one, Rust filters the whole log; the cursor is `page` (a full page, "Load more") or
    `scan` (Rust stopped at its scan cap before a full page: "Searched the newest N entries."
    and "Continue search"), both continuing with `before = scannedTo` until `done`. A newer
    request drops an older answer.
  - `auditFilter.ts`: `toFilterInput` maps the bar to the Rust filter. The event select becomes
    `events: [code]`; the connection select, `connection`; the time window, `since` in Unix ms,
    fixed when the filter is applied so paging stays on the same window. The text is trimmed
    and cut to 128 code points (the field also has `maxLength` 128). The selects apply at once;
    the text applies 300 ms after typing stops.
  - The select options are every event and connection seen in any page loaded so far
    (`mergeFacets`), so narrowing the list never removes a choice.
  - The counter says "N loaded entries" (unfiltered) or "N matches" / "N matches so far".
  - The text field's placeholder is now "Search details: host, credential, reason". Rust
    matches the redacted `key=value` details only, not the event label or `#seq`.
  - **"Export…"** (`AuditExportMenu.tsx`): a menu "Export format" with CSV and JSON Lines
    (arrows, Escape returns focus to the trigger). It sends the applied filter, or none.
    - Success: toast "Exported N entries" ("1 entry"); with a filter the second line is "Only
      the entries that match the filters." The list and the chain status reload, so the new
      row shows.
    - Cancel: nothing.
    - Failure: the `role="alert"` line with the friendly text.
  - `audit.exported` is labelled "Audit log exported" (details "format: csv   count: 12").
  - `EVENT_LABEL` and `formatTime` moved to `auditLabels.ts` (re-exported from `AuditView`).
- **Errors** (`stores/errors.ts`):
  - `audit.export`: "The audit export could not be written there. Nothing was saved; choose
    another location."
  - `audit.io`: "The audit log could not be read. Check the chain status, then try again."
  - Filter refusals (`input.invalid`) show the Rust message ("invalid filter: …").
- **Mock** (`lib/ipc.mock.audit.ts`, methods in `lib/ipc.mock.web.ts`), following
  `audit_query.rs` / `audit_export.rs`:
  - `compileAuditFilter`: the same refusals and messages ("invalid filter: too many event
    names", "unknown event name", "connection id", "since is after until", "text too long",
    "text", "unknown field"); empty values set no condition. The known events are the ones the
    mock has recorded, plus `audit.exported`.
  - Redaction: a TS port of `mooring_audit::redact` (PEM, Bearer/Basic, secret keys) applied to
    each rendered `key=value` line. The unfiltered `auditTail` is redacted too, as in Rust.
  - Matching: events any-of, connection exact, `since` inclusive / `until` exclusive on
    `floor(at)` ms, text case-insensitive over the redacted lines only.
  - `scanAuditPage`: the `scan_page` algorithm (newest `cap` candidates, `scannedTo`, `done`).
  - The export writes the CSV (header row, columns, CRLF, RFC 4180 quoting, `'` before
    `= + - @ \t \r`, `#end` footer) or the JSONL (header, entries, footer) to `auditFiles`, then
    records `audit.exported { format, count }`.
  - Knobs: `auditSaves` (queued dialog answers, `null` = cancel; the extension is added),
    `failAuditExport` (`audit.export`), `auditScanCap`. Both commands need an unlocked vault;
    the export checks the filter before the dialog and the vault again after it.

## Left open

- The event select offers one event at a time. The contract allows up to 32 (any-of); a
  multi-select was not asked for.
- Choices come from loaded pages: an event or connection that only occurs in older, unloaded
  entries is not offered until a page shows it.
- The "Last hour" … "Last 30 days" windows count back from the moment the filter is applied.
  The mock's seed rows have fixed 2026-11 timestamps, so in the browser demo a short window may
  show no match.
- No e2e flow for export (qa-owned `apps/desktop/e2e/`). The mock knobs above are ready for one.

## Decision needed

1. **Free-text scope (rust-core Decision 2).** I took the narrower server scope: the details
   only. A search for an event label ("Session closed") or `#seq` finds nothing now; the event
   select covers the label case. Confirm, or ask rust-core to include the event name.
2. **Time units (rust-core Decision 1).** The UI sends Unix milliseconds (`Date.now()`), as
   proposed. Nothing to change if confirmed.

## Test evidence

- `pnpm typecheck` ✓ · `pnpm lint` ✓ · `pnpm build` ✓
- `pnpm test`: 119 files / 919 tests, all green (W3 ended at 118 / 903). The command-name
  guard (`ipc.commands.test.ts`) passes: `audit_export` is registered in `generate_handler!`.
- `make e2e` (Playwright, mock transport): 42/42 passed (flows 5, kube 6, vsphere 4,
  secrets-sync 7, a4 11, a5 9).
- New tests:
  - `lib/ipc.mock.audit.test.ts`:
    - validation and messages
    - redaction (including PEM)
    - filter semantics (events, connection, window, text over details only, no secret
      findable, `[redacted]` findable)
    - paging (full page, scan cap, done, empty log)
    - locked vault
    - CSV and JSONL layout, the `audit.exported` row with no file name
    - cancel writes and audits nothing
    - a bad filter is refused before the dialog
    - write failure
    - CSV quoting and formula neutralising
  - `lib/ipc.tauri.a5.test.ts`: `audit_tail` with `filter` and page decoding, `audit_export`
    arguments and result, not polled.
  - `components/audit/auditFilters.test.tsx` (rewritten):
    - `toFilterInput`, `mergeFacets`, `searchedCount`
    - the selects call `auditSearch` with the Rust filter
    - text debounce
    - "Load more" then "Continue search" over a log larger than the scan cap
    - a refused filter as an alert
    - export: CSV with a filter (toast "Exported 1 entry", file, audit row)
    - export: JSON Lines unfiltered (new row labelled "Audit log exported")
    - cancel shows nothing; a failure shows the friendly text
    - the menu's Escape returns focus
- Updated: `components.test.tsx` audit case. The text "closed" now matches only through the
  `reason` detail, after the debounce.

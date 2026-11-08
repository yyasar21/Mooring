# A5 · rust-core · filtered `audit_tail` and `audit_export`

Worktree `/home/claude/nexus/.claude/worktrees/agent-a7535772d057825c0`, branch
`worktree-agent-a7535772d057825c0`, from `faa242f`. Answers `a5-ui-harbor-w3.md` Decision needed 1
(audit export, approved by the orchestrator) and the Left open item "filtered `audit_tail`".
No new dependency, no manifest or lockfile change.

## Done

- **`mooring-audit`**
  - New event `audit.exported { format, count }` (`event/a5.rs`). It records no path and no
    filter text.
  - `is_known_event(name)`: whether a name is a current `AuditEvent` wire tag. It asks serde, so
    it cannot drift from the enum. Tested with snake_case names, renamed names and names that are
    not events.
- **`commands/audit_query.rs`** (new): the filter, redaction and scan code that both commands use.
  - `AuditFilterInput` is `deny_unknown_fields`. Every part is optional:
    - `events`: at most 32 names, each a known event; the entry matches any of them
    - `connection`: at most 128 characters, no control characters; it must equal the entry's
      `connection` detail exactly
    - `since` (inclusive) and `until` (exclusive): Unix **milliseconds**; `since > until` is
      refused
    - `text`: at most 128 characters after trimming, no control characters; matched
      case-insensitively
    - An empty list, an empty string or blank text sets no condition.
  - Redaction (`Redacted`): each detail is rendered as `key=value` and passed through
    `mooring_audit::redact`. So a secret-looking value (`password=…`, `token: …`, `Bearer …`, PEM)
    and the value of a secret-named key are both replaced. A value that does not change keeps its
    JSON type. `seq`, `at`, `prev` and `event` are not touched. The free-text filter searches only
    these redacted `key=value` lines. It does not search the event name, `seq`, `at` or `prev`,
    and `null` details are not rendered.
  - Scan cap: **`SCAN_CAP = 50_000` candidate rows per call** (a candidate is a row with
    `seq < before`). Each call reads the file twice:
    1. A cheap pass reads only `seq` from the `{"seq":N,` prefix, with a small serde fallback, to
       count the candidates.
    2. A full pass parses and filters only the newest 50 000 candidates.
    - Memory is limited to `limit` entries. Broken and oversized lines (over 64 KiB) are skipped,
      as before.
- **`audit_tail`** (`commands/audit.rs`):
  - New optional `filter` argument.
  - Without a filter it returns the same bare array as before. The entries are now `Redacted`;
    the wire shape is unchanged.
  - With a filter it returns `{ entries, scannedTo, done }`.
- **`audit_export`** (`commands/audit_export.rs`, new; registered in `lib.rs` and
  `guard/table.rs`, `Scope::Main`):
  - Rust checks the vault and the filter, then opens the native save dialog through
    `LocalPicker::pick_save`, the same way as `vault_export_pick`. The auto-lock
    `dialog_guard` is held while the dialog is open.
  - The vault is checked again after the dialog. The answer goes through the same checks as the
    backup target (`vault_export::check_save_target`, now shared): an existing absolute directory
    outside the app data dir, a UTF-8 name that does not start with `.`, not a non-file. `.csv` or
    `.jsonl` is appended when missing.
  - The write runs off the async runtime (`off_thread`) and holds the audit mutex, so no entry is
    appended between the chain check and the rows.
  - The file is written through `create_part`: `.<name>.<random>.part`, `create_new`, 0600, then
    `BufWriter`, `sync_all`, rename and a directory sync (L-51). The part file is removed on any
    error.
  - After the file is written, `audit.exported { format, count }` is recorded. A cancelled dialog
    writes nothing and records nothing.
  - **CSV** (CRLF line endings, written by hand to RFC 4180):
    - row 1: `#mooring-audit-export,version=1,exported_at=<RFC 3339>,chain=intact|broken,verified_entries=N,broken_at=<line or empty>,filtered=true|false`
    - row 2: `seq,at,event,details,prev`
    - then one row per matching entry, oldest first; `details` is the redacted `key=value`
      lines joined with `; `
    - last row: `#end,rows=N,chain=intact|broken`
    - Cells that contain `,`, `"`, CR or LF are quoted, with `"` doubled. A cell that starts with
      `=`, `+`, `-`, `@`, tab or CR gets a leading `'`.
  - **JSONL**:
    - first line: `{"header":{"format":"mooring-audit-export","version":1,"exportedAt":…,"chain":{"ok","entries","brokenAt"},"filtered":bool}}`
    - then the entries in the `audit_tail` shape, oldest first
    - last line: `{"footer":{"rows":N,"chain":{…}}}`
  - The export has no scan cap: it streams the whole log.
- New IPC code `audit.export` ("the audit export could not be written"); `ipc-codes.json` and
  `ipc-manifest.json` re-blessed.
- `src-tauri/tests/e2e_flow/support.rs`: new locked-vault matrix row `audit_export`. It is
  refused with `vault.locked` before any dialog, even with a picker that would cancel.

## Left open

- **Files outside `crates/**` and `src-tauri/src/**`.** Registering the command needs these
  three. Without them `guard::capability_tests`, the golden tests and the locked-vault matrix fail.
  - `src-tauri/permissions/mooring-main.toml`: one line, `"allow-audit-export"`. This is a
    capability change and needs **security-reviewer sign-off**.
  - `src-tauri/permissions/autogenerated/audit_export.toml`: written by `tauri-build`.
  - `src-tauri/tests/e2e_flow/support.rs`: the matrix row (QA area).
- **The export holds the audit mutex for the whole write.** On a very large log this delays the
  audited commands that run at the same time. The cost is linear in the log size; there is no
  cap and no progress events.
- **The export cannot be re-verified.** Rows are redacted and may be filtered, so their `prev`
  hashes do not chain. The header states whether the whole log verified at export time.
- **Timestamps are milliseconds; storage has nanoseconds.** `since` and `until` compare
  `floor(at_ns / 1e6)`.
- **The UI still needs to wire both features** (owned by ui-engineer):
  - `ipc.ts`: the `filter` argument, the page answer and `auditExport`
  - the mock
  - an "Export…" button in the filter bar
  - friendly text for `audit.export`
  - moving the filters to the server

## Decision needed

1. **Time units.** The filter uses Unix milliseconds (JS `Date.now()`). Confirm, or ask for
   seconds.
2. **Free-text scope.** As specified, it searches only the redacted details. The W3 client-side
   filter also searched the event label and `seq`. Confirm that the server filter may be
   narrower, or let the UI keep matching labels on its side.
3. **Capability line.** Security review of `allow-audit-export` in `mooring-main.toml` (see Left
   open).

## Test evidence

- `cargo fmt --all --check` ✓
- `cargo clippy --workspace --all-targets --offline -- -D warnings` ✓
- `cargo deny --offline check` ✓ (advisories, bans, licenses, sources)
- `cargo test -p mooring-audit` ✓ (44 unit tests), including the new tests
  `known_event_names_follow_the_enum` and `audit_exported_wire_shape`
- `cargo test -p mooring-app` ✓ (lib 489 passed / 1 ignored; `e2e_flow` 55 passed)
- New tests in `commands/audit_query_tests.rs`:
  - `compile_validates_every_field`: the 32-name cap, unknown event names, `since`/`until` order,
    the 128-character text cap (counted in characters), control characters, the connection id,
    empty values meaning no condition, and `deny_unknown_fields`
  - `filter_semantics_events_connection_window_and_text`: any-of events, exact connection,
    inclusive/exclusive window, and text that is case-insensitive and searches details only (not
    the event name, not `null`)
  - `paging_cursor_and_scan_cap`: the cap stops the scan and `scannedTo` continues it; the cursor
    of a full page; `done`; a missing log
  - `broken_and_oversized_lines_are_skipped`, `line_seq_fast_path_and_fallback`
  - `details_are_redacted_and_text_never_sees_secrets`: no `hunter2` or token in the output, the
    text filter cannot find them, `[redacted]` is findable
  - `secret_named_detail_keys_lose_their_value`
- New tests in `commands/audit_export_tests.rs`:
  - `csv_cells_are_quoted_and_formulas_neutralised`: every injection prefix, and quoting combined
    with injection
  - `csv_export_writes_header_rows_footer_privately_and_is_audited`: layout, redaction, mode
    0600, no `.part` file left, the `audit.exported` row with no path
  - `jsonl_export_is_filtered_redacted_and_framed`
  - `header_reports_a_broken_chain`
  - `cancel_writes_and_audits_nothing`
  - `refusals_bad_filter_bad_target_and_locked`: a bad filter is refused before the dialog and
    nothing is written; a target in the data dir, a directory or a relative path is refused; a
    locked vault is refused
  - `a_failed_write_leaves_no_part_file`
  - `format_and_input_wire_names`
- `commands/audit.rs`: `filtered_tail_returns_a_page_and_the_bare_tail_keeps_its_shape`.

## UI contract

```ts
/** Every part optional; [] / "" / blank text = no constraint. Unknown keys are refused. */
export interface AuditFilterInput {
  /** ≤ 32 event wire names (e.g. "vault_locked", "audit.exported"); any-of. Unknown → input.invalid. */
  events?: string[];
  /** Connection id; equals the entry's `connection` detail. ≤ 128 chars, no control chars. */
  connection?: string;
  /** Unix milliseconds, inclusive. */
  since?: number;
  /** Unix milliseconds, exclusive. since > until → input.invalid. */
  until?: number;
  /** ≤ 128 chars (after trim), no control chars; case-insensitive substring of the redacted
   *  `key=value` detail lines only (not the event name, seq, at or prev). */
  text?: string;
}

/** Wire entry (unchanged shape): envelope + flattened, redacted details. */
export interface AuditEntryWire {
  seq: number;
  at: string; // RFC 3339 UTC
  prev: string;
  event: string;
  [detail: string]: unknown; // redacted; may be null
}

export interface AuditTailPage {
  /** Matches, newest first, at most `limit` (1..=500). */
  entries: AuditEntryWire[];
  /** Pass as `before` for the next call: the oldest returned seq when the page is full,
   *  otherwise the oldest seq scanned. null when nothing was scanned. */
  scannedTo: number | null;
  /** true: the whole log (below `before`) has been tested; stop paging. */
  done: boolean;
}

// audit_tail: without `filter` the answer is the bare array, exactly as today.
invoke<AuditEntryWire[]>("audit_tail", { limit, before });
invoke<AuditTailPage>("audit_tail", { limit, before, filter });
// One call tests at most 50 000 rows below `before`; a page may be empty with done=false —
// call again with before = scannedTo (e.g. "Search older entries").

export type AuditExportFormat = "csv" | "jsonl";
export interface AuditExportResult {
  /** Entries written; 0 when cancelled. */
  count: number;
  /** The user closed the save dialog: nothing written, nothing audited. */
  cancelled: boolean;
}
// Opens the native save dialog from Rust; the UI never sees a path.
invoke<AuditExportResult>("audit_export", { format, filter }); // filter optional
```

Error codes:
- `vault.locked`: before the dialog, or when the vault locked while the dialog was open
- `input.invalid`: a bad filter (before the dialog) or an unusable target (`invalid pick: …`)
- `audit.io`: the log could not be read or verified
- `audit.export`: the file could not be written; no part file is left behind
- `state.poisoned`

`audit_export` is user activity: it is not in `PASSIVE_COMMANDS`.

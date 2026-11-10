// Filtered audit reads and the audit export, as rust-core serves them
// (`docs/handoff/a5-rust-core-audit-export.md`, UI contract). The UI never sees a path: the save
// dialog opens from Rust, and only `{ count, cancelled }` comes back.
import type { AuditEntry } from "./ipc.types";

/** Most event names in one filter. */
export const MAX_FILTER_EVENTS = 32;
/** Longest free-text filter, in characters (after trimming). */
export const MAX_FILTER_TEXT = 128;
/** Longest connection id the filter accepts. */
export const MAX_FILTER_CONNECTION = 128;
/** Most candidate rows one filtered `audit_tail` call tests (Rust `SCAN_CAP`). */
export const AUDIT_SCAN_CAP = 50_000;

/** Every part optional; `[]`, `""` and blank text set no condition. Unknown keys are refused. */
export interface AuditFilterInput {
  /** Event wire names, any of (at most 32). An unknown name is `input.invalid`. */
  events?: string[];
  /** Equals the entry's `connection` detail. */
  connection?: string;
  /** Unix milliseconds, inclusive. */
  since?: number;
  /** Unix milliseconds, exclusive. `since > until` is `input.invalid`. */
  until?: number;
  /** Case-insensitive substring of the redacted `key=value` detail lines only. */
  text?: string;
}

/** One page of a filtered tail. */
export interface AuditTailPage {
  /** Matches, newest first, at most `limit`. */
  entries: AuditEntry[];
  /** `before` of the next call; null when nothing was scanned. */
  scannedTo: number | null;
  /** The whole log below `before` has been tested: stop paging. */
  done: boolean;
}

export type AuditExportFormat = "csv" | "jsonl";

export interface AuditExportResult {
  /** Entries written; 0 when cancelled. */
  count: number;
  /** The user closed the save dialog: nothing was written or audited. */
  cancelled: boolean;
}

export interface AuditIpc {
  /** `audit_tail` with a filter: one page and the cursor to continue from. */
  auditSearch(args: { limit: number; before: number | null; filter: AuditFilterInput }): Promise<AuditTailPage>;
  /** `audit_export`: Rust opens the save dialog, writes the redacted rows and audits `audit.exported`. */
  auditExport(args: { format: AuditExportFormat; filter?: AuditFilterInput }): Promise<AuditExportResult>;
}

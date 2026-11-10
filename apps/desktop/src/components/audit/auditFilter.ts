import { MAX_FILTER_TEXT, type AuditEntry, type AuditFilterInput } from "../../lib/ipc";

/** Time windows of the audit filter bar (L4). */
export type AuditSpan = "any" | "hour" | "day" | "week" | "month";
export const SPAN_LABEL: Record<AuditSpan, string> = {
  any: "Any time",
  hour: "Last hour",
  day: "Last 24 hours",
  week: "Last 7 days",
  month: "Last 30 days",
};
const SPAN_MS: Record<Exclude<AuditSpan, "any">, number> = { hour: 3_600_000, day: 86_400_000, week: 7 * 86_400_000, month: 30 * 86_400_000 };

export interface AuditFilter {
  text: string;
  /** Raw event code, or "" for every event. */
  event: string;
  /** Connection id, or "" for every connection. */
  connection: string;
  span: AuditSpan;
}

export const NO_FILTER: AuditFilter = { text: "", event: "", connection: "", span: "any" };

export const isFiltered = (f: AuditFilter): boolean => f.text.trim() !== "" || f.event !== "" || f.connection !== "" || f.span !== "any";

/**
 * The filter Rust runs (`audit_tail` / `audit_export`), or null for the unfiltered log. The time
 * window counts back from `now` in Unix milliseconds; the text is trimmed and cut to 128
 * characters, and Rust matches it against the redacted `key=value` details only.
 */
export function toFilterInput(f: AuditFilter, now = Date.now()): AuditFilterInput | null {
  if (!isFiltered(f)) return null;
  const out: AuditFilterInput = {};
  if (f.event) out.events = [f.event];
  if (f.connection) out.connection = f.connection;
  if (f.span !== "any") out.since = Math.max(0, Math.floor(now - SPAN_MS[f.span]));
  // Rust counts characters (code points), not UTF-16 units.
  const text = Array.from(f.text.trim()).slice(0, MAX_FILTER_TEXT).join("").trim();
  if (text) out.text = text;
  return out;
}

export interface AuditFacets {
  events: string[];
  connections: string[];
}

export const NO_FACETS: AuditFacets = { events: [], connections: [] };

/**
 * The select options: event codes and connection ids seen in any page loaded so far (filtered or
 * not), so narrowing the list never removes the choices. Returns `prev` when nothing is new.
 */
export function mergeFacets(prev: AuditFacets, entries: readonly AuditEntry[]): AuditFacets {
  const events = new Set(prev.events);
  const connections = new Set(prev.connections);
  for (const e of entries) {
    events.add(e.event);
    if (e.details.connection) connections.add(e.details.connection);
  }
  if (events.size === prev.events.length && connections.size === prev.connections.length) return prev;
  return { events: [...events], connections: [...connections] };
}

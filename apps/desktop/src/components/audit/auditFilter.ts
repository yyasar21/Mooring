import type { AuditEntry } from "../../lib/ipc";

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
 * Which loaded rows a filter keeps. `haystack` is what the free-text field searches (the label,
 * the described details, the sequence number). The time window counts back from `now`.
 */
export function filterAudit(entries: readonly AuditEntry[], f: AuditFilter, haystack: (e: AuditEntry) => string[], now = Date.now()): AuditEntry[] {
  const q = f.text.trim().toLowerCase();
  const since = f.span === "any" ? null : now - SPAN_MS[f.span];
  return entries.filter((e) => {
    if (f.event && e.event !== f.event) return false;
    if (f.connection && e.details.connection !== f.connection) return false;
    if (since !== null) {
      const t = Date.parse(e.at);
      if (!Number.isFinite(t) || t < since) return false;
    }
    return !q || haystack(e).some((s) => s.toLowerCase().includes(q));
  });
}

/** Distinct values of the loaded rows, for the select options: event codes and connection ids. */
export function auditFacets(entries: readonly AuditEntry[]): { events: string[]; connections: string[] } {
  const events = new Set<string>();
  const connections = new Set<string>();
  for (const e of entries) {
    events.add(e.event);
    if (e.details.connection) connections.add(e.details.connection);
  }
  return { events: [...events], connections: [...connections] };
}

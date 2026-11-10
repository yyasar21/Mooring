import { useCallback, useEffect, useMemo, useState } from "react";
import { DataTable, type DataColumn } from "@mooring/ui";
import { ipc, MAX_FILTER_TEXT, type AuditEntry, type AuditVerify } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { useCredentials } from "../../stores/credentials";
import { AuditDrawer } from "./AuditDrawer";
import { AuditExportMenu } from "./AuditExportMenu";
import { EVENT_LABEL, formatTime } from "./auditLabels";
import { NO_FACETS, NO_FILTER, SPAN_LABEL, isFiltered, mergeFacets, toFilterInput, type AuditFilter, type AuditSpan } from "./auditFilter";
import { searchedCount, useAuditLog, type AuditLog } from "./useAuditLog";

export { EVENT_LABEL, formatTime } from "./auditLabels";

/** The free text goes to Rust once typing pauses. */
export const TEXT_DEBOUNCE_MS = 300;

/**
 * Audit log viewer: newest first, chain verification, filters by event type, connection, time and
 * detail text, and a drawer with the structured fields of the picked row. Without a filter it
 * pages the log with `before`; with one, Rust filters the whole log (`audit_tail` with `filter`)
 * and the list pages with its `scannedTo` cursor. "Export…" writes the filtered rows (Rust dialog).
 */
export function AuditView() {
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [filter, setFilter] = useState<AuditFilter>(NO_FILTER);
  // The filter Rust runs: the selects apply at once, the text when typing pauses.
  const [applied, setApplied] = useState<AuditFilter>(NO_FILTER);
  const [picked, setPicked] = useState<number | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [facets, setFacets] = useState(NO_FACETS);
  const connections = useTree((s) => s.connections);
  const creds = useCredentials((s) => s.items);

  useEffect(() => {
    if (filter.text === applied.text) {
      if (filter !== applied) setApplied(filter);
      return;
    }
    const t = setTimeout(() => { setApplied(filter); }, TEXT_DEBOUNCE_MS);
    return () => { clearTimeout(t); };
  }, [filter, applied]);

  // `since` is fixed when the filter is applied, so "Load more" pages the same window.
  const input = useMemo(() => toFilterInput(applied), [applied]);
  const log = useAuditLog(input);
  const entries = log.entries;
  useEffect(() => { setFacets((f) => mergeFacets(f, entries)); }, [entries]);

  const runVerify = useCallback(async () => {
    try {
      setVerify(await ipc.auditVerify());
      setVerifyError(null);
    } catch (e: unknown) {
      setVerifyError(describeError(e));
    }
  }, []);

  useEffect(() => { void runVerify(); }, [runVerify]);
  const refresh = () => { void log.reload(); void runVerify(); };

  const connName = useCallback((id: string | undefined) => (id ? connections.find((c) => c.id === id)?.name : undefined), [connections]);
  const credName = useCallback((id: string | undefined) => (id ? creds.find((c) => c.id === id)?.name : undefined), [creds]);

  const describe = useCallback(
    (e: AuditEntry) => {
      const d = { ...e.details };
      const conn = connName(d.connection);
      const cred = credName(d.credential);
      // `credential.sk_converted { id }` names the converted credential by id.
      const converted = e.event === "credential.sk_converted" ? credName(d.id) : undefined;
      if (converted) {
        delete d.id;
        d.credential = converted;
      }
      if (conn) d.connection = conn;
      if (cred) d.credential = cred;
      return Object.entries(d).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join("   ");
    },
    [connName, credName],
  );

  const filtered = input !== null;
  const error = log.error ?? exportError ?? verifyError;
  const entry = picked === null ? undefined : entries.find((e) => e.seq === picked);
  const set = (patch: Partial<AuditFilter>) => { setFilter((f) => ({ ...f, ...patch })); };
  const label = (code: string) => EVENT_LABEL[code] ?? code;

  const columns = useMemo<DataColumn<AuditEntry>[]>(() => [
    { id: "seq", header: "#", width: "72px", numeric: true, className: "mono text-text-faint", cell: (e) => e.seq, sortValue: (e) => e.seq },
    { id: "at", header: "Time (local)", width: "176px", className: "mono tnum text-text-muted", cell: (e) => <time dateTime={e.at}>{formatTime(e.at)}</time>, sortValue: (e) => e.seq },
    {
      id: "event", header: "Event", width: "30%", sortValue: (e) => EVENT_LABEL[e.event] ?? e.event,
      cell: (e) => <span className="audit-event" data-tone={e.details.decision === "rejected" ? "hot" : undefined}>{EVENT_LABEL[e.event] ?? e.event}</span>,
    },
    { id: "details", header: "Details", className: "mono text-text-muted", cell: (e) => <span title={describe(e)}>{describe(e)}</span> },
  ], [describe]);

  return (
    <section aria-label="Audit log" className="audit-view" data-drawer={entry ? true : undefined}>
      <header className="audit-head">
        <h1 className="t-page whitespace-nowrap">Audit log</h1>
        <VerifyBadge v={verify} />
        <button type="button" className="btn ml-auto flex-none" onClick={refresh}>
          Refresh
        </button>
      </header>
      <div role="group" aria-label="Filters" className="audit-filters">
        <input
          aria-label="Filter audit entries"
          placeholder="Search details: host, credential, reason"
          title="Searches the entry details (never the hidden secret values)"
          maxLength={MAX_FILTER_TEXT}
          className="field audit-filter-text"
          value={filter.text}
          onChange={(e) => { set({ text: e.target.value }); }}
        />
        <select aria-label="Event type" className="field" value={filter.event} onChange={(e) => { set({ event: e.target.value }); }}>
          <option value="">All events</option>
          {withPick(facets.events, filter.event).map((code) => ({ code, text: label(code) })).sort((a, b) => a.text.localeCompare(b.text)).map((o) => (
            <option key={o.code} value={o.code}>{o.text}</option>
          ))}
        </select>
        <select aria-label="Connection" className="field" value={filter.connection} onChange={(e) => { set({ connection: e.target.value }); }}>
          <option value="">All connections</option>
          {withPick(facets.connections, filter.connection).map((id) => ({ id, text: connName(id) ?? id })).sort((a, b) => a.text.localeCompare(b.text)).map((o) => (
            <option key={o.id} value={o.id}>{o.text}</option>
          ))}
        </select>
        <select aria-label="Time" className="field" value={filter.span} onChange={(e) => { set({ span: e.target.value as AuditSpan }); }}>
          {(Object.keys(SPAN_LABEL) as AuditSpan[]).map((s) => <option key={s} value={s}>{SPAN_LABEL[s]}</option>)}
        </select>
        {isFiltered(filter) && (
          <button type="button" className="btn btn-subtle" onClick={() => { setFilter(NO_FILTER); setApplied(NO_FILTER); }}>Clear filters</button>
        )}
        <span className="audit-count tnum" aria-live="polite">{countText(entries.length, filtered, log.cursor.kind !== "none")}</span>
        <AuditExportMenu filter={input} onExported={refresh} onError={setExportError} />
      </div>
      {error && <p role="alert" className="bg-danger-soft px-4 py-1.5 text-danger">{error}</p>}
      <div className="audit-body">
        <DataTable
          label="Entries, newest first"
          className="audit-table"
          columns={columns}
          rows={entries}
          rowKey={(e) => String(e.seq)}
          selected={picked === null ? null : String(picked)}
          onSelect={(k) => { setPicked(Number(k)); }}
          defaultSort={{ column: "seq", dir: "descending" }}
          empty={emptyText(log, filtered)}
          footer={<MoreFooter log={log} />}
        />
        {entry && (
          <AuditDrawer
            entry={entry}
            label={label(entry.event)}
            names={{ connection: connName(entry.details.connection), credential: credName(entry.details.credential), ...(entry.event === "credential.sk_converted" ? { id: credName(entry.details.id) } : {}) }}
            onClose={() => {
              const seq = picked;
              setPicked(null);
              // Back to the row the drawer described.
              queueMicrotask(() => { document.querySelector<HTMLElement>(`.audit-table tr[data-key="${String(seq)}"]`)?.focus(); });
            }}
          />
        )}
      </div>
    </section>
  );
}

function VerifyBadge({ v }: { v: AuditVerify | null }) {
  if (!v) return <span className="chip">checking chain…</span>;
  return v.ok ? (
    <span role="status" className="chip tnum" data-tone="success">
      <span aria-hidden className="state-dot" data-state="connected" /> Chain intact, {v.entries} entries
    </span>
  ) : (
    <span role="status" className="chip" data-tone="danger">
      Chain broken at entry {v.brokenAt ?? "?"}. Entries from there on cannot be trusted.
    </span>
  );
}

/** The current pick stays an option even before a page shows it. */
const withPick = (values: string[], pick: string) => (pick && !values.includes(pick) ? [...values, pick] : values);

function countText(n: number, filtered: boolean, more: boolean): string {
  if (!filtered) return `${n.toLocaleString("en-US")} loaded ${n === 1 ? "entry" : "entries"}`;
  return `${n.toLocaleString("en-US")} ${n === 1 ? "match" : "matches"}${more ? " so far" : ""}`;
}

function emptyText(log: AuditLog, filtered: boolean): string {
  if (log.loading && log.entries.length === 0) return "Loading…";
  if (!filtered) return "No entries yet.";
  return log.cursor.kind === "scan" ? "No match in the entries searched so far." : "No entry matches the filters.";
}

/** "Load older entries" (unfiltered), "Load more" (a full filtered page) or "Continue search" (scan cap). */
function MoreFooter({ log }: { log: AuditLog }) {
  const c = log.cursor;
  if (c.kind === "none") return null;
  const n = c.kind === "scan" ? searchedCount(log.newest, c.before) : null;
  return (
    <div className="flex items-center gap-3 px-4 py-3">
      {c.kind === "scan" && (
        <span className="text-text-muted">
          {n === null ? `Searched back to entry ${String(c.before)}.` : `Searched the newest ${n.toLocaleString("en-US")} entries.`}
        </span>
      )}
      <button type="button" className="btn" disabled={log.loading} onClick={() => void log.more()}>
        {c.kind === "older" ? "Load older entries" : c.kind === "page" ? "Load more" : "Continue search"}
      </button>
    </div>
  );
}

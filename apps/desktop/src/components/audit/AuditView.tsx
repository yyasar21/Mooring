import { useCallback, useEffect, useMemo, useState } from "react";
import { DataTable, type DataColumn } from "@mooring/ui";
import { ipc, type AuditEntry, type AuditVerify } from "../../lib/ipc";
import { errorText } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { useCredentials } from "../../stores/credentials";
import { AuditDrawer } from "./AuditDrawer";
import { NO_FILTER, SPAN_LABEL, auditFacets, filterAudit, isFiltered, type AuditFilter, type AuditSpan } from "./auditFilter";

const PAGE = 200;

export const EVENT_LABEL: Record<string, string> = {
  vault_created: "Vault created",
  vault_unlocked: "Vault unlocked",
  vault_locked: "Vault locked",
  password_changed: "Master password changed",
  credential_used: "Credential used",
  credential_copied: "Secret copied",
  credential_otp_attached: "TOTP seed attached",
  credential_prompted: "Asked for sign-in",
  session_opened: "Session opened",
  session_closed: "Session closed",
  vault_exported: "Vault exported",
  trust_decision: "Host trust decision",
  "vault.lock": "Vault locked",
  "vault.policy_changed": "Auto-lock policy changed",
  "session.forward.open": "Forward opened",
  "session.forward.close": "Forward closed",
  "session.sftp.transfer": "File transfer",
  "audit.syslog_changed": "Syslog mirror changed",
  "app.start": "Application started",
  // ADR-0024: FIDO2 security keys (fingerprint and backend only).
  "credential.sk_converted": "SSH key converted to a security-key credential",
  "session.auth_sk": "Security-key sign-in",
  // ADR-0027: RD Gateway and smart cards (host, auth method and outcome; never a PIN).
  "session.rdp.gateway": "RD Gateway sign-in",
  "session.rdp.gateway_basic": "RD Gateway used Basic authentication",
  "credential.pin_prompted": "Smart card PIN asked",
  // L-50: the bws binary no longer matched its pin and was not run.
  "secret.tool_changed": "bws binary changed: refused until the source is tested",
  // L-48: the web-via proxy refused a destination outside the start host and allowed origins.
  forward_refused: "Web proxy refused a destination outside the allowed origins",
  "portable.acl_unavailable": "Portable data folder: owner-only ACL could not be applied (FAT/exFAT or policy)",
};

/**
 * Audit log viewer: newest first, paged with `before`, chain verification, filters by text, event
 * type, connection and time (L4), and a drawer with the structured fields of the picked row.
 * Export needs a Rust command first (see the W3 handoff); there is no export button until then.
 */
export function AuditView() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [filter, setFilter] = useState<AuditFilter>(NO_FILTER);
  const [picked, setPicked] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [more, setMore] = useState(false);
  const connections = useTree((s) => s.connections);
  const creds = useCredentials((s) => s.items);

  const load = useCallback(async (before: number | null) => {
    try {
      const page = await ipc.auditTail({ limit: PAGE, before });
      setEntries((cur) => (before === null ? page : [...cur, ...page]));
      setMore(page.length === PAGE);
      setError(null);
    } catch (e: unknown) {
      setError(errorText(e));
    }
  }, []);

  const runVerify = useCallback(async () => {
    try {
      setVerify(await ipc.auditVerify());
    } catch (e: unknown) {
      setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    void load(null);
    void runVerify();
  }, [load, runVerify]);

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

  const facets = useMemo(() => auditFacets(entries), [entries]);
  const shown = useMemo(
    () => filterAudit(entries, filter, (e) => [e.event, EVENT_LABEL[e.event] ?? "", describe(e), String(e.seq)]),
    [entries, filter, describe],
  );
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
        <button type="button" className="btn ml-auto flex-none" onClick={() => { void load(null); void runVerify(); }}>
          Refresh
        </button>
      </header>
      <div role="group" aria-label="Filters" className="audit-filters">
        <input
          aria-label="Filter audit entries"
          placeholder="Filter by event, host, credential"
          className="field audit-filter-text"
          value={filter.text}
          onChange={(e) => { set({ text: e.target.value }); }}
        />
        <select aria-label="Event type" className="field" value={filter.event} onChange={(e) => { set({ event: e.target.value }); }}>
          <option value="">All events</option>
          {facets.events.map((code) => ({ code, text: label(code) })).sort((a, b) => a.text.localeCompare(b.text)).map((o) => (
            <option key={o.code} value={o.code}>{o.text}</option>
          ))}
        </select>
        <select aria-label="Connection" className="field" value={filter.connection} onChange={(e) => { set({ connection: e.target.value }); }}>
          <option value="">All connections</option>
          {facets.connections.map((id) => ({ id, text: connName(id) ?? id })).sort((a, b) => a.text.localeCompare(b.text)).map((o) => (
            <option key={o.id} value={o.id}>{o.text}</option>
          ))}
        </select>
        <select aria-label="Time" className="field" value={filter.span} onChange={(e) => { set({ span: e.target.value as AuditSpan }); }}>
          {(Object.keys(SPAN_LABEL) as AuditSpan[]).map((s) => <option key={s} value={s}>{SPAN_LABEL[s]}</option>)}
        </select>
        {isFiltered(filter) && (
          <button type="button" className="btn btn-subtle" onClick={() => { setFilter(NO_FILTER); }}>Clear filters</button>
        )}
        <span className="audit-count tnum" aria-live="polite">{shown.length} of {entries.length} loaded entries</span>
      </div>
      {error && <p role="alert" className="bg-danger-soft px-4 py-1.5 text-danger">{error}</p>}
      <div className="audit-body">
        <DataTable
          label="Entries, newest first"
          className="audit-table"
          columns={columns}
          rows={shown}
          rowKey={(e) => String(e.seq)}
          selected={picked === null ? null : String(picked)}
          onSelect={(k) => { setPicked(Number(k)); }}
          defaultSort={{ column: "seq", dir: "descending" }}
          empty={isFiltered(filter) ? "No entry matches the filters." : "No entries yet."}
          footer={more && (
            <div className="px-4 py-3">
              <button type="button" className="btn" onClick={() => void load(entries.at(-1)?.seq ?? null)}>
                Load older entries
              </button>
            </div>
          )}
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

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

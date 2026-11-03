import { useCallback, useEffect, useMemo, useState } from "react";
import { ipc, type AuditEntry, type AuditVerify } from "../../lib/ipc";
import { errorText } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";

const PAGE = 200;

const EVENT_LABEL: Record<string, string> = {
  vault_created: "Vault created",
  vault_unlocked: "Vault unlocked",
  vault_locked: "Vault locked",
  password_changed: "Master password changed",
  credential_used: "Credential used",
  session_opened: "Session opened",
  session_closed: "Session closed",
  vault_exported: "Vault exported",
  trust_decision: "Host trust decision",
};

/** Audit log viewer: newest first, paged with `before`, client-side filter, chain verification. */
export function AuditView() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [more, setMore] = useState(false);
  const setView = useUi((s) => s.setView);
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

  const describe = useCallback(
    (e: AuditEntry) => {
      const d = { ...e.details };
      const conn = d.connection ? connections.find((c) => c.id === d.connection)?.name : undefined;
      const cred = d.credential ? creds.find((c) => c.id === d.credential)?.name : undefined;
      if (conn) d.connection = conn;
      if (cred) d.credential = cred;
      return Object.entries(d).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join("   ");
    },
    [connections, creds],
  );

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter((e) =>
      [e.event, EVENT_LABEL[e.event] ?? "", describe(e), String(e.seq)].some((s) => s.toLowerCase().includes(q)),
    );
  }, [entries, filter, describe]);

  return (
    <section aria-label="Audit log" className="flex h-full min-w-0 flex-col bg-bg">
      <header className="flex h-[var(--bar-h)] flex-none items-center gap-3 border-b border-line bg-bg-sunken px-4">
        <h1 className="whitespace-nowrap font-medium">Audit log</h1>
        <VerifyBadge v={verify} />
        <input
          aria-label="Filter audit entries"
          placeholder="Filter by event, host, credential"
          className="field ml-auto h-[26px] w-[240px] min-w-[120px] shrink"
          value={filter}
          onChange={(e) => { setFilter(e.target.value); }}
        />
        <button type="button" className="btn flex-none" onClick={() => { void load(null); void runVerify(); }}>
          Refresh
        </button>
        <button type="button" className="btn btn-ghost flex-none" onClick={() => { setView("workspace"); }}>
          Back to sessions
        </button>
      </header>
      {error && <p role="alert" className="bg-danger-soft px-4 py-1.5 text-danger">{error}</p>}
      <div className="audit-row border-b border-line text-[length:var(--fs-xs)] text-text-faint" aria-hidden>
        <span className="text-right">#</span>
        <span>Time (local)</span>
        <span>Event</span>
        <span>Details</span>
      </div>
      <ol aria-label="Entries, newest first" className="min-h-0 flex-1 overflow-y-auto pb-6">
        {shown.map((e) => (
          <li key={e.seq} className="audit-row">
            <span className="mono tnum text-right text-text-faint">{e.seq}</span>
            <time className="mono tnum text-text-muted" dateTime={e.at}>{formatTime(e.at)}</time>
            <span className={e.details.decision === "rejected" ? "text-danger" : ""}>{EVENT_LABEL[e.event] ?? e.event}</span>
            <span className="mono truncate text-text-muted select-text" title={describe(e)}>{describe(e)}</span>
          </li>
        ))}
        {shown.length === 0 && <li className="px-4 py-8 text-center text-text-faint">{filter ? "No entry matches the filter." : "No entries yet."}</li>}
        {more && (
          <li className="px-4 pt-3">
            <button type="button" className="btn" onClick={() => void load(entries.at(-1)?.seq ?? null)}>
              Load older entries
            </button>
          </li>
        )}
      </ol>
    </section>
  );
}

function VerifyBadge({ v }: { v: AuditVerify | null }) {
  if (!v) return <span className="text-[length:var(--fs-xs)] text-text-faint">checking chain…</span>;
  return v.ok ? (
    <span role="status" className="inline-flex items-center gap-1.5 whitespace-nowrap text-[length:var(--fs-xs)] text-text-muted">
      <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-ok" /> Chain intact, {v.entries} entries
    </span>
  ) : (
    <span role="status" className="inline-flex items-center gap-1.5 rounded-[var(--radius-s)] bg-danger-soft px-2 py-0.5 text-[length:var(--fs-xs)] text-danger">
      Chain broken at entry {v.brokenAt ?? "?"}. Entries from there on cannot be trusted.
    </span>
  );
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

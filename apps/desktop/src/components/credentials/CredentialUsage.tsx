import { useEffect, useState } from "react";
import { DataTable, Icon, ProtocolIcon, type DataColumn } from "@mooring/ui";
import { ipc, type AuditEntry, type ConnectionSummary, type CredentialMeta, type Folder } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { folderPath, useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { EVENT_LABEL, formatTime } from "../audit/AuditView";

/** The roles a connection can give a credential, in the words of the connection dialog. */
function rolesOf(c: ConnectionSummary, id: string): string[] {
  const out: string[] = [];
  if (c.credentialId === id) out.push("Sign-in");
  else if (c.credentialId === null && c.effectiveCredentialId === id) out.push("Sign-in (folder default)");
  if (c.gatewayCredentialId === id) out.push("RD Gateway");
  if (c.becomeCredentialId === id) out.push("Become");
  if (c.certificateCredentialId === id) out.push("Certificate");
  return out;
}

/** Connections and folders that point at this credential (the explicit references `usedByCount` counts). */
export function usage(meta: CredentialMeta, connections: ConnectionSummary[], folders: Folder[]) {
  const conns = connections.filter((c) => c.credentialId === meta.id || c.gatewayCredentialId === meta.id || c.becomeCredentialId === meta.id || c.certificateCredentialId === meta.id);
  const defaults = folders.filter((f) => f.defaultCredentialId === meta.id);
  return { conns, defaults };
}

/** Select a connection or folder in Hosts (the tree and its details). */
function reveal(sel: { kind: "connection" | "folder"; id: string }) {
  useUi.getState().setView("workspace");
  useTree.getState().select(sel);
}

/** L2 "Used by" tab: every connection and folder default that references the credential. */
export function UsedByPanel({ meta }: { meta: CredentialMeta }) {
  const connections = useTree((s) => s.connections);
  const folders = useTree((s) => s.folders);
  const { conns, defaults } = usage(meta, connections, folders);
  if (conns.length + defaults.length === 0) {
    return <p className="cred-tab-empty">No connection or folder uses this credential. Pick it in a connection's Sign-in section or as a folder default.</p>;
  }
  return (
    <ul className="cred-usedby" aria-label="Used by">
      {conns.map((c) => (
        <li key={c.id}>
          <ProtocolIcon protocol={c.protocol} />
          <button type="button" className="cred-link" onClick={() => { reveal({ kind: "connection", id: c.id }); }}>{c.name}</button>
          <span className="cred-usedby-role">{rolesOf(c, meta.id).join(", ")}</span>
          <span className="cred-usedby-path">{folderPath(folders, c.folderId).join(" / ") || "Top level"}</span>
        </li>
      ))}
      {defaults.map((f) => (
        <li key={f.id}>
          <span className="m-proto" aria-hidden><Icon name="folder" /></span>
          <button type="button" className="cred-link" onClick={() => { reveal({ kind: "folder", id: f.id }); }}>{f.name}</button>
          <span className="cred-usedby-role">Folder default</span>
          <span className="cred-usedby-path">{folderPath(folders, f.parentId).join(" / ") || "Top level"}</span>
        </li>
      ))}
    </ul>
  );
}

/** Whether an audit row is about this credential (by id; `credential.sk_converted` names it as `id`). */
export function aboutCredential(e: AuditEntry, id: string): boolean {
  return e.details.credential === id || (e.event === "credential.sk_converted" && e.details.id === id);
}

/** L2 "Audit" tab: the latest audit rows that name this credential (from `audit_tail`, read-only). */
export function CredentialAuditPanel({ meta }: { meta: CredentialMeta }) {
  const connections = useTree((s) => s.connections);
  const [rows, setRows] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    ipc.auditTail({ limit: 500, before: null }).then(
      (page) => { if (live) setRows(page.filter((e) => aboutCredential(e, meta.id))); },
      (e: unknown) => { if (live) setError(describeError(e)); },
    );
    return () => { live = false; };
  }, [meta.id]);
  const columns: DataColumn<AuditEntry>[] = [
    { id: "at", header: "Time (local)", width: "152px", className: "mono tnum text-text-muted", cell: (e) => <time dateTime={e.at}>{formatTime(e.at)}</time>, sortValue: (e) => e.seq },
    { id: "event", header: "Event", cell: (e) => EVENT_LABEL[e.event] ?? e.event, sortValue: (e) => EVENT_LABEL[e.event] ?? e.event },
    {
      id: "conn", header: "Connection", className: "text-text-muted",
      cell: (e) => connections.find((c) => c.id === e.details.connection)?.name ?? e.details.connection ?? "—",
    },
  ];
  if (error) return <p role="alert" className="cred-tab-empty text-danger">{error}</p>;
  if (rows === null) return <p className="cred-tab-empty">Reading the audit log…</p>;
  return (
    <>
      <DataTable
        label="Audit entries for this credential"
        className="cred-audit"
        columns={columns}
        rows={rows}
        rowKey={(e) => String(e.seq)}
        defaultSort={{ column: "at", dir: "descending" }}
        empty="The last 500 audit entries do not mention this credential."
      />
      <p className="field-hint px-5 pb-4">From the last 500 audit entries. The audit log has the full history.</p>
    </>
  );
}

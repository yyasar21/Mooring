import type { ReactNode } from "react";
import { ProtocolPip, StateDot } from "@nexus/ui";
import type { ConnectionSummary, CredentialMeta, Folder } from "../../lib/ipc";
import { folderPath, useTree } from "../../stores/tree";
import { KIND_LABEL, useCredentials } from "../../stores/credentials";
import { useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { CopyPassword } from "./CopyPassword";

/** Right pane: properties of the selected node. Credentials show as a reference, never a value. */
export function Inspector() {
  const selected = useTree((s) => s.selected);
  const connection = useTree((s) => (selected?.kind === "connection" ? s.connections.find((c) => c.id === selected.id) : undefined));
  const folder = useTree((s) => (selected?.kind === "folder" ? s.folders.find((f) => f.id === selected.id) : undefined));

  return (
    <aside aria-label="Details" className="flex h-full min-w-0 flex-col overflow-y-auto bg-bg-sunken">
      <div className="flex h-[var(--bar-h)] flex-none items-center border-b border-line px-3.5 text-[length:var(--fs-xs)] font-medium text-text-muted">
        Details
      </div>
      {connection ? (
        <ConnectionDetails c={connection} />
      ) : folder ? (
        <FolderDetails f={folder} />
      ) : (
        <p className="p-4 text-text-faint">Select a connection or folder to see its details.</p>
      )}
    </aside>
  );
}

function ConnectionDetails({ c }: { c: ConnectionSummary }) {
  const folders = useTree((s) => s.folders);
  const cred = useCredentials((s) => s.items.find((x) => x.id === c.effectiveCredentialId));
  const tab = useSessions((s) => s.tabs.find((t) => t.connectionId === c.id));
  const openDialog = useUi((s) => s.openDialog);
  const path = folderPath(folders, c.folderId);
  const inherited = c.credentialId === null && c.effectiveCredentialId !== null;
  const source = inherited ? inheritedFrom(folders, c.folderId) : null;

  return (
    <div>
      <header className="flex items-start gap-2 px-3.5 pt-3.5">
        <ProtocolPip protocol={c.protocol} />
        <div className="min-w-0 flex-1">
          <h2 className="truncate text-[length:var(--fs-l)] font-medium leading-tight">{c.name}</h2>
          <p className="truncate text-[length:var(--fs-xs)] text-text-faint">{path.join(" / ") || "Top level"}</p>
        </div>
      </header>
      <div className="flex gap-2 px-3.5 pt-3">
        <button type="button" className="btn btn-primary" onClick={() => void useSessions.getState().open(c.id)}>
          {tab ? "Go to session" : "Connect"}
        </button>
        <button type="button" className="btn" onClick={() => { openDialog({ kind: "connection", id: c.id, folderId: c.folderId }); }}>
          Edit
        </button>
      </div>

      <h3 className="section-title">Connection</h3>
      <dl className="prop-grid px-3.5">
        <Prop k="Host" mono>{c.host}</Prop>
        <Prop k="Port" mono>{c.port ?? "default"}</Prop>
        <Prop k="Protocol">{c.protocol.toUpperCase()}</Prop>
        <Prop k="Tags">{c.tags.length ? c.tags.join(", ") : <span className="text-text-faint">none</span>}</Prop>
        {tab && (
          <Prop k="Session">
            <span className="inline-flex items-center gap-1.5">
              <StateDot state={tab.state} /> {tab.prompt ? "waiting for you" : tab.state}
            </span>
          </Prop>
        )}
        {tab?.peerIdentity && <Prop k="Host key" mono>{tab.peerIdentity}</Prop>}
      </dl>

      <h3 className="section-title">Credential</h3>
      <CredentialRef cred={cred} inheritedFrom={source} />
      <p className="px-3.5 pt-3 text-[length:var(--fs-xs)] leading-snug text-text-faint">
        Copying writes an audit entry. Mooring clears the clipboard after 30 seconds.
      </p>
    </div>
  );
}

function FolderDetails({ f }: { f: Folder }) {
  const folders = useTree((s) => s.folders);
  const count = useTree((s) => s.connections.filter((c) => c.folderId === f.id).length);
  const cred = useCredentials((s) => s.items.find((x) => x.id === f.defaultCredentialId));
  const openDialog = useUi((s) => s.openDialog);
  const isRoot = f.parentId === null;

  return (
    <div>
      <header className="px-3.5 pt-3.5">
        <h2 className="truncate text-[length:var(--fs-l)] font-medium leading-tight">{f.name}</h2>
        <p className="truncate text-[length:var(--fs-xs)] text-text-faint">{folderPath(folders, f.parentId).join(" / ") || "Top level"}</p>
      </header>
      <div className="flex flex-wrap gap-2 px-3.5 pt-3">
        <button type="button" className="btn" onClick={() => { openDialog({ kind: "connection", folderId: f.id }); }}>
          New connection
        </button>
        {!isRoot && (
          <button type="button" className="btn" onClick={() => { openDialog({ kind: "folder", id: f.id, parentId: f.parentId ?? "" }); }}>
            Edit
          </button>
        )}
      </div>
      <h3 className="section-title">Folder</h3>
      <dl className="prop-grid px-3.5">
        <Prop k="Connections">{count}</Prop>
      </dl>
      <h3 className="section-title">Default credential</h3>
      <CredentialRef cred={cred} inheritedFrom={null} />
    </div>
  );
}

function CredentialRef({ cred, inheritedFrom: from }: { cred: CredentialMeta | undefined; inheritedFrom: string | null }) {
  if (!cred) return <p className="px-3.5 text-text-faint">None. The session will ask when it connects.</p>;
  return (
    <div className="mx-3.5 rounded-[var(--radius-s)] border border-line bg-bg px-3 py-2.5">
      <dl className="prop-grid">
        <Prop k="Name">{cred.name}</Prop>
        <Prop k="Kind">{KIND_LABEL[cred.kind]}</Prop>
        <Prop k="Username" mono>{cred.username || "none"}</Prop>
        {from && <Prop k="From">folder {from}</Prop>}
      </dl>
      {cred.kind === "password" && (
        <div className="pt-2.5">
          <CopyPassword credentialId={cred.id} />
        </div>
      )}
    </div>
  );
}

function Prop({ k, mono, children }: { k: string; mono?: boolean; children: ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd className={mono ? "mono select-text" : ""}>{children}</dd>
    </>
  );
}

function inheritedFrom(folders: Folder[], folderId: string): string | null {
  let cur = folders.find((f) => f.id === folderId);
  while (cur) {
    if (cur.defaultCredentialId) return cur.name;
    const p = cur.parentId;
    cur = folders.find((f) => f.id === p);
  }
  return null;
}

import type { ReactNode } from "react";
import { HudLabel, ProtocolPip, StateDot } from "@mooring/ui";
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
    <aside aria-label="Details" className="deck-pane flex h-full flex-col overflow-y-auto">
      <div className="deck-head">
        <span className="m-micro flex-1">Details</span>
        {selected && <span className="m-micro tnum">{selected.kind === "folder" ? "Folder" : "Host"}</span>}
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
      <header className="m-hud mx-3.5 mt-3.5 px-3 pb-3 pt-2.5" data-active={tab?.state === "connected" ? true : undefined}>
        <div className="flex items-center gap-2">
          <ProtocolPip protocol={c.protocol} live={tab?.state === "connected"} />
          <p className="m-micro min-w-0 flex-1 truncate">{path.join(" / ") || "Top level"}</p>
        </div>
        <h2 className="readout-title mt-2 truncate">{c.name}</h2>
        <p className="readout-host mt-1 truncate select-text">
          {c.host}
          {c.port !== null && <span className="text-text-faint">:{c.port}</span>}
        </p>
      </header>
      <div className="flex gap-2 px-3.5 pt-3">
        <button type="button" className="btn btn-primary" onClick={() => void useSessions.getState().open(c.id)}>
          {tab ? "Go to session" : "Connect"}
        </button>
        <button type="button" className="btn" onClick={() => { openDialog({ kind: "connection", id: c.id, folderId: c.folderId }); }}>
          Edit
        </button>
      </div>

      <section className="readout-section">
        <HudLabel>Connection</HudLabel>
        <dl className="prop-grid">
          <Prop k="Host" mono>{c.host}</Prop>
          <Prop k="Port" mono>{c.port ?? "default"}</Prop>
          <Prop k="Protocol">{c.protocol.toUpperCase()}</Prop>
          <Prop k="Tags">{c.tags.length ? c.tags.join(", ") : <span className="text-text-faint">none</span>}</Prop>
          {tab && (
            <Prop k="Session">
              <span className="inline-flex items-center gap-2" style={{ color: tab.prompt ? "var(--hot)" : undefined }}>
                <StateDot state={tab.state} /> {tab.prompt ? "waiting for you" : tab.state}
              </span>
            </Prop>
          )}
          {tab?.peerIdentity && <Prop k="Host key" mono>{tab.peerIdentity}</Prop>}
        </dl>
      </section>

      <section className="readout-section">
        <HudLabel>Credential</HudLabel>
        <CredentialRef cred={cred} inheritedFrom={source} />
      </section>
      <p className="px-3.5 pb-4 pt-3 text-[length:var(--fs-xs)] leading-snug text-text-faint">
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
      <header className="m-hud mx-3.5 mt-3.5 px-3 pb-3 pt-2.5">
        <p className="m-micro truncate">{folderPath(folders, f.parentId).join(" / ") || "Top level"}</p>
        <h2 className="readout-title mt-2 truncate">{f.name}</h2>
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
      <section className="readout-section">
        <HudLabel>Folder</HudLabel>
        <dl className="prop-grid">
          <Prop k="Hosts"><span className="tnum">{count}</span></Prop>
        </dl>
      </section>
      <section className="readout-section">
        <HudLabel>Default credential</HudLabel>
        <CredentialRef cred={cred} inheritedFrom={null} />
      </section>
    </div>
  );
}

function CredentialRef({ cred, inheritedFrom: from }: { cred: CredentialMeta | undefined; inheritedFrom: string | null }) {
  if (!cred) return <p className="text-text-faint">None. The session will ask when it connects.</p>;
  return (
    <div className="cred-card m-hud">
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

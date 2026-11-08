import { useState, type ReactNode } from "react";
import { HudLabel, ProtocolPip, StateDot } from "@mooring/ui";
import type { ConnectionSummary, Folder } from "../../lib/ipc";
import { folderPath, useTree, viaNames } from "../../stores/tree";
import { lineState, useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { ConnectionCredentials, FolderCredential } from "./CredentialReadout";
import { hasNetworkCard, NetworkCard } from "./NetworkCard";
import { ImportWizard } from "../vsphere/ImportWizard";
import { SyncPanel } from "../vsphere/SyncPanel";
import { VmPanel } from "../vsphere/VmPanel";
import { SyncBadge } from "../vsphere/SyncBadge";
import { isSyncedVm, isVcenter, READONLY_REASON, sourceName, syncedRootOf } from "../vsphere/vsphere";

/** Right pane: properties of the selected node. Credentials show as a reference, never a value. */
export function Inspector() {
  const selected = useTree((s) => s.selected);
  const connection = useTree((s) => (selected?.kind === "connection" ? s.connections.find((c) => c.id === selected.id) : undefined));
  const folder = useTree((s) => (selected?.kind === "folder" ? s.folders.find((f) => f.id === selected.id) : undefined));

  return (
    <aside aria-label="Details" className="deck-pane flex h-full flex-col overflow-y-auto">
      <div className="deck-head">
        <span className="m-micro flex-1">Details</span>
        {selected && <span className="m-micro tnum">{selected.kind === "folder" ? "Folder" : connection && isSyncedVm(connection) ? "VM" : "Host"}</span>}
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
  const connections = useTree((s) => s.connections);
  const tab = useSessions((s) => s.tabs.find((t) => t.connectionId === c.id));
  const openDialog = useUi((s) => s.openDialog);
  const [wizard, setWizard] = useState(false);
  const path = folderPath(folders, c.folderId);
  const inherited = c.credentialId === null && c.effectiveCredentialId !== null;
  const source = inherited ? inheritedFrom(folders, c.folderId) : null;
  const vcenter = isVcenter(c);
  const synced = vcenter && syncedRootOf(folders, c.id) !== undefined;
  const vm = isSyncedVm(c);

  return (
    <div>
      <header className="m-hud mx-3.5 mt-3.5 px-3 pb-3 pt-2.5" data-active={tab?.state === "connected" ? true : undefined}>
        <div className="flex items-center gap-2">
          <ProtocolPip protocol={c.protocol} live={tab?.state === "connected"} />
          <p className="m-micro min-w-0 flex-1 truncate">{path.join(" / ") || "Top level"}</p>
          {vm && <SyncBadge source={sourceName(connections, c.syncSource)} missing={c.syncState === "missing"} />}
        </div>
        <h2 className="readout-title mt-2 truncate">{c.name}</h2>
        <p className="readout-host mt-1 truncate select-text">
          {c.host}
          {c.port !== null && <span className="text-text-faint">:{c.port}</span>}
        </p>
      </header>
      <div className="flex flex-wrap gap-2 px-3.5 pt-3">
        {!vm && !vcenter && (
          <button type="button" className="btn btn-primary" onClick={() => void useSessions.getState().open(c.id)}>
            {tab ? "Go to session" : "Connect"}
          </button>
        )}
        <button
          type="button"
          className="btn"
          title={vm ? "Credential, tags, overrides and options are yours; name, host and folder come from vCenter" : undefined}
          onClick={() => { openDialog({ kind: "connection", id: c.id, folderId: c.folderId }); }}
        >
          {vm ? "Edit overlays" : "Edit"}
        </button>
        {vcenter && !synced && (
          <button type="button" className="btn" onClick={() => { setWizard(true); }}>Import inventory…</button>
        )}
      </div>
      {wizard && <ImportWizard connection={c} onClose={() => { setWizard(false); }} />}

      {vm && <VmPanel vm={c} />}
      {synced && <SyncPanel vcenter={c} />}

      <section className="readout-section">
        <HudLabel>Connection</HudLabel>
        <dl className="prop-grid">
          <Prop k="Host" mono>{c.host}</Prop>
          <Prop k="Port" mono>{c.port ?? "default"}</Prop>
          <Prop k="Protocol">{c.protocol.toUpperCase()}</Prop>
          {viaNames(connections, c) && <Prop k="Connect via">{viaNames(connections, c)}</Prop>}
          <Prop k="Tags">{c.tags.length ? c.tags.join(", ") : <span className="text-text-faint">none</span>}</Prop>
          {vm && <Prop k="Synced from">{sourceName(connections, c.syncSource)}</Prop>}
          {tab && (
            <Prop k="Session">
              <span className="inline-flex items-center gap-2" style={{ color: tab.prompt ? "var(--warning)" : undefined }}>
                <StateDot {...(tab.prompt ? { tone: "wait" as const } : { state: lineState(tab.state) })} /> {tab.prompt ? "waiting for you" : tab.state}
              </span>
            </Prop>
          )}
          {tab?.peerIdentity && <Prop k="Host key" mono>{tab.peerIdentity}</Prop>}
        </dl>
      </section>

      <section className="readout-section">
        <HudLabel>Credential</HudLabel>
        <ConnectionCredentials c={c} inheritedFrom={source} />
      </section>
      <p className="px-3.5 pb-1 pt-3 text-[length:var(--fs-xs)] leading-snug text-text-faint">
        Copying writes an audit entry. Mooring clears the clipboard after 30 seconds.
      </p>
      {hasNetworkCard(c) && <NetworkCard key={c.id} c={c} />}
    </div>
  );
}

function FolderDetails({ f }: { f: Folder }) {
  const folders = useTree((s) => s.folders);
  const connections = useTree((s) => s.connections);
  const count = useTree((s) => s.connections.filter((c) => c.folderId === f.id).length);
  const openDialog = useUi((s) => s.openDialog);
  const isRoot = f.parentId === null;
  const synced = !!f.syncSource;
  const vcenter = synced ? connections.find((c) => c.id === f.syncSource) : undefined;
  const missing = synced ? connections.filter((c) => c.syncSource === f.syncSource && c.syncState === "missing").length : 0;

  return (
    <div>
      <header className="m-hud mx-3.5 mt-3.5 px-3 pb-3 pt-2.5">
        <div className="flex items-center gap-2">
          <p className="m-micro min-w-0 flex-1 truncate">{folderPath(folders, f.parentId).join(" / ") || "Top level"}</p>
          {synced && <SyncBadge source={vcenter?.name ?? "vCenter"} />}
        </div>
        <h2 className="readout-title mt-2 truncate">{f.name}</h2>
      </header>
      <div className="flex flex-wrap gap-2 px-3.5 pt-3">
        <button type="button" className="btn" disabled={synced} title={synced ? READONLY_REASON : undefined} onClick={() => { openDialog({ kind: "connection", folderId: f.id }); }}>
          New connection
        </button>
        {!isRoot && (
          <button
            type="button"
            className="btn"
            title={synced ? "Only the default credential can be changed here" : undefined}
            onClick={() => { openDialog({ kind: "folder", id: f.id, parentId: f.parentId ?? "" }); }}
          >
            {synced ? "Default credential…" : "Edit"}
          </button>
        )}
        {vcenter && !f.externalId && (
          <button type="button" className="btn" onClick={() => { useTree.getState().select({ kind: "connection", id: vcenter.id }); }}>
            Go to vCenter
          </button>
        )}
      </div>
      {synced && (
        <section className="readout-section">
          <HudLabel>Synced from vCenter</HudLabel>
          <dl className="prop-grid">
            <Prop k="Source">{vcenter?.name ?? "vCenter"}</Prop>
            {f.externalId && <Prop k="vCenter id" mono>{f.externalId}</Prop>}
            {!f.externalId && <Prop k="Missing VMs"><span className={missing ? "text-danger tnum" : "text-text-faint tnum"}>{missing}</span></Prop>}
          </dl>
          <p className="field-hint mt-2">{READONLY_REASON} The default credential below is yours and survives refreshes.</p>
        </section>
      )}
      {vcenter && !f.externalId && <SyncPanel vcenter={vcenter} />}
      <section className="readout-section">
        <HudLabel>Folder</HudLabel>
        <dl className="prop-grid">
          <Prop k={synced ? "VMs" : "Hosts"}><span className="tnum">{count}</span></Prop>
        </dl>
      </section>
      <section className="readout-section">
        <HudLabel>Default credential</HudLabel>
        <FolderCredential id={f.defaultCredentialId} />
      </section>
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

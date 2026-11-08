import { Icon, Kbd, PROTOCOL_LABEL } from "@mooring/ui";
import type { ConnectionSummary } from "../lib/ipc";
import { useCredentials } from "../stores/credentials";
import { useSessions } from "../stores/sessions";
import { folderPath, useTree, viaNames } from "../stores/tree";
import { useUi } from "../stores/ui";
import { hostLabel } from "./SessionHeader";
import { isSyncedVm, isVcenter } from "./vsphere/vsphere";

const ICON = { ssh: "ssh", rdp: "rdp", vnc: "vnc", web: "web", kubernetes: "kubernetes", "vsphere-console": "vsphere" } as const;

/** A row that opens a session from the workspace (a vCenter or a synced VM uses its own panels). */
export const hasReadyPage = (c: ConnectionSummary | undefined): c is ConnectionSummary => !!c && !isVcenter(c) && !isSyncedVm(c);

/**
 * L5: the "ready to connect" page for a selected connection with no session yet: its key facts
 * (protocol, address, folder, who signs in, the route) and a primary Connect. Shown where the
 * empty workspace would be. The region is named after the connection, so its Connect does not
 * collide with the inspector's.
 */
export function ReadyPage({ c }: { c: ConnectionSummary }) {
  const folders = useTree((s) => s.folders);
  const connections = useTree((s) => s.connections);
  const cred = useCredentials((s) => s.items.find((x) => x.id === c.effectiveCredentialId));
  const route = viaNames(connections, c);
  const path = folderPath(folders, c.folderId).join(" / ") || "Top level";
  const signIn = cred ? `${cred.name}${c.credentialId === null ? " (folder default)" : ""}` : "Asks at connect";
  const connect = () => void useSessions.getState().open(c.id);

  return (
    <div className="panel-note">
      <section aria-label={`${c.name}, ready to connect`} className="ready-page">
        <span className="ready-icon" aria-hidden><Icon name={ICON[c.protocol]} size={24} /></span>
        <h2 className="ready-title">{c.name}</h2>
        <p className="ready-host mono select-text">{hostLabel(c)}</p>
        <dl className="ready-facts">
          <dt>Protocol</dt><dd>{PROTOCOL_LABEL[c.protocol]}</dd>
          <dt>Folder</dt><dd>{path}</dd>
          <dt>Sign-in</dt><dd>{signIn}</dd>
          {route && <><dt>Connect via</dt><dd>{route}</dd></>}
          {c.tags.length > 0 && <><dt>Tags</dt><dd>{c.tags.join(", ")}</dd></>}
        </dl>
        <div className="ready-actions">
          <button type="button" className="btn btn-primary btn-lg" onClick={connect}>Connect</button>
          <button type="button" className="btn btn-lg" onClick={() => { useUi.getState().openDialog({ kind: "connection", id: c.id, folderId: c.folderId }); }}>
            Edit connection
          </button>
        </div>
        <p className="ready-hint">Double-click it in the tree to connect, or press <Kbd>mod K</Kbd> to open another.</p>
      </section>
    </div>
  );
}

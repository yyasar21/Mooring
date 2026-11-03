import { useState } from "react";
import type { Protocol } from "../../lib/ipc";
import { folderPath, useTree } from "../../stores/tree";
import { useCredentials } from "../../stores/credentials";
import { useSessions } from "../../stores/sessions";
import { DialogFooter, Modal } from "./Modal";

const PROTOCOLS: { value: Protocol; label: string; port: number | null }[] = [
  { value: "ssh", label: "SSH", port: 22 },
  { value: "rdp", label: "RDP", port: 3389 },
  { value: "vnc", label: "VNC", port: 5900 },
  { value: "web", label: "Web", port: 443 },
  { value: "kubernetes", label: "Kubernetes", port: null },
  { value: "vsphere-console", label: "vSphere console", port: null },
];

/** Create or edit a connection. The credential is chosen by reference; secrets never appear here. */
export function ConnectionDialog({ id, folderId, onClose }: { id?: string; folderId: string; onClose: () => void }) {
  const existing = useTree((s) => s.connections.find((c) => c.id === id));
  const folders = useTree((s) => s.folders);
  const creds = useCredentials((s) => s.items);
  const [name, setName] = useState(existing?.name ?? "");
  const [protocol, setProtocol] = useState<Protocol>(existing?.protocol ?? "ssh");
  const [host, setHost] = useState(existing?.host ?? "");
  const [port, setPort] = useState(existing?.port?.toString() ?? "");
  const [folder, setFolder] = useState(existing?.folderId ?? folderId);
  const [cred, setCred] = useState(existing?.credentialId ?? "");
  const [tags, setTags] = useState(existing?.tags.join(" ") ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const portNum = port.trim() === "" ? null : Number(port);
  const portBad = portNum !== null && (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535);
  const valid = name.trim() !== "" && host.trim() !== "" && !portBad;
  const defaultPort = PROTOCOLS.find((p) => p.value === protocol)?.port;

  async function submit() {
    setBusy(true);
    const fields = {
      folderId: folder,
      name: name.trim(),
      protocol,
      host: host.trim(),
      port: portNum,
      credentialId: cred || null,
      tags: tags.split(/[\s,]+/).filter(Boolean),
    };
    const t = useTree.getState();
    const saved = existing ? await t.updateConnection(existing.id, fields) : await t.createConnection(fields);
    setBusy(false);
    if (saved) {
      t.select({ kind: "connection", id: saved.id });
      onClose();
    } else setError(useTree.getState().error ?? "could not save the connection");
  }

  async function remove() {
    if (!existing) return;
    setBusy(true);
    for (const tab of useSessions.getState().tabs.filter((x) => x.connectionId === existing.id)) {
      await useSessions.getState().close(tab.id);
    }
    const ok = await useTree.getState().deleteConnection(existing.id);
    setBusy(false);
    if (ok) onClose();
    else setError(useTree.getState().error ?? "could not delete the connection");
  }

  return (
    <Modal title={existing ? "Edit connection" : "New connection"} onClose={onClose} width={500}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) void submit();
        }}
      >
        <div className="grid grid-cols-[1fr_120px] gap-3 px-4 py-4">
          <div className="col-span-2">
            <label className="field-label" htmlFor="conn-name">Name</label>
            <input id="conn-name" className="field" value={name} maxLength={200} onChange={(e) => { setName(e.target.value); }} />
          </div>
          <div>
            <label className="field-label" htmlFor="conn-host">Host</label>
            <input
              id="conn-host"
              className="field mono"
              spellCheck={false}
              placeholder="server.example.test"
              value={host}
              onChange={(e) => { setHost(e.target.value); }}
            />
          </div>
          <div>
            <label className="field-label" htmlFor="conn-port">Port</label>
            <input
              id="conn-port"
              className="field mono"
              inputMode="numeric"
              placeholder={defaultPort?.toString() ?? "none"}
              aria-invalid={portBad}
              value={port}
              onChange={(e) => { setPort(e.target.value); }}
            />
          </div>
          <div>
            <label className="field-label" htmlFor="conn-proto">Protocol</label>
            <select id="conn-proto" className="field" value={protocol} onChange={(e) => { setProtocol(e.target.value as Protocol); }}>
              {PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
          </div>
          <div>
            <label className="field-label" htmlFor="conn-folder">Folder</label>
            <select id="conn-folder" className="field" value={folder} onChange={(e) => { setFolder(e.target.value); }}>
              {folders.map((f) => (
                <option key={f.id} value={f.id}>{folderPath(folders, f.id).join(" / ") || f.name}</option>
              ))}
            </select>
          </div>
          <div className="col-span-2">
            <label className="field-label" htmlFor="conn-cred">Credential</label>
            <select id="conn-cred" className="field" value={cred} onChange={(e) => { setCred(e.target.value); }}>
              <option value="">Inherit from folder</option>
              {creds.map((c) => <option key={c.id} value={c.id}>{c.name} · {c.username || c.kind}</option>)}
            </select>
          </div>
          <div className="col-span-2">
            <label className="field-label" htmlFor="conn-tags">Tags</label>
            <input
              id="conn-tags"
              className="field"
              placeholder="space or comma separated"
              value={tags}
              onChange={(e) => { setTags(e.target.value); }}
            />
          </div>
        </div>
        <DialogFooter error={portBad ? "Port must be 1 to 65535." : error}>
          {existing && (
            <button type="button" className="btn btn-ghost btn-danger" disabled={busy} onClick={() => void remove()}>
              Delete
            </button>
          )}
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy || !valid}>
            {existing ? "Save connection" : "Create connection"}
          </button>
        </DialogFooter>
      </form>
    </Modal>
  );
}

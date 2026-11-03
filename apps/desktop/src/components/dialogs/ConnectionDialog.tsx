import { useMemo, useState } from "react";
import { HudLabel } from "@mooring/ui";
import type { Protocol } from "../../lib/ipc";
import { credentialValidFor, supportsOverride } from "../../lib/credentials";
import { folderPath, useTree } from "../../stores/tree";
import { useCredentials } from "../../stores/credentials";
import { useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { CredentialPicker, pickerOptions } from "../credentials/CredentialPicker";
import { DialogFooter, Modal } from "./Modal";

const PROTOCOLS: { value: Protocol; label: string; port: number | null }[] = [
  { value: "ssh", label: "SSH", port: 22 },
  { value: "rdp", label: "RDP", port: 3389 },
  { value: "vnc", label: "VNC", port: 5900 },
  { value: "web", label: "Web", port: 443 },
  { value: "kubernetes", label: "Kubernetes", port: null },
  { value: "vsphere-console", label: "vSphere console", port: null },
];

/** Nearest folder default credential above `folderId` (the inheritance rule of ADR-0005). */
function inheritedId(folders: { id: string; parentId: string | null; defaultCredentialId: string | null }[], folderId: string): string | null {
  let cur = folders.find((f) => f.id === folderId);
  while (cur) {
    if (cur.defaultCredentialId) return cur.defaultCredentialId;
    const p = cur.parentId;
    cur = folders.find((f) => f.id === p);
  }
  return null;
}

/** Create or edit a connection. Credentials are chosen by reference; secrets never appear here. */
export function ConnectionDialog({ id, folderId, onClose }: { id?: string; folderId: string; onClose: () => void }) {
  const existing = useTree((s) => s.connections.find((c) => c.id === id));
  const folders = useTree((s) => s.folders);
  const creds = useCredentials((s) => s.items);
  const kinds = useCredentials((s) => s.kinds);
  const [name, setName] = useState(existing?.name ?? "");
  const [protocol, setProtocol] = useState<Protocol>(existing?.protocol ?? "ssh");
  const [host, setHost] = useState(existing?.host ?? "");
  const [port, setPort] = useState(existing?.port?.toString() ?? "");
  const [folder, setFolder] = useState(existing?.folderId ?? folderId);
  const [cred, setCred] = useState(existing?.credentialId ?? "");
  const [userOv, setUserOv] = useState(existing?.usernameOverride ?? "");
  const [domainOv, setDomainOv] = useState(existing?.domainOverride ?? "");
  const [gateway, setGateway] = useState(existing?.gatewayCredentialId ?? "");
  const [become, setBecome] = useState(existing?.becomeCredentialId ?? "");
  const [tags, setTags] = useState(existing?.tags.join(" ") ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const portNum = port.trim() === "" ? null : Number(port);
  const portBad = portNum !== null && (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535);
  const defaultPort = PROTOCOLS.find((p) => p.value === protocol)?.port;

  const inherited = creds.find((c) => c.id === inheritedId(folders, folder));
  const effective = creds.find((c) => c.id === (cred || inherited?.id));
  const inheritedOk = inherited ? credentialValidFor(kinds, inherited, protocol, "primary") : null;

  const primaryOptions = useMemo(
    () =>
      pickerOptions(
        creds,
        kinds,
        protocol,
        "primary",
        "Inherit from folder",
        inherited ? `${inherited.name}${inheritedOk && !inheritedOk.ok ? " — not usable here" : ""}` : "none set: the session will ask",
      ),
    [creds, kinds, protocol, inherited, inheritedOk],
  );
  const gatewayOptions = useMemo(
    () => pickerOptions(creds, kinds, protocol, "gateway", "Same as the session credential", "the RD Gateway gets the sign-in above"),
    [creds, kinds, protocol],
  );
  const becomeOptions = useMemo(
    () => pickerOptions(creds, kinds, protocol, "become", "None", "no privilege escalation after login"),
    [creds, kinds, protocol],
  );

  const pick = (v: string, opts: { value: string; disabledReason: string | null }[]) =>
    opts.find((o) => o.value === v && !o.disabledReason) ? v : "";
  // Changing protocol drops choices that became incompatible instead of failing on save.
  const primary = pick(cred, primaryOptions);
  const gw = protocol === "rdp" ? pick(gateway, gatewayOptions) : "";
  const bc = protocol === "ssh" ? pick(become, becomeOptions) : "";
  const canUser = effective ? supportsOverride(effective.kind, "username") : true;
  const canDomain = effective ? supportsOverride(effective.kind, "domain") : true;
  const dropped = (cred && !primary) || (gateway && protocol === "rdp" && !gw) || (become && protocol === "ssh" && !bc);
  const valid = name.trim() !== "" && host.trim() !== "" && !portBad;

  async function submit() {
    setBusy(true);
    const fields = {
      folderId: folder,
      name: name.trim(),
      protocol,
      host: host.trim(),
      port: portNum,
      credentialId: primary || null,
      usernameOverride: canUser && userOv.trim() ? userOv.trim() : null,
      domainOverride: canDomain && domainOv.trim() ? domainOv.trim() : null,
      gatewayCredentialId: gw || null,
      becomeCredentialId: bc || null,
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
    <Modal title={existing ? "Edit connection" : "New connection"} onClose={onClose} width={560}>
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
            <input id="conn-host" className="field mono" spellCheck={false} placeholder="server.example.test" value={host} onChange={(e) => { setHost(e.target.value); }} />
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
            <label className="field-label" htmlFor="conn-tags">Tags</label>
            <input id="conn-tags" className="field" placeholder="space or comma separated" value={tags} onChange={(e) => { setTags(e.target.value); }} />
          </div>
        </div>

        <div className="space-y-3 border-t border-line px-4 py-4">
          <HudLabel>Sign-in</HudLabel>
          <div className="flex items-start gap-2">
            <div className="min-w-0 flex-1">
              <CredentialPicker label="Credential" value={primary} options={primaryOptions} kinds={kinds} onChange={setCred} />
            </div>
            <button
              type="button"
              className="btn mt-[18px]"
              onClick={() => { useUi.getState().showCredentials({ mode: "new", protocol }); }}
            >
              New…
            </button>
          </div>
          {inherited && !primary && inheritedOk && !inheritedOk.ok && (
            <p className="field-hint field-problem" role="note">
              The folder credential “{inherited.name}” cannot sign in here: {inheritedOk.reason} Choose one above, or the session will fail.
            </p>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="field-label" htmlFor="conn-user-ov">
                Username override<span className="field-opt">optional</span>
              </label>
              <input
                id="conn-user-ov"
                className="field mono"
                spellCheck={false}
                disabled={!canUser}
                placeholder={canUser ? "use the credential's" : "not used by this kind"}
                value={canUser ? userOv : ""}
                onChange={(e) => { setUserOv(e.target.value); }}
              />
            </div>
            <div>
              <label className="field-label" htmlFor="conn-domain-ov">
                Domain override<span className="field-opt">optional</span>
              </label>
              <input
                id="conn-domain-ov"
                className="field mono"
                spellCheck={false}
                disabled={!canDomain}
                placeholder={canDomain ? "use the credential's" : "not used by this kind"}
                value={canDomain ? domainOv : ""}
                onChange={(e) => { setDomainOv(e.target.value); }}
              />
            </div>
          </div>
          <p className="field-hint">Overrides replace the account for this connection only. The stored secret is shared.</p>
          {protocol === "rdp" && (
            <CredentialPicker label="RD Gateway credential" value={gw} options={gatewayOptions} kinds={kinds} onChange={setGateway} />
          )}
          {protocol === "ssh" && (
            <CredentialPicker
              label="Become (sudo)"
              value={bc}
              options={becomeOptions}
              kinds={kinds}
              onChange={setBecome}
              hint="The password is sent only when the remote sudo prompt appears."
            />
          )}
          {dropped && <p className="field-hint">A previous choice does not fit {protocol.toUpperCase()} and was cleared.</p>}
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

import { useState } from "react";
import type { CredentialKind } from "../../lib/ipc";
import { KIND_LABEL, useCredentials } from "../../stores/credentials";
import { DialogFooter, Modal } from "./Modal";

const SECRET_LABELS: Record<CredentialKind, [string, string | null]> = {
  password: ["Password", null],
  ssh_key: ["Private key (PEM or OpenSSH)", "Key passphrase (optional)"],
  certificate: ["Certificate (PEM)", "Private key (PEM)"],
};

/**
 * Create a credential, or edit its name/username and optionally replace its secret.
 * Secret fields are write-only: never prefilled, cleared the moment the form is submitted,
 * and sent to Rust once. An empty secret on edit means "keep the stored one".
 */
export function CredentialDialog({ id, onClose }: { id?: string; onClose: () => void }) {
  const existing = useCredentials((s) => s.items.find((c) => c.id === id));
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState<CredentialKind>(existing?.kind ?? "password");
  const [username, setUsername] = useState(existing?.username ?? "");
  const [secret, setSecret] = useState("");
  const [secret2, setSecret2] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [label1, label2] = SECRET_LABELS[kind];
  const multiline = kind !== "password";
  const valid = name.trim() !== "" && (existing !== undefined || secret.length > 0);

  async function submit() {
    // Take the values, then wipe the fields before any await so nothing lingers in the form.
    const s1 = secret;
    const s2 = secret2 || null;
    setSecret("");
    setSecret2("");
    setBusy(true);
    const store = useCredentials.getState();
    let ok: boolean;
    if (existing) {
      ok = await store.updateMeta(existing.id, name.trim(), username.trim());
      if (ok && s1) ok = await store.replaceSecret(existing.id, s1, s2);
    } else {
      ok = (await store.create({ name: name.trim(), kind, username: username.trim(), secret: s1, secret2: s2 })) !== null;
    }
    setBusy(false);
    if (ok) onClose();
    else setError(useCredentials.getState().error ?? "could not save the credential");
  }

  const secretField = (fid: string, label: string, value: string, set: (v: string) => void, hint?: string) => (
    <div>
      <label className="field-label" htmlFor={fid}>{label}</label>
      {multiline ? (
        <textarea
          id={fid}
          className="field mono h-24 resize-none py-1.5"
          autoComplete="off"
          spellCheck={false}
          value={value}
          placeholder={existing ? "Leave empty to keep the stored value" : ""}
          onChange={(e) => { set(e.target.value); }}
          style={{ WebkitTextSecurity: value ? "disc" : "none" } as React.CSSProperties}
        />
      ) : (
        <input
          id={fid}
          type="password"
          className="field mono"
          autoComplete="new-password"
          value={value}
          placeholder={existing ? "Leave empty to keep the stored value" : ""}
          onChange={(e) => { set(e.target.value); }}
        />
      )}
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  );

  return (
    <Modal title={existing ? "Edit credential" : "New credential"} onClose={onClose} width={480}>
      <form
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) void submit();
        }}
      >
        <div className="space-y-3 px-4 py-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="field-label" htmlFor="cred-name">Name</label>
              <input id="cred-name" className="field" maxLength={200} value={name} onChange={(e) => { setName(e.target.value); }} />
            </div>
            <div>
              <label className="field-label" htmlFor="cred-kind">Kind</label>
              <select
                id="cred-kind"
                className="field"
                value={kind}
                disabled={existing !== undefined}
                onChange={(e) => { setKind(e.target.value as CredentialKind); }}
              >
                {(Object.keys(KIND_LABEL) as CredentialKind[]).map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="field-label" htmlFor="cred-user">Username</label>
            <input
              id="cred-user"
              className="field mono"
              spellCheck={false}
              autoComplete="off"
              value={username}
              onChange={(e) => { setUsername(e.target.value); }}
            />
          </div>
          {secretField("cred-secret", label1, secret, setSecret, "Encrypted in the vault. Mooring never shows it again.")}
          {label2 && secretField("cred-secret2", label2, secret2, setSecret2)}
        </div>
        <DialogFooter error={error}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy || !valid}>
            {existing ? "Save credential" : "Create credential"}
          </button>
        </DialogFooter>
      </form>
    </Modal>
  );
}

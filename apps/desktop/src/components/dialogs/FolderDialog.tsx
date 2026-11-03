import { useState } from "react";
import { useTree } from "../../stores/tree";
import { useCredentials } from "../../stores/credentials";
import { accountSummary } from "../../lib/credentials";
import { DialogFooter, Modal } from "./Modal";

/** Create or edit a folder: name and the default credential inherited by everything below it. */
export function FolderDialog({ id, parentId, onClose }: { id?: string; parentId: string; onClose: () => void }) {
  const existing = useTree((s) => s.folders.find((f) => f.id === id));
  const parent = useTree((s) => s.folders.find((f) => f.id === parentId));
  const creds = useCredentials((s) => s.items);
  const [name, setName] = useState(existing?.name ?? "");
  const [cred, setCred] = useState(existing?.defaultCredentialId ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    const t = useTree.getState();
    let folderId = existing?.id;
    if (existing) {
      if (name.trim() !== existing.name && !(await t.renameFolder(existing.id, name))) folderId = undefined;
    } else {
      folderId = (await t.createFolder(parentId, name))?.id;
    }
    const credentialId = cred || null;
    if (folderId && credentialId !== (existing?.defaultCredentialId ?? null)) {
      if (!(await t.setFolderCredential(folderId, credentialId))) folderId = undefined;
    }
    setBusy(false);
    if (folderId) onClose();
    else setError(useTree.getState().error ?? "could not save the folder");
  }

  async function remove() {
    if (!existing) return;
    setBusy(true);
    const ok = await useTree.getState().deleteFolder(existing.id);
    setBusy(false);
    if (ok) onClose();
    else setError(useTree.getState().error ?? "could not delete the folder");
  }

  return (
    <Modal title={existing ? `Edit folder` : `New folder in ${parent?.name ?? "tree"}`} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="space-y-3 px-4 py-4">
          <div>
            <label className="field-label" htmlFor="folder-name">Name</label>
            <input id="folder-name" className="field" value={name} maxLength={200} onChange={(e) => { setName(e.target.value); }} />
          </div>
          <div>
            <label className="field-label" htmlFor="folder-cred">Default credential</label>
            <select id="folder-cred" className="field" value={cred} onChange={(e) => { setCred(e.target.value); }}>
              <option value="">None (inherit from parent)</option>
              {creds.map((c) => (
                <option key={c.id} value={c.id}>{c.name}{accountSummary(c) ? ` (${accountSummary(c)})` : ""}</option>
              ))}
            </select>
            <p className="field-hint">Connections in this folder use it unless they set their own.</p>
          </div>
        </div>
        <DialogFooter error={error}>
          {existing && (
            <button type="button" className="btn btn-ghost btn-danger" disabled={busy} onClick={() => void remove()}>
              Delete folder and contents
            </button>
          )}
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy || name.trim().length === 0}>
            {existing ? "Save folder" : "Create folder"}
          </button>
        </DialogFooter>
      </form>
    </Modal>
  );
}

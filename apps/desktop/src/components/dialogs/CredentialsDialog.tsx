import { useState } from "react";
import { KIND_LABEL, useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";
import { DialogFooter, Modal } from "./Modal";

/** Credential list: metadata only, with edit / delete / new. */
export function CredentialsDialog({ onClose }: { onClose: () => void }) {
  const items = useCredentials((s) => s.items);
  const openDialog = useUi((s) => s.openDialog);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <Modal title="Credentials" onClose={onClose} width={560}>
      <ul aria-label="Stored credentials" className="max-h-[48vh] overflow-y-auto py-1">
        {items.length === 0 && <li className="px-4 py-6 text-center text-text-faint">No credentials yet. Create one to attach it to folders and connections.</li>}
        {items.map((c) => (
          <li key={c.id} className="flex items-center gap-3 px-4 py-1.5">
            <span className="min-w-0 flex-1">
              <span className="block truncate">{c.name}</span>
              <span className="mono block truncate text-text-faint">{c.username || "no username"}</span>
            </span>
            <span className="w-[86px] text-[length:var(--fs-xs)] text-text-muted">{KIND_LABEL[c.kind]}</span>
            <button type="button" className="btn btn-ghost" onClick={() => { openDialog({ kind: "credential", id: c.id }); }}>
              Edit
            </button>
            {confirm === c.id ? (
              <button
                type="button"
                className="btn btn-danger"
                onClick={() =>
                  void useCredentials.getState().remove(c.id).then((ok) => {
                    setConfirm(null);
                    setError(ok ? null : useCredentials.getState().error);
                  })
                }
              >
                Confirm delete
              </button>
            ) : (
              <button type="button" className="btn btn-ghost btn-danger" onClick={() => { setConfirm(c.id); }}>
                Delete
              </button>
            )}
          </li>
        ))}
      </ul>
      <DialogFooter error={error}>
        <button type="button" className="btn btn-ghost" onClick={onClose}>Close</button>
        <button type="button" className="btn btn-primary" onClick={() => { openDialog({ kind: "credential" }); }}>
          New credential
        </button>
      </DialogFooter>
    </Modal>
  );
}

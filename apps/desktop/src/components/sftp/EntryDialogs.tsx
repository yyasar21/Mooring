import { useState } from "react";
import type { SftpEntry } from "../../lib/ipc";
import { checkEntryName } from "../../lib/remotePath";
import { DialogFooter, Modal } from "../dialogs/Modal";

/** Ask for one path component (new folder, rename). */
export function NameDialog({ title, label, initial, action, onSubmit, onClose }: {
  title: string;
  label: string;
  initial: string;
  action: string;
  onSubmit: (name: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const problem = checkEntryName(name);

  return (
    <Modal title={title} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setTouched(true);
          if (problem || busy) return;
          setBusy(true);
          void onSubmit(name).then((ok) => {
            setBusy(false);
            if (ok) onClose();
          });
        }}
      >
        <div className="px-4 py-3.5">
          <label className="field-label" htmlFor="sftp-name">{label}</label>
          <input
            id="sftp-name"
            className="field mono"
            value={name}
            spellCheck={false}
            aria-invalid={touched && problem ? true : undefined}
            onChange={(e) => { setName(e.target.value); }}
          />
        </div>
        <DialogFooter error={touched ? problem : null}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{action}</button>
        </DialogFooter>
      </form>
    </Modal>
  );
}

/** Remove is never recursive (the crate refuses non-empty folders); say so before asking. */
export function RemoveDialog({ entry, path, onConfirm, onClose }: {
  entry: SftpEntry;
  path: string;
  onConfirm: () => Promise<boolean>;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const what = entry.kind === "dir" ? "folder" : entry.kind === "symlink" ? "link" : "file";
  return (
    <Modal title={`Delete ${what}?`} onClose={onClose}>
      <div className="px-4 py-3.5">
        <p className="mono select-text break-all" style={{ color: "var(--hot)" }}>{path}</p>
        <p className="mt-3 text-text-muted">
          {entry.kind === "dir"
            ? "Only an empty folder can be deleted. Nothing inside is touched."
            : "The file is deleted on the server. This cannot be undone."}
        </p>
      </div>
      <div className="flex justify-end gap-2 border-t border-line px-4 py-3">
        <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button
          type="button"
          className="btn btn-danger"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void onConfirm().then(() => { onClose(); });
          }}
        >
          Delete
        </button>
      </div>
    </Modal>
  );
}

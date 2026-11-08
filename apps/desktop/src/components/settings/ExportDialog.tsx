import { useState } from "react";
import { ipc, type BackupPick, type ExportResult } from "../../lib/ipc";
import { fmtBytes } from "../../lib/format";
import { exportFormProblem, passphraseStrength } from "../../lib/passphrase";
import { describeError } from "../../stores/errors";
import { Modal } from "../dialogs/Modal";
import { useSecretInput } from "./useSecretInput";

/**
 * ADR-0023 export: master password, the backup passphrase twice (with a strength hint), then
 * the native save dialog that Rust opens (`vault_export_pick`), then `vault_export_age`. A pick
 * survives a refused export, so a mistyped password does not ask for the file again. Every
 * password field is cleared after each attempt.
 *
 * L-53: the three secrets never enter React state. The fields are uncontrolled; the form problem
 * is checked on submit, the values are read once for the IPC call and the fields emptied.
 */
export function ExportDialog({ onClose }: { onClose: () => void }) {
  const master = useSecretInput();
  const passphrase = useSecretInput();
  const repeat = useSecretInput();
  const [problem, setProblem] = useState<string | null>(null);
  const [strength, setStrength] = useState<ReturnType<typeof passphraseStrength> | null>(null);
  const [busy, setBusy] = useState(false);
  const [pick, setPick] = useState<BackupPick | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ name: string; result: ExportResult } | null>(null);

  function clearAll() {
    master.clear();
    passphrase.clear();
    repeat.clear();
    setStrength(null);
  }

  async function submit() {
    if (busy) return;
    const p = exportFormProblem({ master: master.peek(), passphrase: passphrase.peek(), repeat: repeat.peek() });
    setProblem(p);
    if (p) return;
    setBusy(true);
    setError(null);
    try {
      const target = pick ?? (await ipc.vaultExportPick());
      if (!target) {
        setError("No file was chosen, so nothing was saved.");
        return;
      }
      setPick(target);
      const password = master.take();
      const exportPassphrase = passphrase.take();
      const result = await ipc.vaultExportAge({ pickId: target.pickId, password, exportPassphrase });
      setDone({ name: target.name, result });
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      clearAll();
      setBusy(false);
    }
  }

  if (done) {
    const r = done.result;
    return (
      <Modal title="Backup saved" onClose={onClose} width={480}>
        <div className="flex flex-col gap-3 px-4 py-4">
          <p role="status" className="m-0">
            Saved <span className="mono">{done.name}</span> ({fmtBytes(r.bytes)}): {r.connections} connections, {r.credentials} credentials and {r.folders} folders.
          </p>
          <p className="field-hint m-0">Keep the passphrase somewhere safe. Without it the backup cannot be opened, by you or by anyone else.</p>
        </div>
        <div className="sec-actions border-t border-line px-4 py-3">
          <button type="button" className="btn btn-primary" onClick={onClose}>Done</button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Export a backup" onClose={onClose} width={480}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="flex flex-col gap-3 px-4 py-4">
          <p className="m-0 text-[length:var(--fs-s)] text-text-muted">
            The backup holds every folder, connection, credential and trusted host key, encrypted with a passphrase you choose (age, scrypt). It is a separate key from the master password.
          </p>
          <div>
            <label className="field-label" htmlFor="exp-master">Master password</label>
            <input id="exp-master" type="password" className="field" autoComplete="current-password" ref={master.ref} onChange={master.onChange} />
          </div>
          <div>
            <label className="field-label" htmlFor="exp-pass">Backup passphrase</label>
            <input id="exp-pass" type="password" className="field" autoComplete="new-password" aria-describedby="exp-strength" ref={passphrase.ref} onChange={(e) => {
                passphrase.onChange(e);
                setStrength(e.target.value ? passphraseStrength(e.target.value) : null);
              }} />
            <p id="exp-strength" className="strength mt-1" data-level={strength?.level}>{strength?.text ?? "At least 12 characters. Several unrelated words work well."}</p>
          </div>
          <div>
            <label className="field-label" htmlFor="exp-pass2">Repeat backup passphrase</label>
            <input id="exp-pass2" type="password" className="field" autoComplete="new-password" ref={repeat.ref} onChange={repeat.onChange} />
          </div>
          {pick && <p className="field-hint m-0">Saving to <span className="mono">{pick.name}</span>.</p>}
          {problem && <p role="alert" className="settings-err">{problem}</p>}
          {error && <p role="alert" className="settings-err">{error}</p>}
        </div>
        <div className="sec-actions border-t border-line px-4 py-3">
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Exporting…" : pick ? "Export" : "Choose file and export…"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

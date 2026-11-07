import { useState } from "react";
import { ipc, type BackupPick, type ExportResult } from "../../lib/ipc";
import { fmtBytes } from "../../lib/format";
import { exportFormProblem, passphraseStrength } from "../../lib/passphrase";
import { describeError } from "../../stores/errors";
import { Modal } from "../dialogs/Modal";

/**
 * ADR-0023 export: master password, the backup passphrase twice (with a strength hint), then
 * the native save dialog that Rust opens (`vault_export_pick`), then `vault_export_age`. A pick
 * survives a refused export, so a mistyped password does not ask for the file again. Every
 * password field is cleared after each attempt.
 */
export function ExportDialog({ onClose }: { onClose: () => void }) {
  const [master, setMaster] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [repeat, setRepeat] = useState("");
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [pick, setPick] = useState<BackupPick | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ name: string; result: ExportResult } | null>(null);
  const problem = exportFormProblem({ master, passphrase, repeat });
  const strength = passphrase ? passphraseStrength(passphrase) : null;

  async function submit() {
    setTried(true);
    if (problem || busy) return;
    setBusy(true);
    setError(null);
    try {
      const target = pick ?? (await ipc.vaultExportPick());
      if (!target) {
        setError("No file was chosen, so nothing was saved.");
        return;
      }
      setPick(target);
      const result = await ipc.vaultExportAge({ pickId: target.pickId, password: master, exportPassphrase: passphrase });
      setDone({ name: target.name, result });
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setMaster("");
      setPassphrase("");
      setRepeat("");
      setTried(false);
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
            <input id="exp-master" type="password" className="field" autoComplete="current-password" value={master} onChange={(e) => { setMaster(e.target.value); }} />
          </div>
          <div>
            <label className="field-label" htmlFor="exp-pass">Backup passphrase</label>
            <input id="exp-pass" type="password" className="field" autoComplete="new-password" aria-describedby="exp-strength" value={passphrase} onChange={(e) => { setPassphrase(e.target.value); }} />
            <p id="exp-strength" className="strength mt-1" data-level={strength?.level}>{strength?.text ?? "At least 12 characters. Several unrelated words work well."}</p>
          </div>
          <div>
            <label className="field-label" htmlFor="exp-pass2">Repeat backup passphrase</label>
            <input id="exp-pass2" type="password" className="field" autoComplete="new-password" value={repeat} onChange={(e) => { setRepeat(e.target.value); }} />
          </div>
          {pick && <p className="field-hint m-0">Saving to <span className="mono">{pick.name}</span>.</p>}
          {tried && problem && <p role="alert" className="settings-err">{problem}</p>}
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

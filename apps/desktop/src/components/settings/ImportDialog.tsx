import { useState, type ReactNode } from "react";
import { ipc, isIpcError, REPLACE_CONFIRM, type ImportConflict, type ImportInspect, type ImportMode, type ImportPickResult, type ImportResult } from "../../lib/ipc";
import { fmtBytes, fmtStamp } from "../../lib/format";
import { describeError } from "../../stores/errors";
import { useCredentials } from "../../stores/credentials";
import { useTree } from "../../stores/tree";
import { Modal } from "../dialogs/Modal";
import { useSecretInput } from "./useSecretInput";

const RESOLUTION: Record<ImportConflict["resolution"], string> = {
  kept_both: "changed on both sides: both copies kept",
  last_writer_wins: "changed on both sides: the newer one kept",
  kept_edit: "your edit kept",
};

/** A pick Rust forgot (third wrong passphrase, or it expired): the file must be chosen again. */
const pickGone = (e: unknown) => isIpcError(e) && e.code === "input.invalid" && /pick/.test(e.message);

/**
 * ADR-0023 import, after the native open dialog (`vault_import_pick`) chose `pick`:
 * passphrase → `vault_import_inspect` (counts, same or foreign vault) → mode and passwords →
 * `vault_import_age` → summary. Merge is the default; Replace needs the word REPLACE typed.
 *
 * L-53: the passphrase and both master passwords never enter React state. The fields are
 * uncontrolled, read once for the IPC call and emptied after it and when they leave the page.
 */
export function ImportDialog({ pick, onClose, onExportFirst }: { pick: ImportPickResult; onClose: () => void; onExportFirst: () => void }) {
  const passphrase = useSecretInput();
  const [inspect, setInspect] = useState<ImportInspect | null>(null);
  const [mode, setMode] = useState<ImportMode>("merge");
  const [confirm, setConfirm] = useState("");
  const master = useSecretInput();
  const source = useSecretInput();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [gone, setGone] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);

  async function open() {
    if (passphrase.empty || busy) return;
    setBusy(true);
    setError(null);
    try {
      const exportPassphrase = passphrase.take();
      setInspect(await ipc.vaultImportInspect({ pickId: pick.pickId, exportPassphrase }));
    } catch (e: unknown) {
      if (pickGone(e)) setGone(true);
      setError(pickGone(e) ? "Mooring stopped trying this file after three wrong passphrases. Choose it again to retry." : describeError(e));
    } finally {
      passphrase.clear();
      setBusy(false);
    }
  }

  const replaceOk = mode !== "replace" || confirm === REPLACE_CONFIRM;
  const canImport = inspect !== null && !master.empty && (!inspect.needsSourcePassword || !source.empty) && replaceOk && !busy;

  async function apply() {
    if (!inspect || !canImport) return;
    setBusy(true);
    setError(null);
    try {
      const password = master.take();
      const sourcePassword = inspect.needsSourcePassword ? source.take() : null;
      const r = await ipc.vaultImportAge({
        pickId: pick.pickId,
        password,
        sourcePassword,
        mode,
        confirm: mode === "replace" ? confirm : null,
      });
      setResult(r);
      await Promise.all([useTree.getState().load(), useCredentials.getState().load()]);
    } catch (e: unknown) {
      if (pickGone(e)) setGone(true);
      setError(pickGone(e) ? "This file was already imported or the review expired. Choose it again." : describeError(e));
    } finally {
      master.clear();
      source.clear();
      setBusy(false);
    }
  }

  const footer = (primary: ReactNode) => (
    <div className="sec-actions border-t border-line px-4 py-3">
      <button type="button" className="btn btn-ghost" onClick={onClose}>{result || gone ? "Close" : "Cancel"}</button>
      {!gone && primary}
    </div>
  );

  if (result) {
    return (
      <Modal title="Backup imported" onClose={onClose} width={520}>
        <div className="flex flex-col gap-3 px-4 py-4" role="status">
          <p className="m-0">
            {result.mode === "replace" ? "The vault now holds exactly what the backup held." : "The backup was merged into this vault."}{" "}
            Added {result.added}, updated {result.updated}{result.skipped > 0 ? `, skipped ${String(result.skipped)}` : ""}.
          </p>
          {result.conflicts.length > 0 ? (
            <>
              <p className="m-0 text-[length:var(--fs-s)] text-text-muted">{result.conflicts.length} conflict{result.conflicts.length === 1 ? "" : "s"}:</p>
              <ul className="backup-conflicts" aria-label="Conflicts">
                {result.conflicts.map((c) => (
                  <li key={`${c.kind}-${c.id}`}><span className="text-text">{c.name}</span> ({c.kind}) — {RESOLUTION[c.resolution]}</li>
                ))}
              </ul>
            </>
          ) : (
            <p className="m-0 text-[length:var(--fs-s)] text-text-muted">No conflicts.</p>
          )}
        </div>
        {footer(null)}
      </Modal>
    );
  }

  return (
    <Modal title="Import a backup" onClose={onClose} width={520}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void (inspect ? apply() : open());
        }}
      >
        <div className="flex flex-col gap-3 px-4 py-4">
          <p className="m-0 text-[length:var(--fs-s)]">
            <span className="mono">{pick.name}</span> <span className="text-text-muted">({fmtBytes(pick.bytes)})</span>
          </p>
          {!inspect ? (
            <div>
              <label className="field-label" htmlFor="imp-pass">Backup passphrase</label>
              <input id="imp-pass" type="password" className="field" autoComplete="off" disabled={gone} ref={passphrase.ref} onChange={passphrase.onChange} />
              <p className="field-hint">The passphrase chosen when the backup was exported. Nothing is imported yet.</p>
            </div>
          ) : (
            <Review inspect={inspect} mode={mode} setMode={setMode} confirm={confirm} setConfirm={setConfirm} source={source} onExportFirst={onExportFirst} />
          )}
          {inspect && (
            <div>
              <label className="field-label" htmlFor="imp-master">Master password of this vault</label>
              <input id="imp-master" type="password" className="field" autoComplete="current-password" ref={master.ref} onChange={master.onChange} />
            </div>
          )}
          {error && <p role="alert" className="settings-err">{error}</p>}
        </div>
        {footer(
          <button type="submit" className={`btn ${mode === "replace" && inspect ? "btn-danger" : "btn-primary"}`} disabled={inspect ? !canImport : passphrase.empty || busy}>
            {busy ? "Working…" : !inspect ? "Open backup" : mode === "replace" ? "Replace this vault" : "Merge into this vault"}
          </button>,
        )}
      </form>
    </Modal>
  );
}

function Review({ inspect, mode, setMode, confirm, setConfirm, source, onExportFirst }: {
  inspect: ImportInspect;
  mode: ImportMode;
  setMode: (m: ImportMode) => void;
  confirm: string;
  setConfirm: (v: string) => void;
  source: Pick<ReturnType<typeof useSecretInput>, "ref" | "onChange">;
  onExportFirst: () => void;
}) {
  const c = inspect.counts;
  return (
    <>
      <dl className="backup-facts" aria-label="Backup contents">
        <dt>Exported</dt><dd>{fmtStamp(inspect.exportedAt)} by Mooring {inspect.appVersion}</dd>
        <dt>Contains</dt><dd>{c.connections} connections, {c.credentials} credentials, {c.folders} folders, {c.trust} trusted host keys</dd>
        <dt>Vault</dt><dd>{inspect.sameVault ? "This vault" : "Another vault"}</dd>
      </dl>
      {inspect.needsSourcePassword && (
        <div className="flex flex-col gap-2">
          <p className="backup-note" role="note">
            This backup comes from another vault. Enter that vault’s master password so Mooring can re-encrypt its secrets under this vault’s key.
          </p>
          <div>
            <label className="field-label" htmlFor="imp-source">Master password of the other vault</label>
            <input id="imp-source" type="password" className="field" autoComplete="off" ref={source.ref} onChange={source.onChange} />
          </div>
        </div>
      )}
      <fieldset className="backup-modes">
        <legend className="field-label">How to import</legend>
        <label className="backup-mode">
          <input type="radio" name="imp-mode" checked={mode === "merge"} onChange={() => { setMode("merge"); }} />
          <span><span className="text-text">Merge</span> <span className="text-text-muted">(recommended). Adds what is new and keeps both copies of anything changed on both sides.</span></span>
        </label>
        <label className="backup-mode">
          <input type="radio" name="imp-mode" checked={mode === "replace"} onChange={() => { setMode("replace"); }} />
          <span><span className="text-text">Replace</span> <span className="text-text-muted">this vault’s folders, connections, credentials and trusted keys with the backup’s.</span></span>
        </label>
      </fieldset>
      {mode === "replace" && (
        <div className="flex flex-col gap-2">
          <p className="backup-note" data-tone="danger" role="note">
            Everything in this vault that is not in the backup is deleted. This cannot be undone.{" "}
            <button type="button" className="btn btn-ghost" onClick={onExportFirst}>Export a backup first…</button>
          </p>
          <div>
            <label className="field-label" htmlFor="imp-confirm">Type {REPLACE_CONFIRM} to confirm</label>
            <input id="imp-confirm" className="field mono" autoComplete="off" spellCheck={false} value={confirm} onChange={(e) => { setConfirm(e.target.value); }} />
          </div>
        </div>
      )}
    </>
  );
}

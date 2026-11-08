import { useState } from "react";
import { ipc, type ImportPickResult } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { ExportDialog } from "./ExportDialog";
import { ImportDialog } from "./ImportDialog";
import { SettingsCard } from "./Toggle";

/**
 * Settings → Backup (ADR-0023): export the whole vault to an `age` file and import one back.
 * Both file dialogs are native and run by Rust; the UI only ever sees a pick id and a file name.
 */
export function BackupCard() {
  const [exporting, setExporting] = useState(false);
  const [importPick, setImportPick] = useState<ImportPickResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function chooseImport() {
    setBusy(true);
    setError(null);
    try {
      const pick = await ipc.vaultImportPick();
      if (pick) setImportPick(pick);
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <SettingsCard title="Backup" labelledBy="backup-title">
      <div className="settings-body">
        <div className="backup-row">
          <p className="text-[length:var(--fs-13)] text-text-muted">
            An encrypted copy of the vault in one file: folders, connections, credentials and trusted host keys. It opens with its own passphrase, on any computer with Mooring.
          </p>
        </div>
        <div className="sec-actions" style={{ justifyContent: "flex-start" }}>
          <button type="button" className="btn" onClick={() => { setExporting(true); }}>Export backup…</button>
          <button type="button" className="btn" disabled={busy} onClick={() => void chooseImport()}>Import backup…</button>
        </div>
        <p className="field-hint">Importing merges by default. Replacing the vault is a separate choice that asks you to type REPLACE.</p>
        {error && <p role="alert" className="settings-err">{error}</p>}
      </div>
      {importPick && (
        <ImportDialog pick={importPick} onClose={() => { setImportPick(null); }} onExportFirst={() => { setExporting(true); }} />
      )}
      {exporting && <ExportDialog onClose={() => { setExporting(false); }} />}
    </SettingsCard>
  );
}

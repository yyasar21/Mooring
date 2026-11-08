import { useEffect, useState } from "react";
import { ipc, type ImportFormatInfo, type KnownLocation } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { SettingsCard } from "../settings/Toggle";
import type { SourceId } from "./importText";
import { ImportWizard } from "./ImportWizard";
import { SourceTiles } from "./SourceTiles";

/**
 * Settings → Import (ADR-0019 §6): the source grid; a tile opens the wizard at its file step (or
 * the directory form for LDAPS), the known-location shortcut runs the preview straight away.
 */
export function ImportCard() {
  const [formats, setFormats] = useState<ImportFormatInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<{ format: SourceId; known: KnownLocation | null } | null>(null);

  useEffect(() => {
    let live = true;
    ipc.importFormats().then(
      (rows) => { if (live) setFormats(rows); },
      (e: unknown) => { if (live) setError(describeError(e)); },
    );
    return () => { live = false; };
  }, []);

  return (
    <SettingsCard title="Import" labelledBy="settings-import">
      <div className="settings-body">
        <p className="text-text-muted">
          Read another tool's export into a new folder of this vault. Nothing is merged or overwritten, no password is decrypted, and nothing leaves this computer.
        </p>
        <SourceTiles formats={formats} onChoose={(format) => { setOpen({ format, known: null }); }} onKnown={(known) => { setOpen({ format: known, known }); }} />
        {error && <p role="alert" className="settings-err">{error}</p>}
      </div>
      {open && <ImportWizard key={`${open.format}-${open.known ?? "file"}`} format={open.format} known={open.known} onClose={() => { setOpen(null); }} />}
    </SettingsCard>
  );
}

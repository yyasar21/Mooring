import { useEffect, useRef } from "react";
import type { ImportReport, KnownLocation } from "../../lib/ipc";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { Modal } from "../dialogs/Modal";
import { Toggle } from "../settings/Toggle";
import { DirectoryForm } from "./DirectoryForm";
import { formatSize, KNOWN_LOCATION_TEXT, plural, SOURCE_TILES, type SourceId } from "./importText";
import { PreviewCounts, PreviewNotes, PreviewOptions } from "./PreviewNotes";
import { PreviewTree } from "./PreviewTree";
import { SourceTiles } from "./SourceTiles";
import { useImportWizard, type WizardStep } from "./useImportWizard";

const steps = (first: "file" | "directory"): { id: WizardStep; label: string }[] => [
  first === "file" ? { id: "file", label: "File" } : { id: "directory", label: "Directory" },
  { id: "preview", label: "Preview" },
  { id: "apply", label: "Apply" },
];

/**
 * The import wizard of ADR-0019 §6: source → file (Rust dialog; the WebView never sees the file)
 * or directory (the LDAPS form, I2) → preview (checkboxes, duplicates, opt-ins, skipped,
 * warnings) → apply → report. Closing before the apply discards the held plan. `format` null
 * opens on the source grid (onboarding).
 */
export function ImportWizard({ format, known = null, onClose }: { format: SourceId | null; known?: KnownLocation | null; onClose: () => void }) {
  const w = useImportWizard(format, known);
  const label = w.source ? (SOURCE_TILES.find((t) => t.id === w.source)?.label ?? w.source) : null;
  const close = () => { w.discard(); onClose(); };
  const openFolder = (r: ImportReport) => {
    onClose();
    useUi.getState().setView("workspace");
    useTree.getState().select({ kind: "folder", id: r.rootFolderId });
  };
  const sourceReady = w.source === "ldaps" || w.known !== null || w.pick !== null;
  const rail = steps(w.source === "ldaps" ? "directory" : "file");
  /** Each step lands focus on its first control, so the keyboard never falls out of the dialog. */
  const body = useRef<HTMLDivElement>(null);
  useEffect(() => {
    body.current?.querySelector<HTMLElement>("[data-focus-first], .imp-rows input")?.focus();
  }, [w.step]);

  return (
    <Modal title={label ? `Import from ${label}` : "Import connections"} onClose={close} width={680}>
      {w.step !== "source" && (
        <ol className="vs-steps" aria-label="Import steps">
          {rail.map((s, i) => (
            <li key={s.id} aria-current={w.step === s.id ? "step" : undefined} data-done={rail.findIndex((x) => x.id === w.step) > i || undefined}>
              <span className="tnum">{i + 1}</span>
              {s.label}
            </li>
          ))}
        </ol>
      )}

      <div className="imp-body" ref={body}>
        {w.step === "source" && (
          <>
            <p className="text-text-muted">Choose the tool you are coming from. Mooring reads its export once and puts everything in a new folder; nothing you already have is changed.</p>
            <SourceTiles formats={w.formats} onChoose={w.chooseSource} onKnown={(k) => void w.readKnownLocation(k)} disabled={w.busy} />
          </>
        )}

        {w.step === "directory" && (
          <>
            <DirectoryForm value={w.ldap} errors={w.ldapErrors} bind={w.bind} busy={w.busy} onChange={w.setLdap} onTest={() => void w.testBind()} />
            {w.busy && <p role="status" className="vs-line">Contacting the directory over TLS…</p>}
            {w.error && <p role="alert" className="imp-error">{w.error}</p>}
          </>
        )}

        {w.step === "file" && w.format && (
          <>
            {w.known ? (
              <p className="text-text-muted">
                Reading <span className="mono">{KNOWN_LOCATION_TEXT[w.known].where}</span> on this computer. No file dialog is needed.
              </p>
            ) : (
              <>
                <p className="text-text-muted">
                  {SOURCE_TILES.find((t) => t.id === w.format)?.hint}. The file is opened by Mooring's Rust core, read once and kept as a plan in memory for ten minutes; it is never changed or copied.
                </p>
                <div className="imp-dock m-hud" data-active={w.pick ? true : undefined}>
                  {w.pick ? (
                    <div className="imp-dock-file">
                      <span className="imp-dock-name">{w.pick.fileName}</span>
                      <span className="imp-dock-size tnum">{formatSize(w.pick.size)}</span>
                    </div>
                  ) : (
                    <span className="imp-dock-empty">No file chosen yet</span>
                  )}
                  <button type="button" className="btn" disabled={w.busy} onClick={() => void w.pickFile()} autoFocus>
                    {w.pick ? "Choose another file" : "Choose file"}
                  </button>
                </div>
                {w.info?.knownLocation && (
                  <button type="button" className="btn btn-ghost self-start" disabled={w.busy} onClick={() => { const k = w.info?.knownLocation; if (k) void w.readKnownLocation(k); }}>
                    {KNOWN_LOCATION_TEXT[w.info.knownLocation].button}
                  </button>
                )}
              </>
            )}
            {w.busy && <p role="status" className="vs-line">Reading and checking the file…</p>}
            {w.error && <p role="alert" className="imp-error">{w.error}</p>}
          </>
        )}

        {w.step === "preview" && w.preview && (
          <>
            <PreviewCounts preview={w.preview} />
            <PreviewOptions preview={w.preview} secretsPossible={w.info?.secretsPossible ?? false} known={w.known !== null} options={w.options} busy={w.busy} onOption={(k, on) => void w.setOption(k, on)} />
            {w.preview.items.some((i) => i.duplicateOf !== undefined) && (
              <Toggle
                checked={w.skipDuplicates}
                onChange={w.setSkipDuplicates}
                label="Skip duplicates"
                hint={`${plural(w.preview.items.filter((i) => i.duplicateOf !== undefined).length, "connection")} already in the vault with the same protocol, host, port and user. Off, they are imported as second copies.`}
              />
            )}
            <PreviewTree preview={w.preview} excluded={w.excluded} onToggle={w.toggle} onAll={w.setAll} skipDuplicates={w.skipDuplicates} />
            <PreviewNotes preview={w.preview} excluded={w.excluded} onToggle={w.toggle} />
            {w.busy && <p role="status" className="vs-line">Running the preview again…</p>}
            {w.error && <p role="alert" className="imp-error">{w.error}</p>}
          </>
        )}

        {w.step === "apply" && w.report && (
          <>
            <p role="status" className="vs-line" data-tone="ok" tabIndex={-1} data-focus-first>Imported into “{w.preview?.rootName ?? "the new folder"}”.</p>
            <dl className="imp-counts" role="group" aria-label="Import report">
              {([["folders", w.report.folders], ["connections", w.report.connections], ["credentials", w.report.credentials], ["secrets", w.report.secrets], ["skipped", w.report.skipped]] as const).map(([k, v]) => (
                <div key={k} data-hot={(k === "skipped" && v > 0) || undefined}>
                  <dd className="tnum">{v}</dd>
                  <dt>{k}</dt>
                </div>
              ))}
            </dl>
            <p className="field-hint">
              Everything sits under one new folder, so a mistaken import is one delete away. Credentials that ask at connect will prompt the first time you open their connection.
            </p>
          </>
        )}
      </div>

      <div className="imp-foot">
        {w.step === "apply" && w.report ? (
          <>
            <button type="button" className="btn btn-ghost" onClick={onClose}>Close</button>
            <button type="button" className="btn btn-primary" onClick={() => { if (w.report) openFolder(w.report); }}>Open folder</button>
          </>
        ) : (
          <>
            <button type="button" className="btn btn-ghost" onClick={close} autoFocus={w.known !== null}>Cancel</button>
            {w.step !== "source" && (
              <button type="button" className="btn" disabled={w.busy} onClick={w.back}>Back</button>
            )}
            {(w.step === "file" || w.step === "directory") && (
              <button type="button" className="btn btn-primary" disabled={w.busy || !sourceReady} onClick={() => void w.runPreview()}>
                {w.error && w.known ? "Try again" : "Preview"}
              </button>
            )}
            {w.step === "preview" && (
              <button type="button" className="btn btn-primary" disabled={w.busy} onClick={() => void w.apply()}>
                Import {plural(w.preview?.items.filter((i) => !w.excluded.has(i.key) && !(w.skipDuplicates && i.duplicateOf !== undefined)).length ?? 0, "item")}
              </button>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}

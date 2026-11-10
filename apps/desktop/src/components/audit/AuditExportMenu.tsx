import { useEffect, useRef, useState } from "react";
import { ipc, type AuditExportFormat, type AuditFilterInput } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { useToasts } from "../../stores/toast";

const FORMATS: { format: AuditExportFormat; label: string; hint: string }[] = [
  { format: "csv", label: "CSV", hint: "for spreadsheets" },
  { format: "jsonl", label: "JSON Lines", hint: "one entry per line" },
];

export const exportedText = (n: number): string => `Exported ${n.toLocaleString("en-US")} ${n === 1 ? "entry" : "entries"}`;

/**
 * "Export…" in the audit filter bar. Rust opens the save dialog, writes the redacted rows that
 * match `filter` and audits `audit.exported`; the UI never sees the path. A cancelled dialog
 * shows nothing; a failure goes to `onError`.
 */
export function AuditExportMenu({ filter, onExported, onError }: { filter: AuditFilterInput | null; onExported: () => void; onError: (text: string | null) => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (open) menu.current?.querySelector<HTMLElement>("[role='menuitem']")?.focus();
  }, [open]);

  const run = async (format: AuditExportFormat) => {
    setOpen(false);
    trigger.current?.focus();
    setBusy(true);
    onError(null);
    try {
      const res = await ipc.auditExport(filter ? { format, filter } : { format });
      if (res.cancelled) return;
      useToasts.getState().push(exportedText(res.count), { detail: filter ? "Only the entries that match the filters." : null });
      onExported();
    } catch (e: unknown) {
      onError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative flex-none">
      <button
        ref={trigger}
        type="button"
        className="btn"
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={busy}
        title={filter ? "Export the entries that match the filters" : "Export the whole audit log"}
        onClick={() => { setOpen(!open); }}
      >
        Export…
      </button>
      {open && (
        <div
          ref={menu}
          role="menu"
          aria-label="Export format"
          className="split-menu"
          onKeyDown={(e) => {
            const els = [...(menu.current?.querySelectorAll<HTMLElement>("[role='menuitem']") ?? [])];
            const i = els.indexOf(document.activeElement as HTMLElement);
            if (e.key === "ArrowDown" || e.key === "ArrowUp") {
              e.preventDefault();
              els[(i + (e.key === "ArrowDown" ? 1 : -1) + els.length) % els.length]?.focus();
            } else if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              setOpen(false);
              trigger.current?.focus();
            }
          }}
          onBlur={(e) => { if (!menu.current?.contains(e.relatedTarget)) setOpen(false); }}
        >
          {FORMATS.map((f) => (
            <button key={f.format} type="button" role="menuitem" onClick={() => void run(f.format)}>
              <span>{f.label}</span>
              <span className="ml-auto text-text-faint">{f.hint}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

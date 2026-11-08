import type { ReactNode } from "react";
import { CLIPBOARD_POLICIES, MAX_FPS_VALUES, type ClipboardPolicy, type MaxFps } from "../../../lib/ipc";

/** A radio group drawn as the segmented control of the settings cards. */
export function Seg<T extends string | number>({ legend, name, value, options, onChange, hint }: {
  legend: string;
  name: string;
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (v: T) => void;
  hint?: ReactNode;
}) {
  return (
    <fieldset className="settings-seg">
      <legend className="field-label">{legend}</legend>
      {options.map((o) => (
        <label key={String(o.value)} className="seg-opt" data-checked={value === o.value || undefined}>
          <input type="radio" name={name} value={String(o.value)} checked={value === o.value} onChange={() => { onChange(o.value); }} />
          {o.label}
        </label>
      ))}
      {hint && <p className="field-hint mt-1 w-full">{hint}</p>}
    </fieldset>
  );
}

const CLIPBOARD_LABEL: Record<ClipboardPolicy, string> = {
  both: "Both directions",
  to_remote: "Local → remote only",
  from_remote: "Remote → local only",
  off: "Off",
};

export function ClipboardSelect({ id, value, onChange }: { id: string; value: ClipboardPolicy; onChange: (v: ClipboardPolicy) => void }) {
  return (
    <div>
      <label className="field-label" htmlFor={id}>Clipboard</label>
      <select id={id} className="field" value={value} onChange={(e) => { onChange(e.target.value as ClipboardPolicy); }}>
        {CLIPBOARD_POLICIES.map((p) => <option key={p} value={p}>{CLIPBOARD_LABEL[p]}</option>)}
      </select>
      <p className="field-hint">Text only. Mooring reads and writes the clipboard itself; the text never passes through this window.</p>
    </div>
  );
}

export function FpsSeg({ name, value, onChange }: { name: string; value: MaxFps; onChange: (v: MaxFps) => void }) {
  return (
    <Seg
      legend="Frame rate cap"
      name={name}
      value={value}
      options={MAX_FPS_VALUES.map((v) => ({ value: v, label: `${String(v)} fps` }))}
      onChange={onChange}
      hint="60 fps doubles the bandwidth on busy screens."
    />
  );
}

/** Extra CA certificates (PEM), off by default; toggling off stores `null`. */
export function CaPemField({ id, value, error, onChange }: { id: string; value: string | null; error: string | undefined; onChange: (v: string | null) => void }) {
  const on = value !== null;
  return (
    <div>
      <label className="flex items-center gap-2 text-[length:var(--fs-13)]">
        <input type="checkbox" checked={on} onChange={(e) => { onChange(e.target.checked ? "" : null); }} />
        Trust an extra certificate authority
      </label>
      {on && (
        <>
          <label className="field-label mt-2" htmlFor={id}>CA certificates (PEM)</label>
          <textarea
            id={id}
            className="field mono h-24 resize-y text-[length:var(--fs-12)]"
            spellCheck={false}
            placeholder="-----BEGIN CERTIFICATE-----"
            aria-invalid={error ? true : undefined}
            aria-describedby={`${id}-hint`}
            value={value}
            onChange={(e) => { onChange(e.target.value); }}
          />
          <p id={`${id}-hint`} className={error ? "field-hint field-problem" : "field-hint"} role={error ? "alert" : undefined}>
            {error ?? "Certificates only, up to 64 KiB. A certificate this CA signed is accepted without a prompt and is not pinned."}
          </p>
        </>
      )}
    </div>
  );
}

/** A fixed fact about the protocol in this release, shown so nobody hunts for a missing setting. */
export function ReadOnly({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="opt-readonly">
      <span className="field-label">{label}</span>
      <span className="text-[length:var(--fs-13)] text-text-muted">{children}</span>
    </div>
  );
}

export function Warn({ children }: { children: ReactNode }) {
  return <p className="settings-warn" role="note">{children}</p>;
}

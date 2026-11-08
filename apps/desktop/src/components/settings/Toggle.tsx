import type { ReactNode } from "react";

/** A labelled switch (native checkbox with role="switch"); the accent when on. */
export function Toggle({ checked, onChange, label, hint, disabled }: {
  checked: boolean;
  onChange: (on: boolean) => void;
  label: string;
  hint?: ReactNode;
  disabled?: boolean;
}) {
  return (
    <label className="toggle" data-on={checked || undefined} data-disabled={disabled || undefined}>
      <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => { onChange(e.target.checked); }} />
      <span className="toggle-track" aria-hidden />
      <span className="min-w-0">
        <span className="toggle-label">{label}</span>
        {hint && <span className="field-hint block">{hint}</span>}
      </span>
    </label>
  );
}

/** Card frame shared by the settings sections. The heading id is the `openSettingsCard` contract. */
export function SettingsCard({ title, children, labelledBy }: { title: string; children: ReactNode; labelledBy: string }) {
  return (
    <section aria-labelledby={labelledBy} className="settings-card">
      <header className="settings-card-head">
        <h2 id={labelledBy} className="settings-card-title">{title}</h2>
      </header>
      {children}
    </section>
  );
}

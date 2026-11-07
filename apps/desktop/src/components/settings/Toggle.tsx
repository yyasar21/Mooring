import type { ReactNode } from "react";

/** A labelled switch (native checkbox with role="switch"); cyan when on. */
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

/** Card frame shared by the settings sections. */
/** `kicker` is optional: A5 cards leave it out (the Harbor redesign drops the micro labels). */
export function SettingsCard({ title, kicker, children, labelledBy }: { title: string; kicker?: string; children: ReactNode; labelledBy: string }) {
  return (
    <section aria-labelledby={labelledBy} className="settings-card m-hud">
      <header className="settings-card-head">
        {kicker && <span className="m-micro">{kicker}</span>}
        <h2 id={labelledBy} className="m-display text-[length:var(--fs-l)]">{title}</h2>
      </header>
      {children}
    </section>
  );
}

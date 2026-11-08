import { useRef, type KeyboardEvent, type ReactNode } from "react";

export const sectionTabId = (base: string, t: string) => `${base}-tab-${t}`;
export const sectionPanelId = (base: string, t: string) => `${base}-panel-${t}`;

/**
 * Section tabs of a details pane (inspector M4, credential detail L2): a `tablist` with a roving
 * tab stop. Left/Right/Home/End move and select (automatic activation: each panel is cheap).
 */
export function SectionTabs<T extends string>({ base, label, tabs, labels, value, onChange }: {
  base: string;
  label: string;
  tabs: readonly T[];
  labels: Record<T, ReactNode>;
  value: T;
  onChange: (t: T) => void;
}) {
  const refs = useRef(new Map<T, HTMLButtonElement>());

  const onKey = (e: KeyboardEvent) => {
    const i = tabs.indexOf(value);
    const next =
      e.key === "ArrowRight" ? tabs[(i + 1) % tabs.length]
        : e.key === "ArrowLeft" ? tabs[(i - 1 + tabs.length) % tabs.length]
          : e.key === "Home" ? tabs[0]
            : e.key === "End" ? tabs[tabs.length - 1]
              : undefined;
    if (next === undefined) return;
    e.preventDefault();
    onChange(next);
    refs.current.get(next)?.focus();
  };

  return (
    <div role="tablist" aria-label={label} className="inspector-tabs" onKeyDown={onKey}>
      {tabs.map((t) => (
        <button
          key={t}
          ref={(el) => { if (el) refs.current.set(t, el); else refs.current.delete(t); }}
          type="button"
          role="tab"
          id={sectionTabId(base, t)}
          aria-selected={value === t}
          aria-controls={sectionPanelId(base, t)}
          tabIndex={value === t ? 0 : -1}
          onClick={() => { onChange(t); }}
        >
          {labels[t]}
        </button>
      ))}
    </div>
  );
}

/** The panel that belongs to a `SectionTabs` tab. */
export function SectionPanel({ base, tab, className, children }: { base: string; tab: string; className?: string; children: ReactNode }) {
  return (
    <div role="tabpanel" id={sectionPanelId(base, tab)} aria-labelledby={sectionTabId(base, tab)} className={className}>
      {children}
    </div>
  );
}

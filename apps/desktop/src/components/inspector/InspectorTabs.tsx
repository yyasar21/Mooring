import { useRef, type KeyboardEvent } from "react";

export type InspectorTab = "properties" | "network" | "history";

const LABEL: Record<InspectorTab, string> = { properties: "Properties", network: "Network", history: "History" };

export const tabId = (base: string, t: InspectorTab) => `${base}-tab-${t}`;
export const panelId = (base: string, t: InspectorTab) => `${base}-panel-${t}`;

/**
 * The inspector's section tabs (M4): a `tablist` with a roving tab stop. Left/Right/Home/End move
 * and select (automatic activation: each panel is cheap to show).
 */
export function InspectorTabs({ base, tabs, value, onChange }: { base: string; tabs: readonly InspectorTab[]; value: InspectorTab; onChange: (t: InspectorTab) => void }) {
  const refs = useRef(new Map<InspectorTab, HTMLButtonElement>());

  const onKey = (e: KeyboardEvent) => {
    const i = tabs.indexOf(value);
    const next =
      e.key === "ArrowRight" ? tabs[(i + 1) % tabs.length]
        : e.key === "ArrowLeft" ? tabs[(i - 1 + tabs.length) % tabs.length]
          : e.key === "Home" ? tabs[0]
            : e.key === "End" ? tabs[tabs.length - 1]
              : undefined;
    if (!next) return;
    e.preventDefault();
    onChange(next);
    refs.current.get(next)?.focus();
  };

  return (
    <div role="tablist" aria-label="Details sections" className="inspector-tabs" onKeyDown={onKey}>
      {tabs.map((t) => (
        <button
          key={t}
          ref={(el) => { if (el) refs.current.set(t, el); else refs.current.delete(t); }}
          type="button"
          role="tab"
          id={tabId(base, t)}
          aria-selected={value === t}
          aria-controls={panelId(base, t)}
          tabIndex={value === t ? 0 : -1}
          onClick={() => { onChange(t); }}
        >
          {LABEL[t]}
        </button>
      ))}
    </div>
  );
}

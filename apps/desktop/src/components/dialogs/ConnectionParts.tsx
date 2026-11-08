import type { ReactNode } from "react";
import { Icon, type IconName } from "@mooring/ui";
import type { Protocol } from "../../lib/ipc";
import { SECTION_LABEL, type ConnSection } from "./connectionForm";

export const PROTOCOLS: { value: Protocol; label: string; port: number | null; icon: IconName }[] = [
  { value: "ssh", label: "SSH", port: 22, icon: "ssh" },
  { value: "rdp", label: "RDP", port: 3389, icon: "rdp" },
  { value: "vnc", label: "VNC", port: 5900, icon: "vnc" },
  { value: "web", label: "Web", port: 443, icon: "web" },
  { value: "kubernetes", label: "Kubernetes", port: null, icon: "kubernetes" },
  { value: "vsphere-console", label: "vSphere console", port: null, icon: "vsphere" },
];

const SECTION_ICON: Record<ConnSection, IconName> = { general: "rdp", signin: "key", gateway: "shield", display: "hosts", advanced: "gear" };

export const sectionHeadingId = (s: ConnSection) => `conn-sec-${s}`;

/** L1: the protocol as radio cards (native radios: arrows move, the group has one tab stop). */
export function ProtocolCards({ value, disabled, onChange }: { value: Protocol; disabled: boolean; onChange: (p: Protocol) => void }) {
  return (
    <fieldset aria-label="Protocol" className="proto-cards" disabled={disabled}>
      <legend className="field-label">Protocol</legend>
      <div className="proto-cards-row">
        {PROTOCOLS.map((p) => (
          <label key={p.value} className="proto-card" data-checked={value === p.value || undefined}>
            <input type="radio" name="conn-proto" value={p.value} checked={value === p.value} onChange={() => { onChange(p.value); }} />
            <Icon name={p.icon} />
            <span>{p.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/**
 * The dialog's left section nav (L1). A click scrolls the section into view and focuses its
 * heading; the item of the section in view carries `aria-current`. A dot marks a section with an
 * error (with a text alternative).
 */
export function SectionNav({ sections, active, invalid, onGo }: {
  sections: ConnSection[];
  active: ConnSection;
  invalid: ReadonlySet<ConnSection>;
  onGo: (s: ConnSection) => void;
}) {
  return (
    <nav aria-label="Connection sections" className="conn-nav">
      <ul>
        {sections.map((s) => (
          <li key={s}>
            <button type="button" aria-current={s === active ? "true" : undefined} onClick={() => { onGo(s); }}>
              <Icon name={SECTION_ICON[s]} />
              <span className="flex-1">{SECTION_LABEL[s]}</span>
              {invalid.has(s) && <span className="conn-nav-err" role="img" aria-label="has errors" />}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** One titled section of the form; its heading is the nav's focus target. */
export function FormSection({ id, title, children }: { id: ConnSection; title?: string; children: ReactNode }) {
  return (
    <section aria-labelledby={sectionHeadingId(id)} data-section={id} className="conn-section">
      <h3 id={sectionHeadingId(id)} tabIndex={-1} className="conn-section-title">{title ?? SECTION_LABEL[id]}</h3>
      {children}
    </section>
  );
}

/** A field's error line, linked from the input with `aria-describedby`. */
export function FieldError({ id, text }: { id: string; text: string | undefined }) {
  if (!text) return null;
  return (
    <p id={id} className="field-error">
      <Icon name="alert" size={14} />
      {text}
    </p>
  );
}

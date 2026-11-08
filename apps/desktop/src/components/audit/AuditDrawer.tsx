import { useEffect, useRef } from "react";
import { Icon } from "@mooring/ui";
import type { AuditEntry } from "../../lib/ipc";

/** How a details key reads in the drawer: "peer_identity" → "Peer identity". */
export function fieldLabel(key: string): string {
  const s = key.replace(/[_.]/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Keys whose values are hosts, ids, fingerprints or hashes: shown in mono. */
const MONO = /^(host|target|fingerprint|peer_identity|id|connection|credential|session|bind|address|reference|prev|hash|path|source)$/;

/**
 * L4: one audit row's structured fields in a drawer beside the table: the event (label and code),
 * local and UTC time, every detail key on its own line with names resolved next to their ids, and
 * the hash link to the previous row. Plain text only; nothing here is a secret (the log redacts).
 */
export function AuditDrawer({ entry, label, names, onClose }: {
  entry: AuditEntry;
  label: string;
  /** Resolved names for id-valued keys (connection, credential). */
  names: Record<string, string | undefined>;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { closeRef.current?.focus({ preventScroll: true }); }, [entry.seq]);
  const at = new Date(entry.at);
  const valid = !Number.isNaN(at.getTime());
  return (
    <aside
      aria-label={`Entry ${String(entry.seq)}`}
      className="audit-drawer"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onClose();
        }
      }}
    >
      <header className="audit-drawer-head">
        <div className="min-w-0 flex-1">
          <p className="t-caption tnum">Entry {entry.seq}</p>
          <h2 className="audit-drawer-title">{label}</h2>
        </div>
        <button ref={closeRef} type="button" className="icon-btn" aria-label="Close entry details" title="Close" onClick={onClose}>
          <Icon name="x" />
        </button>
      </header>
      <dl className="audit-fields">
        <dt>Event code</dt>
        <dd className="mono select-text">{entry.event}</dd>
        <dt>Time (local)</dt>
        <dd className="tnum">{valid ? at.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "medium" }) : entry.at}</dd>
        <dt>Time (UTC)</dt>
        <dd className="mono tnum select-text">{valid ? at.toISOString() : entry.at}</dd>
        {Object.entries(entry.details).map(([k, v]) => (
          <div key={k} className="contents">
            <dt>{fieldLabel(k)}</dt>
            <dd className={MONO.test(k) ? "mono select-text" : "select-text"}>
              {names[k] ? <>{names[k]} <span className="text-text-faint mono">{v}</span></> : v}
            </dd>
          </div>
        ))}
        <dt>Previous hash</dt>
        <dd className="mono select-text audit-hash">{entry.prev}</dd>
      </dl>
    </aside>
  );
}

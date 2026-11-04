/** The vCenter glyph: a datacenter rack of three slots, the bottom one lit. */
export function VcenterIcon({ size = 10 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1" aria-hidden>
      <rect x="1" y="0.5" width="8" height="9" />
      <path d="M1 3.5h8M1 6.5h8" />
      <circle cx="3" cy="8" r="0.6" fill="currentColor" stroke="none" />
    </svg>
  );
}

/**
 * "Synced from <vCenter>" badge for tree rows and inspector headers. `compact` shows only the
 * glyph (child folders of a synced subtree); the full text goes on the root and in the inspector.
 */
export function SyncBadge({ source, compact = false, missing = false }: { source: string; compact?: boolean; missing?: boolean }) {
  const title = missing ? `Synced from ${source}; vCenter no longer reports it` : `Synced from ${source}: read-only, refreshed from vCenter`;
  return (
    <span className="tree-sync" title={title} aria-label={title} role="img">
      <VcenterIcon />
      {!compact && <span>{source}</span>}
    </span>
  );
}

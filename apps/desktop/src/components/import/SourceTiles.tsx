import type { ImportFormat, ImportFormatInfo, KnownLocation } from "../../lib/ipc";
import { KNOWN_LOCATION_TEXT, SOURCE_TILES } from "./importText";

/**
 * The source grid of ADR-0019 §6: one tile per importer, the known-location shortcut under PuTTY
 * and OpenSSH, and the "Directory (LDAPS)" tile reserved for the I2 importer (disabled until its
 * form lands; see `docs/handoff/a4-ui-u1.md`, "Extension point").
 */
export function SourceTiles({ formats, onChoose, onKnown, disabled }: {
  formats: ImportFormatInfo[];
  onChoose: (format: ImportFormat) => void;
  onKnown: (known: KnownLocation) => void;
  disabled?: boolean;
}) {
  return (
    <ul className="imp-tiles" aria-label="Import sources">
      {SOURCE_TILES.map((t) => {
        const info = t.id === "ldaps" ? null : formats.find((f) => f.format === t.id);
        const soon = t.id === "ldaps";
        const known = info?.knownLocation ?? null;
        return (
          <li key={t.id} className="imp-tile" data-soon={soon || undefined}>
            <button
              type="button"
              className="imp-tile-main"
              disabled={disabled || soon}
              aria-describedby={`imp-tile-hint-${t.id}`}
              onClick={() => { if (t.id !== "ldaps") onChoose(t.id); }}
            >
              <span className="imp-tile-mark" aria-hidden>
                <TileGlyph id={t.id} />
              </span>
              <span className="imp-tile-name">{t.label}</span>
              <span id={`imp-tile-hint-${t.id}`} className="imp-tile-hint">
                {soon ? "Coming in this release" : t.hint}
              </span>
            </button>
            {known && (
              <button type="button" className="imp-tile-known" disabled={disabled} onClick={() => { onKnown(known); }}>
                {KNOWN_LOCATION_TEXT[known].button}
              </button>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** One-stroke glyphs: a document for file formats, a tree for the directory. */
function TileGlyph({ id }: { id: string }) {
  if (id === "ldaps") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.2">
        <rect x="6.5" y="1.5" width="5" height="4" />
        <rect x="1.5" y="12.5" width="5" height="4" />
        <rect x="11.5" y="12.5" width="5" height="4" />
        <path d="M9 5.5v3.5M4 12.5V9h10v3.5" />
      </svg>
    );
  }
  if (id === "openssh" || id === "putty") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.2">
        <rect x="1.5" y="3.5" width="15" height="11" />
        <path d="M4.5 7l2.5 2-2.5 2M8.5 11.5h4" />
      </svg>
    );
  }
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.2">
      <path d="M4.5 1.5h6l3.5 3.5v11.5h-9.5z" />
      <path d="M10.5 1.5V5H14M7 9h4M7 12h4" />
    </svg>
  );
}

// Small display formatters shared by settings cards and the inspector.

/** "46.0 MB" / "812 kB" / "1.25 GB"; null when there is no size. */
export function fmtBytes(n: number | null): string | null {
  if (n === null || n < 0 || !Number.isFinite(n)) return null;
  if (n < 1000) return `${String(n)} B`;
  if (n < 1_000_000) return `${(n / 1000).toFixed(0)} kB`;
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  return `${(n / 1_000_000_000).toFixed(2)} GB`;
}

/** "2026-11-20" from RFC 3339, or the raw text when it does not parse; null for null. */
export function fmtDate(iso: string | null): string | null {
  if (iso === null) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toISOString().slice(0, 10);
}

/** "2026-11-06 10:42 UTC" / "never". */
export function fmtStamp(iso: string | null): string {
  if (iso === null) return "never";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : `${new Date(t).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** "42 s ago" / "3 min ago" / "2 h ago" / "5 d ago" for a duration in seconds. */
export function fmtAgo(secs: number): string {
  if (secs < 60) return `${String(Math.round(secs))} s ago`;
  if (secs < 3600) return `${String(Math.round(secs / 60))} min ago`;
  if (secs < 86_400) return `${String(Math.round(secs / 3600))} h ago`;
  return `${String(Math.round(secs / 86_400))} d ago`;
}

/** Milliseconds with one decimal: "4.1 ms". */
export function fmtMs(ms: number): string {
  return `${(Math.round(ms * 10) / 10).toString()} ms`;
}

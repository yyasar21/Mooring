import type { EntryKind } from "../../lib/ipc";

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "?";
  let v = n;
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) {
    v /= 1024;
    u += 1;
  }
  return u === 0 ? `${v} B` : `${v < 10 ? v.toFixed(1) : Math.round(v)} ${UNITS[u] ?? ""}`;
}

/** `drwxr-xr-x` from the kind and `mode & 0o7777`; setuid/setgid/sticky shown as s/s/t. */
export function formatMode(kind: EntryKind, mode: number | null): string {
  const head = kind === "dir" ? "d" : kind === "symlink" ? "l" : kind === "file" ? "-" : "?";
  if (mode === null) return `${head}?????????`;
  const bit = (m: number, c: string) => ((mode & m) !== 0 ? c : "-");
  const x = (exec: number, special: number, on: string, off: string) =>
    (mode & special) !== 0 ? ((mode & exec) !== 0 ? on : off) : bit(exec, "x");
  return (
    head +
    bit(0o400, "r") + bit(0o200, "w") + x(0o100, 0o4000, "s", "S") +
    bit(0o040, "r") + bit(0o020, "w") + x(0o010, 0o2000, "s", "S") +
    bit(0o004, "r") + bit(0o002, "w") + x(0o001, 0o1000, "t", "T")
  );
}

/** Local `YYYY-MM-DD HH:MM` from Unix seconds. */
export function formatMtime(secs: number | null): string {
  if (secs === null) return "";
  const d = new Date(secs * 1000);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function percent(done: number, total: number | null): number | null {
  if (total === null || total <= 0) return null;
  return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
}

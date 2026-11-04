// Decoder for the heterogeneous `sync_status.conflicts` list (ADR-0017 S2 + review 6b L-35).
// Rust serialises it untagged: merge entries `{ kind, id, name, resolution }` followed by trust
// entries `{ kind: "trust", id: "<trust file>", name: "<host:port>" }`. Each entry is checked
// field by field so a shape drift drops the entry instead of crashing the card or the banner.
import type { SyncConflict, SyncConflictKind, SyncMergeConflict, SyncResolution, SyncStatus, SyncTrustConflict } from "./ipc.types.secrets";

const MERGE_KINDS: readonly SyncConflictKind[] = ["folder", "connection", "credential"];

type Wire = Record<string, unknown>;

function rec(v: unknown): Wire | null {
  return typeof v === "object" && v !== null ? (v as Wire) : null;
}

function resolution(raw: unknown): SyncResolution | null {
  const w = rec(raw);
  if (!w) return null;
  switch (w.type) {
    case "keptBoth":
      return typeof w.copyId === "string" ? { type: "keptBoth", copyId: w.copyId } : null;
    case "keptEdit":
      return { type: "keptEdit" };
    case "lastWriterWins":
      return { type: "lastWriterWins" };
    default:
      return null;
  }
}

/** One entry, or null when it is neither a merge nor a trust conflict. */
export function decodeSyncConflict(raw: unknown): SyncConflict | null {
  const w = rec(raw);
  if (!w || typeof w.id !== "string" || typeof w.name !== "string") return null;
  if (w.kind === "trust") {
    const t: SyncTrustConflict = { kind: "trust", id: w.id, name: w.name };
    return t;
  }
  const kind = MERGE_KINDS.find((k) => k === w.kind);
  const res = resolution(w.resolution);
  if (!kind || !res) return null;
  const m: SyncMergeConflict = { kind, id: w.id, name: w.name, resolution: res };
  return m;
}

export function decodeSyncConflicts(raw: unknown): SyncConflict[] {
  if (!Array.isArray(raw)) return [];
  return raw.map(decodeSyncConflict).filter((c): c is SyncConflict => c !== null);
}

/** `sync_status` reply and the `sync:status` payload: the status as sent, with `conflicts` decoded. */
export function decodeSyncStatus(raw: unknown): SyncStatus {
  const w = rec(raw) ?? {};
  return { ...(w as unknown as SyncStatus), conflicts: decodeSyncConflicts(w.conflicts) };
}

export const isTrustConflict = (c: SyncConflict): c is SyncTrustConflict => c.kind === "trust";
export const isMergeConflict = (c: SyncConflict): c is SyncMergeConflict => c.kind !== "trust";

// Defensive decoders for ADR-0010 payloads. The backend is trusted to send camelCase, but channel
// messages and events are decoded field by field so a shape drift never crashes a panel.
import {
  LOCK_REASONS,
  type EntryKind,
  type ForwardInfo,
  type ForwardKind,
  type HostPort,
  type LocalPick,
  type LockReason,
  type SftpEntry,
  type SftpListing,
  type TransferProgress,
  type TransferState,
} from "./ipc.types";

type Wire = Record<string, unknown>;

function rec(v: unknown): Wire {
  return typeof v === "object" && v !== null ? (v as Wire) : {};
}
function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}
function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}
function numOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
/** camelCase first, snake_case as a fallback (channel payloads may use the crate's serde names). */
function pick(w: Wire, camel: string, snake: string): unknown {
  return camel in w ? w[camel] : w[snake];
}

const TRANSFER_STATES: readonly TransferState[] = ["running", "done", "failed", "cancelled"];
const ENTRY_KINDS: readonly EntryKind[] = ["file", "dir", "symlink", "other"];
const FORWARD_KINDS: readonly ForwardKind[] = ["local", "remote", "dynamic"];

/** One `Channel<Progress>` message. An unknown state is treated as a failure, never as done. */
export function decodeProgress(raw: unknown): TransferProgress {
  const w = rec(raw);
  const state = pick(w, "state", "state");
  const known = TRANSFER_STATES.find((s) => s === state);
  const err = w.error;
  return {
    transferId: str(pick(w, "transferId", "transfer_id")),
    bytesDone: num(pick(w, "bytesDone", "bytes_done")),
    bytesTotal: numOrNull(pick(w, "bytesTotal", "bytes_total")),
    state: known ?? "failed",
    error: typeof err === "string" ? err : known ? null : "unrecognised transfer state",
  };
}

/** `sftp_pick_local` reply: null (cancelled) or `{ pickId, name }`. Anything else is a cancel. */
export function decodePick(raw: unknown): LocalPick | null {
  if (raw === null || typeof raw !== "object") return null;
  const w = rec(raw);
  const pickId = str(pick(w, "pickId", "pick_id"));
  if (pickId === "") return null;
  return { pickId, name: str(w.name) };
}

export function decodeEntry(raw: unknown): SftpEntry {
  const w = rec(raw);
  const kind = typeof w.kind === "string" ? w.kind.toLowerCase() : "";
  return {
    name: str(w.name),
    kind: ENTRY_KINDS.find((k) => k === kind) ?? "other",
    size: num(w.size),
    mtime: numOrNull(w.mtime),
    mode: numOrNull(w.mode),
  };
}

export function decodeListing(raw: unknown): SftpListing {
  const w = rec(raw);
  const entries = Array.isArray(w.entries) ? w.entries.map(decodeEntry).filter((e) => e.name !== "") : [];
  return { entries, truncated: w.truncated === true };
}

function hostPort(raw: unknown): HostPort {
  const w = rec(raw);
  return { host: str(w.host), port: num(w.port) };
}

export function decodeForward(raw: unknown): ForwardInfo {
  const w = rec(raw);
  const kind = FORWARD_KINDS.find((k) => k === w.kind) ?? "local";
  return {
    id: str(w.id),
    kind,
    bind: hostPort(w.bind),
    target: w.target === null || w.target === undefined ? null : hostPort(w.target),
    // Anything but an explicit loopback is shown as external: never understate exposure.
    exposure: w.exposure === "loopback" ? "loopback" : "external",
    openedAt: str(pick(w, "openedAt", "opened_at")),
    connections: num(w.connections),
  };
}

/** Payload of the `vault:locked` event. */
export function decodeLockReason(raw: unknown): LockReason | "unknown" {
  const r = rec(raw).reason;
  return LOCK_REASONS.find((x) => x === r) ?? "unknown";
}

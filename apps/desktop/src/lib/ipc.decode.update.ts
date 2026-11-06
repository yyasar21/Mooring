// Wire decoding of `update_check` / `update:available` (ADR-0018 §3, U0): optional manifest
// fields (`date`, `size`) arrive absent or null and are normalised to null; `notes` is kept as the
// plain text Rust sanitised. Nothing else is interpreted.
import type { UpdateAvailable, UpdateInfo, UpdateInstallMode, UpdateManualReason } from "./ipc.types.update";

type Wire = Record<string, unknown>;

const MODES: readonly UpdateInstallMode[] = ["in_app", "manual"];
const REASONS: readonly UpdateManualReason[] = ["package_manager", "homebrew", "not_writable", "not_bundled"];

function rec(v: unknown): Wire {
  return typeof v === "object" && v !== null ? (v as Wire) : {};
}

function decodeAvailable(raw: unknown): UpdateAvailable | null {
  if (typeof raw !== "object" || raw === null) return null;
  const w = raw as Wire;
  return {
    version: typeof w.version === "string" ? w.version : "",
    date: typeof w.date === "string" ? w.date : null,
    notes: typeof w.notes === "string" ? w.notes : "",
    size: typeof w.size === "number" && Number.isFinite(w.size) ? w.size : null,
  };
}

export function decodeUpdateInfo(raw: unknown): UpdateInfo {
  const w = rec(raw);
  const mode = MODES.find((m) => m === w.installMode) ?? "manual";
  const reason = REASONS.find((r) => r === w.manualReason);
  return {
    current: typeof w.current === "string" ? w.current : "",
    available: decodeAvailable(w.available),
    installMode: mode,
    ...(mode === "manual" && reason ? { manualReason: reason } : {}),
    checkedAt: typeof w.checkedAt === "string" ? w.checkedAt : "",
  };
}

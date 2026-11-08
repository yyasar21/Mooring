// Wire decoding of `update_check` / `update:available` (ADR-0018 §3, U0): optional manifest
// fields (`date`, `size`) arrive absent or null and are normalised to null; `notes` is kept as the
// plain text Rust sanitised. `update_settings_get` / `_set` (F2) carry `lastVerified`, a semver
// or null, normalised the same way. Nothing else is interpreted.
import type { UpdateAvailable, UpdateInfo, UpdateInstallMode, UpdateManualReason, UpdateSettings } from "./ipc.types.update";

type Wire = Record<string, unknown>;

const MODES: readonly UpdateInstallMode[] = ["in_app", "manual"];
const REASONS: readonly UpdateManualReason[] = ["package_manager", "homebrew", "not_writable", "not_bundled", "portable", "dev_build", "winget"];

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

/** `update_settings_get` / `update_settings_set`: the two timestamps and the verified floor are strings or null. */
export function decodeUpdateSettings(raw: unknown): UpdateSettings {
  const w = rec(raw);
  return {
    backgroundCheck: w.backgroundCheck === true,
    channel: "stable",
    lastCheck: typeof w.lastCheck === "string" ? w.lastCheck : null,
    lastVerified: typeof w.lastVerified === "string" && w.lastVerified !== "" ? w.lastVerified : null,
  };
}

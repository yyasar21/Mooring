// The only place the UI talks to Rust. Every command is typed here; nothing else calls invoke().
// Secrets: the UI sends a master password once (create/unlock) and never receives one back.
import { invoke } from "@tauri-apps/api/core";

export interface AppInfo {
  name: string;
  version: string;
  os: string;
  arch: string;
  debug: boolean;
}

export type VaultStatus = "missing" | "locked" | "unlocked";

/** Error shape produced by the Rust side (`IpcError` in src-tauri/src/commands.rs). */
export class IpcError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "IpcError";
    this.code = code;
  }
}

function isWireError(e: unknown): e is { code: string; message: string } {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

export function isIpcError(e: unknown): e is IpcError {
  return e instanceof IpcError;
}

/** True when running inside the Tauri WebView (false in plain `vite dev` / vitest). */
export function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e: unknown) {
    if (isWireError(e)) throw new IpcError(e.code, e.message);
    throw new IpcError("ipc.unknown", "the application backend did not answer");
  }
}

export const ipc = {
  appInfo: () => call<AppInfo>("app_info"),
  vaultStatus: () => call<VaultStatus>("vault_status"),
  vaultCreate: (password: string) => call<VaultStatus>("vault_create", { password }),
  vaultUnlock: (password: string) => call<VaultStatus>("vault_unlock", { password }),
  vaultLock: (reason: "user" | "idle" | "screen_lock" | "sleep" = "user") =>
    call<VaultStatus>("vault_lock", { reason }),
};

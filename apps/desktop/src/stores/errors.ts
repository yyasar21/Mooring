import { isIpcError } from "../lib/ipc";

/** Message safe to show; IpcError messages are already scrubbed by Rust (ADR-0003). */
export function errorText(e: unknown): string {
  return isIpcError(e) ? e.message : "unexpected error";
}

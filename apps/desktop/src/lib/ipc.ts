// The only place the UI talks to Rust. Every command is typed here; nothing else calls invoke().
// Secrets cross inward only (vault password, credential secrets, prompt answers); none come back.
// Wire convention: command args are camelCase (Tauri maps them to snake_case parameters);
// session events/inputs use the mooring_core serde shapes (snake_case fields, `kind` tag) with
// byte payloads as base64 strings.
import { Channel, invoke } from "@tauri-apps/api/core";
import type { AuditEntry, Ipc, PromptPurpose, Protocol, SessionEvent, SessionInput } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { MockTransport } from "./ipc.mock";

export * from "./ipc.types";

export { IpcError } from "./ipc.error";

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

// ---------- base64 (Bytes.data on the wire) ----------

export function bytesToBase64(data: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < data.length; i += 0x8000) {
    bin += String.fromCharCode(...data.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- wire <-> UI shapes ----------

type WireRecord = Record<string, unknown>;

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}
function num(v: unknown): number {
  return typeof v === "number" ? v : 0;
}

/** Decode one channel message. Unknown kinds become a `closed` event so the tab never hangs. */
export function decodeSessionEvent(raw: unknown): SessionEvent {
  const w = (typeof raw === "object" && raw !== null ? raw : {}) as WireRecord;
  switch (w.kind) {
    case "connected":
      return {
        kind: "connected",
        protocol: str(w.protocol) as Protocol,
        peerIdentity: typeof w.peer_identity === "string" ? w.peer_identity : null,
      };
    case "bytes":
      return { kind: "bytes", data: base64ToBytes(str(w.data)) };
    case "frame":
      return {
        kind: "frame",
        x: num(w.x),
        y: num(w.y),
        width: num(w.width),
        height: num(w.height),
        rgba: base64ToBytes(str(w.rgba)),
      };
    case "prompt":
      return {
        kind: "prompt",
        id: num(w.id),
        message: str(w.message),
        secret: w.secret === true,
        purpose: promptPurpose(w.purpose),
      };
    case "closed":
      return { kind: "closed", reason: str(w.reason) };
    default:
      return { kind: "closed", reason: "unrecognised session event" };
  }
}

/** Unknown or missing purposes fall back to "other": never the trust dialog. */
function promptPurpose(v: unknown): PromptPurpose {
  return v === "host_key_trust" || v === "keyboard_interactive" ? v : "other";
}

export function encodeSessionInput(input: SessionInput): WireRecord {
  switch (input.kind) {
    case "bytes":
      return { kind: "bytes", data: bytesToBase64(input.data) };
    default:
      return { ...input };
  }
}

/** Audit entries arrive flattened (`seq`, `at`, `prev`, `event`, ...event fields). */
export function decodeAuditEntry(raw: unknown): AuditEntry {
  const w = (typeof raw === "object" && raw !== null ? raw : {}) as WireRecord;
  const details: Record<string, string> = {};
  for (const [k, v] of Object.entries(w)) {
    if (k === "seq" || k === "at" || k === "prev" || k === "event") continue;
    if (v === null || v === undefined) continue;
    details[k] = typeof v === "string" ? v : JSON.stringify(v);
  }
  return { seq: num(w.seq), at: str(w.at), prev: str(w.prev), event: str(w.event), details };
}

// ---------- Tauri transport ----------

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e: unknown) {
    if (isWireError(e)) throw new IpcError(e.code, e.message);
    throw new IpcError("ipc.unknown", "the application backend did not answer");
  }
}

export class TauriTransport implements Ipc {
  appInfo = () => call<Awaited<ReturnType<Ipc["appInfo"]>>>("app_info");
  vaultStatus = () => call<Awaited<ReturnType<Ipc["vaultStatus"]>>>("vault_status");
  vaultCreate: Ipc["vaultCreate"] = (password) => call("vault_create", { password });
  vaultUnlock: Ipc["vaultUnlock"] = (password) => call("vault_unlock", { password });
  vaultLock: Ipc["vaultLock"] = (reason) => call("vault_lock", { reason });
  vaultChangePassword: Ipc["vaultChangePassword"] = (a) => call("vault_change_password", { ...a });

  treeList: Ipc["treeList"] = () => call("tree_list");
  folderCreate: Ipc["folderCreate"] = (a) => call("folder_create", { ...a });
  folderRename: Ipc["folderRename"] = (a) => call("folder_rename", { ...a });
  folderMove: Ipc["folderMove"] = (a) => call("folder_move", { ...a });
  folderSetDefaultCredential: Ipc["folderSetDefaultCredential"] = (a) =>
    call("folder_set_default_credential", { ...a });
  folderDelete: Ipc["folderDelete"] = (a) => call("folder_delete", { ...a });
  connectionCreate: Ipc["connectionCreate"] = (a) => call("connection_create", { ...a });
  connectionUpdate: Ipc["connectionUpdate"] = (a) => call("connection_update", { ...a });
  connectionMove: Ipc["connectionMove"] = (a) => call("connection_move", { ...a });
  connectionDelete: Ipc["connectionDelete"] = (a) => call("connection_delete", { ...a });
  connectionSearch: Ipc["connectionSearch"] = (a) => call("connection_search", { ...a });

  credentialList: Ipc["credentialList"] = () => call("credential_list");
  credentialCreate: Ipc["credentialCreate"] = (a) => call("credential_create", { ...a });
  credentialUpdateMeta: Ipc["credentialUpdateMeta"] = (a) => call("credential_update_meta", { ...a });
  credentialReplaceSecret: Ipc["credentialReplaceSecret"] = (a) => call("credential_replace_secret", { ...a });
  credentialDelete: Ipc["credentialDelete"] = (a) => call("credential_delete", { ...a });
  credentialCopyPassword: Ipc["credentialCopyPassword"] = (a) => call("credential_copy_password", { ...a });

  sessionOpen: Ipc["sessionOpen"] = ({ connectionId, size, onEvent }) => {
    const channel = new Channel<unknown>();
    channel.onmessage = (msg) => {
      onEvent(decodeSessionEvent(msg));
    };
    return call("session_open", { connectionId, size, onEvent: channel });
  };
  sessionSend: Ipc["sessionSend"] = ({ sessionId, input }) =>
    call("session_send", { sessionId, input: encodeSessionInput(input) });
  sessionClose: Ipc["sessionClose"] = (a) => call("session_close", { ...a });
  sessionList: Ipc["sessionList"] = () => call("session_list");

  auditTail: Ipc["auditTail"] = async (a) => {
    const raw = await call<unknown[]>("audit_tail", { ...a });
    return raw.map(decodeAuditEntry);
  };
  auditVerify: Ipc["auditVerify"] = () => call("audit_verify");

  windowDetach: Ipc["windowDetach"] = (a) => call("window_detach", { ...a });
}

function pickTransport(): Ipc {
  return inTauri() ? new TauriTransport() : new MockTransport();
}

/** The process-wide transport. Tests may swap it with `setIpc(new MockTransport())`. */
export let ipc: Ipc = pickTransport();

export function setIpc(next: Ipc): void {
  ipc = next;
}

// The only place the UI talks to Rust. Every command is typed here; nothing else calls invoke().
// Secrets cross inward only (vault password, credential secrets, prompt answers); none come back.
// Wire convention: command args are camelCase (Tauri maps them to snake_case parameters);
// session events/inputs use the mooring_core serde shapes (snake_case fields, `kind` tag) with
// byte payloads as base64 strings.
import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { AuditEntry, Ipc, ProgressHandler, PromptAccount, PromptPurpose, Protocol, SessionEvent, SessionInput } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { MockTransport } from "./ipc.mock";
import { decodeEntry, decodeForward, decodeListing, decodeLockReason, decodePick, decodeProgress } from "./ipc.decode.exit";

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
        account: w.purpose === "credential" ? promptAccount(w.account) : null,
      };
    case "closed":
      return { kind: "closed", reason: str(w.reason) };
    default:
      return { kind: "closed", reason: "unrecognised session event" };
  }
}

/** Unknown or missing purposes fall back to "other": never the trust dialog. */
function promptPurpose(v: unknown): PromptPurpose {
  return v === "host_key_trust" || v === "keyboard_interactive" || v === "credential" ? v : "other";
}

/** `account` of a credential prompt (snake_case on the wire). Missing = ask for everything. */
function promptAccount(raw: unknown): PromptAccount {
  const w = (typeof raw === "object" && raw !== null ? raw : {}) as WireRecord;
  return {
    username: typeof w.username === "string" ? w.username : null,
    domain: typeof w.domain === "string" ? w.domain : null,
    needsUsername: w.needs_username !== false,
    needsDomain: w.needs_domain === true,
  };
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
  connectionSetRoleCredential: Ipc["connectionSetRoleCredential"] = (a) => call("connection_set_role_credential", { ...a });

  credentialKinds: Ipc["credentialKinds"] = () => call("credential_kinds");
  credentialList: Ipc["credentialList"] = () => call("credential_list");
  credentialCreate: Ipc["credentialCreate"] = (a) => call("credential_create", { ...a });
  credentialUpdateFields: Ipc["credentialUpdateFields"] = (a) => call("credential_update_fields", { ...a });
  credentialReplaceSecrets: Ipc["credentialReplaceSecrets"] = (a) => call("credential_replace_secrets", { ...a });
  credentialDelete: Ipc["credentialDelete"] = (a) => call("credential_delete", { ...a });
  credentialCopySecret: Ipc["credentialCopySecret"] = (a) => call("credential_copy_secret", { ...a });
  credentialCopyOtp: Ipc["credentialCopyOtp"] = (a) => call("credential_copy_otp", { ...a });
  credentialParseAccount: Ipc["credentialParseAccount"] = (a) => call("credential_parse_account", { ...a });

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

  // ---------- ADR-0010 ----------

  forwardOpen: Ipc["forwardOpen"] = async (a) => decodeForward(await call<unknown>("forward_open", { ...a }));
  forwardClose: Ipc["forwardClose"] = (a) => call("forward_close", { ...a });
  forwardList: Ipc["forwardList"] = async (a) => (await call<unknown[]>("forward_list", { ...a })).map(decodeForward);

  sftpList: Ipc["sftpList"] = async (a) => decodeListing(await call<unknown>("sftp_list", { ...a }));
  sftpStat: Ipc["sftpStat"] = async (a) => decodeEntry(await call<unknown>("sftp_stat", { ...a }));
  sftpMkdir: Ipc["sftpMkdir"] = (a) => call("sftp_mkdir", { ...a });
  sftpRename: Ipc["sftpRename"] = (a) => call("sftp_rename", { ...a });
  sftpRemove: Ipc["sftpRemove"] = (a) => call("sftp_remove", { ...a });
  sftpPickLocal: Ipc["sftpPickLocal"] = async (a) => decodePick(await call<unknown>("sftp_pick_local", { ...a }));
  sftpDownload: Ipc["sftpDownload"] = ({ onProgress, ...a }) =>
    call("sftp_download", { ...a, onProgress: progressChannel(onProgress) });
  sftpUpload: Ipc["sftpUpload"] = ({ onProgress, ...a }) =>
    call("sftp_upload", { ...a, onProgress: progressChannel(onProgress) });
  sftpTransfers: Ipc["sftpTransfers"] = async (a) => (await call<unknown[]>("sftp_transfers", { ...a })).map(decodeProgress);
  sftpCancel: Ipc["sftpCancel"] = (a) => call("sftp_cancel", { ...a });

  autolockGet: Ipc["autolockGet"] = () => call("autolock_get");
  autolockSet: Ipc["autolockSet"] = (policy) => call("autolock_set", { policy });

  syslogGet: Ipc["syslogGet"] = () => call("syslog_get");
  syslogSet: Ipc["syslogSet"] = (config) => call("syslog_set", { ...config });
  syslogTest: Ipc["syslogTest"] = () => call("syslog_test");

  onVaultLocked: Ipc["onVaultLocked"] = (handler) => {
    let off: (() => void) | null = null;
    let dead = false;
    void listen("vault:locked", (e) => { handler({ reason: decodeLockReason(e.payload) }); }).then((unlisten) => {
      if (dead) unlisten();
      else off = unlisten;
    });
    return () => {
      dead = true;
      off?.();
    };
  };
}

function progressChannel(onProgress: ProgressHandler): Channel {
  const channel = new Channel<unknown>();
  channel.onmessage = (msg) => { onProgress(decodeProgress(msg)); };
  return channel;
}

function pickTransport(): Ipc {
  // Outside Tauri (plain `vite dev`) transfers move slowly enough to watch the progress bars.
  return inTauri() ? new TauriTransport() : new MockTransport({ transferStepMs: 350 });
}

/** The process-wide transport. Tests may swap it with `setIpc(new MockTransport())`. */
export let ipc: Ipc = pickTransport();

export function setIpc(next: Ipc): void {
  ipc = next;
}

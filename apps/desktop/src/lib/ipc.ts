// The only place the UI talks to Rust. Every command is typed here; nothing else calls invoke().
// Secrets cross inward only (vault password, credential secrets, prompt answers); none come back.
// Wire convention: command args are camelCase (Tauri maps them to snake_case parameters);
// session events/inputs use the mooring_core serde shapes (snake_case fields, `kind` tag) with
// byte payloads as base64 strings.
import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { AuditEntry, FrameHandler, Ipc, ProgressHandler, SessionEventHandler } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { MockTransport } from "./ipc.mock";
import { detachedDemoTransport } from "./ipc.mock.demo";
import { bootRoute } from "./route";
import { decodeEntry, decodeForward, decodeListing, decodeLockReason, decodePick, decodeProgress } from "./ipc.decode.exit";
import { decodeKnownCert, decodeSessionEvent, decodeWebEvent, decodeWebWindow, encodeSessionInput, frameBuffer } from "./ipc.decode.session";

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

export { base64ToBytes, bytesToBase64, decodeSessionEvent, encodeSessionInput } from "./ipc.decode.session";

type WireRecord = Record<string, unknown>;

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}
function num(v: unknown): number {
  return typeof v === "number" ? v : 0;
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

/**
 * The only commands the UI may call from a timer (`setInterval`). Each must be passive on the
 * backend (`PASSIVE_COMMANDS` in `src-tauri/src/autolock.rs`): a polled command that counts as
 * activity keeps the idle lock from ever firing (review 4, M-8). A guard test enforces both.
 * `session_frame_ack` is sent per drawn frame (30–60/s, from requestAnimationFrame), so it must
 * never count as activity either (ADR-0011).
 */
export const POLLED_COMMANDS: readonly string[] = ["audit_verify", "forward_list", "session_frame_ack"];

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

  sessionOpen: Ipc["sessionOpen"] = ({ connectionId, size, onEvent, onFrame }) =>
    call("session_open", { connectionId, size, onEvent: eventChannel(onEvent), ...(onFrame ? { onFrame: frameChannel(onFrame) } : {}) });
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
  windowAttach: Ipc["windowAttach"] = (a) => call("window_attach", { ...a });
  sessionAttach: Ipc["sessionAttach"] = ({ sessionId, onEvent, onFrame }) =>
    call("session_attach", { sessionId, onEvent: eventChannel(onEvent), ...(onFrame ? { onFrame: frameChannel(onFrame) } : {}) });

  // ---------- ADR-0011 / ADR-0012 ----------

  sessionFrameAck: Ipc["sessionFrameAck"] = (a) => call("session_frame_ack", { ...a });
  sessionScreenshot: Ipc["sessionScreenshot"] = (a) => call("session_screenshot", { ...a });
  sessionSetViewOnly: Ipc["sessionSetViewOnly"] = (a) => call("session_set_view_only", { ...a });
  connectionOptionsGet: Ipc["connectionOptionsGet"] = (a) => call("connection_options_get", { ...a });
  connectionOptionsSet: Ipc["connectionOptionsSet"] = (a) => call("connection_options_set", { ...a });
  knownCertsList: Ipc["knownCertsList"] = async (a) => (await call<unknown[]>("known_certs_list", { ...a })).map(decodeKnownCert);
  knownCertsRemove: Ipc["knownCertsRemove"] = (a) => call("known_certs_remove", { ...a });

  // ---------- ADR-0013 ----------

  webOpen: Ipc["webOpen"] = ({ connectionId, onEvent }) => {
    const channel = new Channel<unknown>();
    channel.onmessage = (msg) => { onEvent(decodeWebEvent(msg)); };
    return call("web_open", { connectionId, onEvent: channel });
  };
  webClose: Ipc["webClose"] = (a) => call("web_close", { ...a });
  webFocus: Ipc["webFocus"] = (a) => call("web_focus", { ...a });
  webReload: Ipc["webReload"] = (a) => call("web_reload", { ...a });
  webPrint: Ipc["webPrint"] = (a) => call("web_print", { ...a });
  webClearData: Ipc["webClearData"] = (a) => call("web_clear_data", { ...a });
  webZoom: Ipc["webZoom"] = (a) => call("web_zoom", { ...a });
  webList: Ipc["webList"] = async () => (await call<unknown[]>("web_list")).map(decodeWebWindow);

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

function eventChannel(onEvent: SessionEventHandler): Channel {
  const channel = new Channel<unknown>();
  channel.onmessage = (msg) => { onEvent(decodeSessionEvent(msg)); };
  return channel;
}

/** The raw MFR1 channel (ADR-0011): binary bodies arrive as ArrayBuffer; anything else is dropped. */
function frameChannel(onFrame: FrameHandler): Channel {
  const channel = new Channel<unknown>();
  channel.onmessage = (msg) => {
    const buf = frameBuffer(msg);
    if (buf) onFrame(buf);
  };
  return channel;
}

function progressChannel(onProgress: ProgressHandler): Channel {
  const channel = new Channel<unknown>();
  channel.onmessage = (msg) => { onProgress(decodeProgress(msg)); };
  return channel;
}

function pickTransport(): Ipc {
  if (inTauri()) return new TauriTransport();
  // Plain `vite dev`: a detached-window URL gets a demo session behind the detached ACL.
  const route = bootRoute();
  if (route.kind === "detached") return detachedDemoTransport(route.sessionId);
  // Transfers move slowly enough to watch the progress bars; web windows show their notices.
  return new MockTransport({ transferStepMs: 350, webDemo: true });
}

/** The process-wide transport. Tests may swap it with `setIpc(new MockTransport())`. */
export let ipc: Ipc = pickTransport();

export function setIpc(next: Ipc): void {
  ipc = next;
}

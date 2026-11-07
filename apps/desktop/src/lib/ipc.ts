// The only place the UI talks to Rust. Every command is typed here; nothing else calls invoke().
// Secrets cross inward only (vault password, credential secrets, prompt answers); none come back.
// Wire convention: command args are camelCase (Tauri maps them to snake_case parameters);
// session events/inputs use the mooring_core serde shapes (snake_case fields, `kind` tag) with
// byte payloads as base64 strings.
import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { AuditEntry, FrameHandler, Ipc, LogChunkHandler, PodEventHandler, ProgressHandler, SessionEventHandler } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { decodeEntry, decodeForward, decodeListing, decodeLockReason, decodePick, decodeProgress } from "./ipc.decode.exit";
import { decodeAccess, decodeLogChunk, decodeNamespaces, decodePodEvent, decodePodList } from "./ipc.decode.kube";
import { decodeKnownCert, decodeSessionEvent, decodeWebEvent, decodeWebWindow, encodeSessionInput, frameBuffer } from "./ipc.decode.session";
import { decodeSyncStatus } from "./ipc.decode.sync";
import { decodeUpdateInfo, decodeUpdateSettings } from "./ipc.decode.update";

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
export const POLLED_COMMANDS: readonly string[] = [
  "audit_verify", "forward_list", "session_frame_ack",
  // ADR-0014 §6, ADR-0015 §5, ADR-0017 §5: passive by contract.
  "kube_access", "kube_namespaces", "kube_pods", "vsphere_status", "vsphere_vm_power", "sync_status",
  // ADR-0016 §4 (E2): polled every second while an OIDC window is open.
  "secret_source_oidc_status",
];

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

  sessionOpen: Ipc["sessionOpen"] = ({ connectionId, size, onEvent, onFrame, kube }) =>
    call("session_open", { connectionId, size, onEvent: eventChannel(onEvent), ...(onFrame ? { onFrame: frameChannel(onFrame) } : {}), ...(kube ? { kube } : {}) });
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

  // ---------- ADR-0014 (Kubernetes) ----------

  kubeOpen: Ipc["kubeOpen"] = (a) => call("kube_open", { ...a });
  kubeAccess: Ipc["kubeAccess"] = async (a) => decodeAccess(await call<unknown>("kube_access", { ...a }));
  kubeNamespaces: Ipc["kubeNamespaces"] = async (a) => decodeNamespaces(await call<unknown>("kube_namespaces", { ...a }));
  kubePods: Ipc["kubePods"] = async (a) => decodePodList(await call<unknown>("kube_pods", { ...a }));
  kubeWatch: Ipc["kubeWatch"] = ({ onEvent, ...a }) => call("kube_watch", { ...a, onEvent: podChannel(onEvent) });
  kubeUnwatch: Ipc["kubeUnwatch"] = (a) => call("kube_unwatch", { ...a });
  kubeLogs: Ipc["kubeLogs"] = ({ onChunk, ...a }) => call("kube_logs", { ...a, onChunk: logChannel(onChunk) });
  kubeLogsStop: Ipc["kubeLogsStop"] = (a) => call("kube_logs_stop", { ...a });

  // ---------- ADR-0015 (vSphere) ----------

  vsphereTest: Ipc["vsphereTest"] = (a) => call("vsphere_test", { ...a });
  vsphereSyncEnable: Ipc["vsphereSyncEnable"] = (a) => call("vsphere_sync_enable", { ...a });
  vsphereSyncDisable: Ipc["vsphereSyncDisable"] = (a) => call("vsphere_sync_disable", { ...a });
  vsphereRefresh: Ipc["vsphereRefresh"] = (a) => call("vsphere_refresh", { ...a });
  vsphereStatus: Ipc["vsphereStatus"] = (a) => call("vsphere_status", { ...a });
  vsphereVmPower: Ipc["vsphereVmPower"] = (a) => call("vsphere_vm_power", { ...a });
  vsphereVmAction: Ipc["vsphereVmAction"] = (a) => call("vsphere_vm_action", { ...a });
  vsphereVmIdentity: Ipc["vsphereVmIdentity"] = (a) => call("vsphere_vm_identity", { ...a });
  vsphereConsole: Ipc["vsphereConsole"] = (a) => call("vsphere_console", { ...a });

  // ---------- ADR-0016 (external secrets) ----------

  secretSourceList: Ipc["secretSourceList"] = () => call("secret_source_list");
  secretSourceGet: Ipc["secretSourceGet"] = (a) => call("secret_source_get", { ...a });
  secretSourceCreate: Ipc["secretSourceCreate"] = (a) => call("secret_source_create", { ...a });
  secretSourceUpdate: Ipc["secretSourceUpdate"] = (a) => call("secret_source_update", { ...a });
  secretSourceDelete: Ipc["secretSourceDelete"] = (a) => call("secret_source_delete", { ...a });
  secretSourceTest: Ipc["secretSourceTest"] = (a) => call("secret_source_test", { ...a });
  secretSourceRevoke: Ipc["secretSourceRevoke"] = (a) => call("secret_source_revoke", { ...a });
  credentialExternalTest: Ipc["credentialExternalTest"] = (a) => call("credential_external_test", { ...a });
  secretSourceOidcBegin: Ipc["secretSourceOidcBegin"] = (a) => call("secret_source_oidc_begin", { ...a });
  secretSourceOidcStatus: Ipc["secretSourceOidcStatus"] = (a) => call("secret_source_oidc_status", { ...a });

  // ---------- ADR-0017 (vault sync) ----------

  syncConfigure: Ipc["syncConfigure"] = (a) => call("sync_configure", { ...a });
  syncStatus: Ipc["syncStatus"] = () => call<unknown>("sync_status").then(decodeSyncStatus);
  syncNow: Ipc["syncNow"] = () => call("sync_now");
  syncResolveFork: Ipc["syncResolveFork"] = (a) => call("sync_resolve_fork", { ...a });
  syncDisable: Ipc["syncDisable"] = (a) => call("sync_disable", { ...a });
  vaultJoin: Ipc["vaultJoin"] = (a) => call("vault_join", { ...a });
  onSyncStatus: Ipc["onSyncStatus"] = (handler) => subscribe("sync:status", (payload) => { handler(decodeSyncStatus(payload)); });

  // ---------- ADR-0019 (importers, I1) ----------

  importFormats: Ipc["importFormats"] = () => call("import_formats");
  importPick: Ipc["importPick"] = (a) => call("import_pick", { ...a });
  importPreview: Ipc["importPreview"] = (a) => call("import_preview", { ...a });
  importApply: Ipc["importApply"] = (a) => call("import_apply", { ...a });
  importDiscard: Ipc["importDiscard"] = (a) => call("import_discard", { ...a });
  // ---------- ADR-0019 §4 (directory importer, I2) ----------
  ldapImportTest: Ipc["ldapImportTest"] = (a) => call("ldap_import_test", { ...a });
  ldapImportPreview: Ipc["ldapImportPreview"] = (a) => call("ldap_import_preview", { ...a });

  onVaultLocked: Ipc["onVaultLocked"] = (handler) => subscribe("vault:locked", (payload) => { handler({ reason: decodeLockReason(payload) }); });

  // ---------- ADR-0018 §3 (updater, U0) ----------

  updateCheck: Ipc["updateCheck"] = () => call<unknown>("update_check").then(decodeUpdateInfo);
  updateInstall: Ipc["updateInstall"] = (a) => call("update_install", { ...a });
  updateSettingsGet: Ipc["updateSettingsGet"] = () => call<unknown>("update_settings_get").then(decodeUpdateSettings);
  updateSettingsSet: Ipc["updateSettingsSet"] = (a) => call<unknown>("update_settings_set", { ...a }).then(decodeUpdateSettings);
  onUpdateAvailable: Ipc["onUpdateAvailable"] = (handler) => subscribe("update:available", (payload) => { handler(decodeUpdateInfo(payload)); });

  // ---------- ADR-0020 (network tools, N1) ----------

  netTools: Ipc["netTools"] = () => call("net_tools");
  netPortCheck: Ipc["netPortCheck"] = (a) => call("net_port_check", { ...a });
  netPing: Ipc["netPing"] = (a) => call("net_ping", { ...a });
  netTraceroute: Ipc["netTraceroute"] = (a) => call("net_traceroute", { ...a });
  netWgShow: Ipc["netWgShow"] = () => call("net_wg_show");

  // ---------- ADR-0022 (biometric unlock), ADR-0023 (age backups) ----------

  biometricStatus: Ipc["biometricStatus"] = () => call("biometric_status");
  biometricEnroll: Ipc["biometricEnroll"] = (a) => call("biometric_enroll", { ...a });
  biometricUnlock: Ipc["biometricUnlock"] = () => call("biometric_unlock");
  biometricDisable: Ipc["biometricDisable"] = (a) => call("biometric_disable", { ...a });
  vaultExportPick: Ipc["vaultExportPick"] = () => call("vault_export_pick");
  vaultExportAge: Ipc["vaultExportAge"] = (a) => call("vault_export_age", { ...a });
  vaultImportPick: Ipc["vaultImportPick"] = () => call("vault_import_pick");
  vaultImportInspect: Ipc["vaultImportInspect"] = (a) => call("vault_import_inspect", { ...a });
  vaultImportAge: Ipc["vaultImportAge"] = (a) => call("vault_import_age", { ...a });
}

/** Subscribe to a Tauri event; the returned function unsubscribes, also when called before `listen` resolved. */
function subscribe(event: string, handler: (payload: unknown) => void): () => void {
  let off: (() => void) | null = null;
  let dead = false;
  void listen<unknown>(event, (e) => { handler(e.payload); }).then((unlisten) => {
    if (dead) unlisten();
    else off = unlisten;
  });
  return () => {
    dead = true;
    off?.();
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

function podChannel(onEvent: PodEventHandler): Channel {
  const channel = new Channel<unknown>();
  channel.onmessage = (msg) => { onEvent(decodePodEvent(msg)); };
  return channel;
}

function logChannel(onChunk: LogChunkHandler): Channel {
  const channel = new Channel<unknown>();
  channel.onmessage = (msg) => { onChunk(decodeLogChunk(msg)); };
  return channel;
}

/**
 * Outside Tauri the transport arrives with `bootTransport()` (the mock is its own chunk and never
 * ships in the Tauri bundle). Until then every call fails loudly instead of touching `invoke`.
 */
const PENDING: Ipc = new Proxy({} as Ipc, {
  get(_target, prop) {
    if (typeof prop !== "string") return undefined;
    if (prop.startsWith("on")) return () => () => undefined;
    return () => Promise.reject(new IpcError("internal", `transport not ready: ${prop} called before bootTransport()`));
  },
});

/** The process-wide transport. Tests may swap it with `setIpc(new MockTransport())`. */
export let ipc: Ipc = inTauri() ? new TauriTransport() : PENDING;

export function setIpc(next: Ipc): void {
  ipc = next;
}

/**
 * Plain `vite dev` / Playwright: load `MockTransport` as a lazy chunk and install it, unless a
 * transport is already set (`e2e/boot.ts` installs its own before importing `main`). In Tauri
 * this is a no-op and the chunk is never requested.
 */
export async function bootTransport(): Promise<void> {
  if (ipc !== PENDING) return;
  const { devTransport } = await import("./ipc.mock.demo");
  if (ipc === PENDING) ipc = devTransport();
}

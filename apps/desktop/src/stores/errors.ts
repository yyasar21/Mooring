import { isIpcError } from "../lib/ipc";

/** Message safe to show; IpcError messages are already scrubbed by Rust (ADR-0003). */
export function errorText(e: unknown): string {
  return isIpcError(e) ? e.message : "unexpected error";
}

/**
 * Plain-English text for the IpcError codes Rust emits (`src-tauri/ipc-codes.json`, N-14). Codes
 * without an entry (`input.invalid`, `sftp.failed`, `session.failed`, ...) show the scrubbed Rust
 * message, which is a fixed, path-free sentence naming the field or the server's reason.
 */
export const FRIENDLY: Readonly<Record<string, string>> = {
  "vault.locked": "The vault is locked.",
  "session.not_found": "The session has ended. Reconnect to continue.",
  "session.not_connected": "The session is not connected yet.",
  "forward.limit": "This session already has 64 forwards. Close one first.",
  "forward.bind": "The bind address is in use or not permitted, or the server refused the forward. Try another port.",
  "forward.not_found": "That forward is already closed.",
  "sftp.not_found": "No such file or folder on the server.",
  "sftp.denied": "The server denied permission.",
  "sftp.exists": "A file with that name already exists.",
  "transfer.limit": "Too many transfers are running. Wait for one to finish.",
  "transfer.not_found": "That transfer has already finished.",
  "syslog.not_configured": "Save the syslog settings before sending a test entry.",
  "session.trust_rejected": "You rejected the server certificate, so Mooring did not connect. Nothing was stored.",
  "session.trust_mismatch":
    "The server certificate changed since you trusted it, so Mooring stopped. If the server was reinstalled, confirm the new fingerprint with its owner, then remove the stored certificate in Settings → Trust and connect again.",
  "session.unsupported_security":
    "The server offers only security Mooring refuses (for example an old RFB version, or TLS without NLA while that option is off).",
  "protocol.unavailable": "This protocol is not available in this build of Mooring.",
  "ipc.forbidden": "This window is not allowed to do that. Use the main Mooring window.",
  "clipboard.unavailable": "The system clipboard is not available right now.",
  // ADR-0014..0017 (A3): Rust adds these codes with K4/V2/E2/S1.
  "kube.rbac_denied": "The cluster's RBAC does not let this token do that here.",
  "kube.forbidden_request": "Mooring refused to send that request: it would change the cluster, and Mooring is read-only.",
  "kube.unsupported_auth": "This kubeconfig signs in with a method Mooring does not run (exec plugins, auth providers or files).",
  "tree.synced_readonly": "This folder is synced from vCenter and is read-only. Change it in vCenter, then refresh.",
  "vsphere.power_disabled": "Power actions are off for this vCenter. Turn them on in the connection options.",
  "vsphere.tools_missing": "VMware Tools are not running in this VM, so a guest shutdown or reboot is not possible.",
};

export function describeError(e: unknown): string {
  if (!isIpcError(e)) return "unexpected error";
  return FRIENDLY[e.code] ?? e.message;
}

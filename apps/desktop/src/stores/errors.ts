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
  "kube.refused": "Mooring refused to send that request: it would change the cluster, and Mooring is read-only.",
  "kube.unsupported_auth": "This kubeconfig signs in with a method Mooring does not run (exec plugins, auth providers or files).",
  // ADR-0015 (rust-core V2): vSphere sync, power, consoles and the shared HTTP trust codes.
  "tree.synced_readonly": "This folder is synced from vCenter and is read-only. Change it in vCenter, then refresh.",
  "vsphere.auth_failed": "vCenter refused the sign-in. Check the vsphere_user credential (user@domain) and its password.",
  "vsphere.forbidden": "vCenter denied this request: the account lacks the privilege.",
  "vsphere.not_found": "vCenter does not know this item any more, or inventory sync is not enabled for this connection.",
  "vsphere.too_large": "The inventory is larger than Mooring imports (64 datacenters, 512 clusters, 2 000 hosts, 5 000 VMs). Nothing was written.",
  "vsphere.power_disabled": "Power actions are off for this vCenter. Turn them on in the connection options.",
  "vsphere.power_denied": "vCenter refused the power action: the account may not change this VM's power state.",
  "vsphere.tools_missing": "VMware Tools are not running in this VM, so a guest shutdown or reboot is not possible.",
  "vsphere.wrong_state": "The VM is not in a state that allows this action (for example a guest shutdown of a VM that is off).",
  "vsphere.not_confirmed": "You did not confirm the action in the dialog, so nothing was done.",
  "vsphere.busy": "Another action is still running on this VM. Wait for it to finish.",
  "vsphere.unavailable": "vCenter did not answer. Check the host, port and network, then try again.",
  "vsphere.vmrc_disabled": "VMware Remote Console hand-off is off for this vCenter. Turn it on in the connection options.",
  "vsphere.vmrc_unavailable": "vCenter did not issue a VMware Remote Console ticket for this VM.",
  "vsphere.invalid": "vCenter answered with data Mooring could not read.",
  "vsphere.failed": "vCenter reported an error for this request.",
  // ADR-0016 (E2): secret sources and external references.
  "source.not_found": "That secret source no longer exists.",
  "source.in_use": "A credential still references this source. Point those external references at another source or delete them first.",
  "credential.in_use": "A secret source signs in with this credential. Change the source's credential first.",
  "credential.external_unavailable": "Mooring could not fetch the secret from the source. Nothing is cached, so the connection was not attempted. Test the source in Settings → Secret sources.",
  "credential.external_shape": "The secret exists but does not have the fields the target kind needs. Check the reference, the field map and the KV keys.",
  "credential.external_not_found": "The secret, or the pinned version, does not exist (or was deleted) at that reference.",
  "credential.external_root_token": "The source's token has the root policy. Mooring refuses root tokens; use a token or role with the policies it needs.",
  "window.failed": "The sign-in window could not be opened.",
  // ADR-0017 (S2): vault sync.
  "sync.not_configured": "Vault sync is not configured. Set it up in Settings → Vault sync.",
  "sync.in_progress": "A sync is already running. Wait for it to finish.",
  "sync.cancelled": "You cancelled the confirmation, so nothing was changed.",
  "sync.fork": "Two devices published the same generation (a fork). Choose which copy to keep in Settings → Vault sync.",
  "sync.rollback": "The bucket holds an older generation than this device has seen. Nothing was applied; resolve it in Settings → Vault sync.",
  "sync.conflict": "Another device pushed while this sync ran. Nothing was applied; run Sync now again.",
  "sync.backend_unsupported": "Only S3-compatible storage is supported.",
  "sync.unsupported_backend": "This storage does not honour conditional writes (If-None-Match / If-Match), which sync needs to detect concurrent pushes. Use AWS S3, MinIO or Ceph RGW.",
  "sync.store_not_empty": "This device already holds data. Joining is only possible on a fresh device.",
  "sync.wrong_vault": "The bucket does not hold a vault with that id under that prefix.",
  "sync.tampered": "The synced blob failed verification. It was not applied.",
  "sync.header_mismatch": "The synced vault's password changed on another device. Sync stops until this device adopts the new password.",
  "sync.keyring_header": "Sync is not available while the vault is wrapped in the system keyring.",
  "sync.too_large": "The vault is too large to sync (64 MiB limit).",
  // Shared by the vCenter (ADR-0015) and sync (ADR-0017) HTTP clients.
  "http.trust_prompt": "The server's certificate is not trusted yet. Run Refresh now or Sync now to review and trust it; background runs cannot ask.",
  "http.trust_rejected": "You rejected the server's certificate, so Mooring did not connect. Nothing was stored.",
  "http.trust_mismatch":
    "The server's certificate changed since you trusted it, so Mooring stopped. Confirm the new fingerprint with its owner, then remove the stored certificate in Settings → Trust and try again.",
  "http.trust_store": "Mooring could not read or write its certificate trust store.",
  "http.tls": "The TLS handshake with the server failed.",
};

/** The friendly text for a bare error code (status fields carry codes, not messages). */
export function describeCode(code: string): string {
  return FRIENDLY[code] ?? code;
}

export function describeError(e: unknown): string {
  if (!isIpcError(e)) return "unexpected error";
  return FRIENDLY[e.code] ?? e.message;
}

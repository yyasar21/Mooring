import { isIpcError } from "../lib/ipc";
import { SMART_CARD_RDP } from "../lib/credentials";

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
  // Native confirmation dialogs (security review 6, M-16).
  "confirm.busy": "Another confirmation dialog is already open. Answer it first.",
  "confirm.cooldown": "You cancelled this action a moment ago. Wait a few seconds before asking again.",
  // Shared by the vCenter (ADR-0015) and sync (ADR-0017) HTTP clients.
  "http.trust_prompt": "The server's certificate is not trusted yet. Run the action again from the app (Refresh now, Sync now or Test bind) to review and trust it; background runs cannot ask.",
  "http.trust_rejected": "You rejected the server's certificate, so Mooring did not connect. Nothing was stored.",
  "http.trust_mismatch":
    "The server's certificate changed since you trusted it, so Mooring stopped. Confirm the new fingerprint with its owner, then remove the stored certificate in Settings → Trust and try again.",
  // Review 6b, L-35: conflicting pins after a sync merge fail closed (no prompt, no retry).
  "http.trust_conflict":
    "This host has two different trusted certificates (synced from another device). Remove one in Settings → Trust before connecting.",
  "http.trust_store": "Mooring could not read or write its certificate trust store.",
  "http.tls": "The TLS handshake with the server failed.",
  // ADR-0018 §3 (U0): in-app updater.
  "update.unconfigured": "Updates are not configured in this build.",
  "update.busy": "An update check or install is already running. Wait for it to finish.",
  "update.rate_limited": "You checked a moment ago. Wait a minute before checking again.",
  "update.network": "The update server did not answer. Check the network and try again.",
  "update.manifest": "The update manifest could not be read. Try again later.",
  "update.signature": "The update's signature did not verify, so nothing was installed.",
  "update.none": "There is no newer version, or the offered version changed. Check again.",
  "update.manual_only": "This install is managed by a package manager or Homebrew. Update it there.",
  "update.not_writable": "The installed application is not writable by your user, so Mooring cannot replace it. Reinstall from the release page.",
  "update.sessions_open": "Sessions are still open. Close them, or confirm closing them, before installing.",
  "update.install_failed": "The update was verified but could not be written. Nothing changed; try again or install from the release page.",
  // Security review 7, L-39 (F2): the offered version is below the highest package this install already verified.
  "update.downgrade": "The offered version is older than an update this install already verified, so Mooring refused it. Nothing was installed; check again later.",
  // ADR-0020 (N1): network tools.
  "net.invalid_host": "That is not a valid host name or address, or this connection has no network host to probe.",
  "net.tool_missing": "That tool was not found on this system. Mooring only runs the OS tools at their usual paths.",
  "net.permission_denied": "WireGuard status needs elevated rights; Mooring does not elevate.",
  "net.busy": "Two network tools are already running. Wait for one to finish.",
  "net.rate_limited": "One port check per second. Try again in a moment.",
  "net.spawn": "The tool could not be started.",
  // ADR-0019 (I1): file importers. Every message is content-free; the file stays on disk untouched.
  "import.too_large": "This file is larger than 16 MiB, which is more than Mooring imports. Export a smaller set.",
  "import.format": "Mooring could not read this file as that tool's export. Check that the right tool is selected and the export is complete.",
  "import.encrypted": "This file is encrypted. Export it unencrypted from the source tool, then import it again.",
  "import.doctype": "This XML file declares a DOCTYPE, which Mooring refuses. Export it again without one.",
  "import.limits": "This file exceeds an import limit (20 000 connections, 5 000 folders, 2 000 credentials, or the decompressed size). Split the export.",
  "import.unsupported_container": "This file is a ZIP archive. Unpack it first and import the export inside.",
  "import.plan_expired": "The preview expired or was already used. Preview the file again.",
  "import.not_found": "Nothing to import at that location on this computer.",
  // ADR-0019 §4 (I2): the LDAPS directory importer. Content-free: no DN, bind name or host from the server.
  "ldap.insecure": "Only ldaps:// is supported. Mooring never talks to a directory without TLS from the first byte (StartTLS included); use the LDAPS port, usually 636.",
  "ldap.invalid": "The server URL or the size limit is not valid. Use ldaps://host[:port] and a limit between 1 and 5 000.",
  "ldap.dn_invalid": "The base DN is not a valid distinguished name, or the directory has no such entry. Check it against the directory, for example DC=corp,DC=example,DC=test.",
  "ldap.bind": "The directory refused the sign-in. Check the credential's user, domain and password; the account must be allowed to read the directory.",
  "ldap.size_limit": "The search matched more entries than the size limit allows, so nothing was imported. Narrow the base DN or the name filter, search one level only, or raise the limit (up to 5 000).",
  "ldap.timeout": "The directory did not finish answering within 30 seconds. Narrow the search, or try again when the directory is less busy.",
  "ldap.unavailable": "The directory server did not answer. Check the host, the port (usually 636) and the network, then try again.",
  "ldap.response": "The directory sent a reply Mooring could not read, so it stopped. Nothing was imported.",
  // Security review 7, L-43 (F2): the native "Directory sign-in" confirmation before the first bind.
  "ldap.bind_declined": "You did not confirm the sign-in to the directory, so Mooring did not send the credential. Nothing was searched; try again and choose \"Sign in\" to continue.",
  "ldap.confirm_required": "The sign-in to the directory needs a confirmation dialog, and none could be shown here. Run the import again from the main window.",
  // ADR-0025 (R1): jump hosts.
  "connection.via_invalid":
    "That jump host chain is not allowed. Use at most 3 SSH connections, each once, not this connection itself, and no chain that leads back here. vCenter connections cannot use jump hosts.",
  "connection.in_use_as_hop": "Another connection uses this one as a jump host, so it was not deleted. Remove it from that connection's “Connect via” list first.",
  "session.hop_failed": "A jump host of this connection cannot be used: it is missing, it is not an SSH connection, or its credential is an external reference.",
  "web.via_unsupported": "Web connections cannot open through a jump host yet. Remove the jump hosts from this connection to open it.",
  "vault.unlock": "The master password is wrong.",
  // ADR-0022 (R2): biometric unlock.
  "biometric.unavailable": "Biometric unlock is not available on this device.",
  "biometric.cancelled": "The system prompt was cancelled. Nothing changed.",
  "biometric.failed": "The system could not verify you. Use the master password.",
  "biometric.suspended": "Biometric unlock was turned off for safety. Unlock with the master password, then turn it on again in Settings → Security.",
  "biometric.not_enrolled": "Biometric unlock is not set up for this vault. Unlock with the master password.",
  "biometric.sync_enabled": "Biometric unlock is not available while vault sync is configured.",
  // ADR-0023 (R2): age backups. Messages name no path.
  "vault.export": "The backup could not be written there. Nothing was changed; choose another location.",
  "vault.export_passphrase": "The backup passphrase must be at least 12 characters and differ from the master password.",
  "vault.import_format": "This file is not a Mooring backup, or it is damaged. Nothing was imported.",
  "vault.import_passphrase": "That passphrase does not open this backup. Check it and try again.",
  "vault.import_source_password": "That is not the master password of the vault this backup came from.",
  "vault.import_too_large": "This file is larger than 64 MiB, which is more than a Mooring backup can be.",
  "vault.import_version": "This backup was made in an older format that cannot be imported. Export it again from a current Mooring.",
  // ADR-0026 (R3): dynamic Vault engines, 1Password Connect and Bitwarden `bws`.
  "credential.external_engine":
    "This reference cannot be used that way: an SSH sign reference only certifies an SSH key, and the other engines fill their own target kind. Check the engine and where the credential is used.",
  "secret.lease_failed":
    "Vault did not hand out a lease for the dynamic credential, so Mooring did not use it and did not connect. Check the role in Vault, then connect again.",
  "secret.tool_missing": "bws was not found at the locations Mooring checks. Install the Bitwarden Secrets Manager CLI there, or choose its location in Settings → Secret sources.",
  "secret.tool_version": "The bws found is older than 1.0. Install a current Bitwarden Secrets Manager CLI.",
  "secret.tool_failed": "bws did not finish: it failed, timed out or printed something Mooring could not read. Test the source in Settings → Secret sources.",
  "source.kind_unsupported": "This reference's provider does not match its secret source. Choose a source of the same provider.",
  // ADR-0024 (R4): FIDO2 security keys.
  "credential.use_sk_kind": "This is a security-key key — create a Security key (FIDO2) credential instead.",
  "ssh.sk_key_not_in_agent":
    "The security key is not in your ssh-agent, or no ssh-agent is running, so Mooring did not connect. Add the key to your ssh-agent: ssh-add -K or ssh-add <handle file>.",
  "ssh.sk_helper_disabled":
    "This credential signs with ssh-sk-helper, which is turned off. Switch the credential's signing to ssh-agent and add the key to your agent.",
  "ssh.sk_helper_missing": "ssh-sk-helper was not found at its fixed path on this system. Sign through ssh-agent instead.",
  // ADR-0027 (R5): RD Gateway and smart cards.
  "rdp.gateway_auth":
    "The RD Gateway refused the credentials. Check the RD Gateway credential of this connection (a user and password or a Windows domain account), or choose Same as sign-in.",
  "rdp.gateway_refused": "The RD Gateway refused the tunnel or the channel to this computer. Ask the gateway's administrator whether you may reach it through the gateway.",
  "rdp.gateway_unsupported": "No RD Gateway WebSocket endpoint (RPC over HTTP gateways are not supported). The gateway needs Windows Server 2016 or later.",
  "rdp.smart_card_unsupported": SMART_CARD_RDP,
  "ssh.piv_key_not_in_agent":
    "The smart card key is not in your ssh-agent, and Mooring cannot load it without a PKCS#11 module. Load the card with ssh-add -s <module>, or choose the module in the credential so Mooring asks the PIN.",
  "credential.incompatible":"That credential cannot be used here. Pick a Windows domain or a user and password credential.",
  "credential.not_found": "That credential no longer exists. Pick another one.",
};

/** The friendly text for a bare error code (status fields carry codes, not messages). */
export function describeCode(code: string): string {
  return FRIENDLY[code] ?? code;
}

/**
 * Codes whose Rust message is the authoritative reason (one fixed, safe sentence per variant)
 * and would be lost behind a single friendly text: `update.manual_only` covers package
 * manager, Homebrew, not-bundled and portable (ADR-0021 §2). The friendly text is the
 * fallback when the message is empty.
 */
const MESSAGE_WINS: ReadonlySet<string> = new Set(["update.manual_only"]);

export function describeError(e: unknown): string {
  if (!isIpcError(e)) return "unexpected error";
  if (MESSAGE_WINS.has(e.code) && e.message.trim() !== "") return e.message;
  // ADR-0027: the matrix refuses a smart card on RDP as `credential.incompatible` with the PKINIT sentence.
  if (e.code === "credential.incompatible" && /PKINIT/.test(e.message)) return SMART_CARD_RDP;
  return FRIENDLY[e.code] ?? e.message;
}

import { isIpcError } from "../lib/ipc";

/** Message safe to show; IpcError messages are already scrubbed by Rust (ADR-0003). */
export function errorText(e: unknown): string {
  return isIpcError(e) ? e.message : "unexpected error";
}

/**
 * Plain-English text for the IpcError codes the ADR-0010 panels expect. Unknown codes and
 * `input.invalid` fall back to the scrubbed Rust message, which names the offending field.
 */
const FRIENDLY: Record<string, string> = {
  "vault.locked": "The vault is locked.",
  "session.not_found": "The session has ended. Reconnect to continue.",
  "session.failed": "The session is not connected yet.",
  "session.unsupported": "Only SSH sessions forward ports and transfer files.",
  "forward.limit": "This session already has 64 forwards. Close one first.",
  "forward.bind_failed": "The bind address is in use or not permitted. Try another port.",
  "forward.refused": "The server refused the forward.",
  "forward.not_found": "That forward is already closed.",
  "sftp.not_found": "No such file or folder on the server.",
  "sftp.permission": "The server denied permission.",
  "sftp.exists": "Something with that name already exists.",
  "sftp.not_empty": "The folder is not empty. Only empty folders can be removed.",
  "sftp.not_a_directory": "That is not a folder.",
  "sftp.not_a_file": "Only regular files can be transferred.",
  "sftp.local_path": "The local location was refused. Pick it again in the file dialog.",
  "sftp.transfer_not_found": "That transfer has already finished.",
  "syslog.not_configured": "Save the syslog settings before sending a test entry.",
};

export function describeError(e: unknown): string {
  if (!isIpcError(e)) return "unexpected error";
  return FRIENDLY[e.code] ?? e.message;
}

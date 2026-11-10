// Display names of audit event codes, and the local time format of the audit views.

export const EVENT_LABEL: Record<string, string> = {
  vault_created: "Vault created",
  vault_unlocked: "Vault unlocked",
  vault_locked: "Vault locked",
  password_changed: "Master password changed",
  credential_used: "Credential used",
  credential_copied: "Secret copied",
  credential_otp_attached: "TOTP seed attached",
  credential_prompted: "Asked for sign-in",
  session_opened: "Session opened",
  session_closed: "Session closed",
  vault_exported: "Vault exported",
  trust_decision: "Host trust decision",
  "vault.lock": "Vault locked",
  "vault.policy_changed": "Auto-lock policy changed",
  "session.forward.open": "Forward opened",
  "session.forward.close": "Forward closed",
  "session.sftp.transfer": "File transfer",
  "audit.syslog_changed": "Syslog mirror changed",
  "app.start": "Application started",
  // ADR-0024: FIDO2 security keys (fingerprint and backend only).
  "credential.sk_converted": "SSH key converted to a security-key credential",
  "session.auth_sk": "Security-key sign-in",
  // ADR-0027: RD Gateway and smart cards (host, auth method and outcome; never a PIN).
  "session.rdp.gateway": "RD Gateway sign-in",
  "session.rdp.gateway_basic": "RD Gateway used Basic authentication",
  "credential.pin_prompted": "Smart card PIN asked",
  // L-50: the bws binary no longer matched its pin and was not run.
  "secret.tool_changed": "bws binary changed: refused until the source is tested",
  // L-48: the web-via proxy refused a destination outside the start host and allowed origins.
  forward_refused: "Web proxy refused a destination outside the allowed origins",
  // Harbor W3: the audit log itself was exported (format and count; no path, no filter).
  "audit.exported": "Audit log exported",
  "portable.acl_unavailable": "Portable data folder: owner-only ACL could not be applied (FAT/exFAT or policy)",
};

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

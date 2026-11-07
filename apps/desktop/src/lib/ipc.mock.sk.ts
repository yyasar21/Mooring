// Mock ADR-0024 security keys as rust-core R4 serves them: the `ssh_sk_key` field rules (derived
// `fingerprint` / `application`, `resident` as a boolean, `backend` defaulting to `agent`), the
// `credential.use_sk_kind` refusal of `sk-*` material in an `ssh_key`, the connect pre-flight and
// the touch events. Knobs: whether the "agent" holds the key, how the "user" answers the touch.
import type { CredentialFields, CredentialKind, SessionEventHandler } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { isSkMaterial, parseSkPublicLine } from "./credentials.sk";
import { fakeFingerprint } from "./ipc.mock.creds";

const str = (v: unknown) => (typeof v === "string" ? v : "");

/** `ssh_key` refuses `sk-*` material in the public key, the certificate and the private key (R4). */
export function refuseSkInSshKey(kind: CredentialKind, fields: CredentialFields, secrets: Record<string, string>): void {
  if (kind !== "ssh_key") return;
  if ([str(fields.public_key), str(fields.certificate), secrets.private_key ?? ""].some(isSkMaterial)) {
    throw new IpcError("credential.use_sk_kind", "this is a FIDO2 security key; create an SSH security key (FIDO2) credential");
  }
}

/** Derived fields of an `ssh_sk_key` (refused on input, like Rust's `DERIVED_KEYS`). */
export function deriveSk(fields: CredentialFields): CredentialFields {
  const parsed = parseSkPublicLine(str(fields.public_key));
  if (!parsed.key) throw new IpcError("input.invalid", `public_key: ${parsed.problem ?? "required"}`);
  const out: CredentialFields = { ...fields, backend: str(fields.backend) || "agent" };
  if (out.resident === "true") out.resident = true;
  else delete out.resident;
  out.application = parsed.key.application;
  out.fingerprint = fakeFingerprint(str(fields.public_key).trim().split(/\s+/)[1] ?? "");
  return out;
}

/** How the mock security key behaves at connect. */
export interface MockSkKnobs {
  /** The ssh-agent holds the key (false → `ssh.sk_key_not_in_agent` before any I/O). */
  agentHolds: boolean;
  /** The user touches the key, or lets the 30 s pass. */
  touch: "touch" | "timeout";
  /** Delay before the touch (or the timeout) happens. */
  touchMs: number;
}

export const DEFAULT_SK_KNOBS: MockSkKnobs = { agentHolds: true, touch: "touch", touchMs: 1500 };

/** `sk_keys::preflight`: refuse before connecting. */
export function skPreflight(fields: CredentialFields, knobs: MockSkKnobs): void {
  if (fields.backend === "helper") {
    throw new IpcError("ssh.sk_helper_disabled", "the ssh-sk-helper backend is turned off; use the ssh-agent or turn on sshSkHelper");
  }
  if (!knobs.agentHolds) {
    const why = `security key ${str(fields.fingerprint)} is not in ssh-agent; run \`ssh-add -K\` for a resident key or \`ssh-add ~/.ssh/id_ed25519_sk\``;
    throw new IpcError("ssh.sk_key_not_in_agent", why);
  }
}

/** `SkSigner::sign`: touch_required, then touch_cleared + connected, or touch_timeout + closed. */
export function signWithTouch(
  emit: SessionEventHandler,
  fingerprint: string,
  knobs: MockSkKnobs,
  done: (ok: boolean) => void,
): void {
  const id = 7;
  emit({ kind: "touch_required", id, fingerprint, timeoutSeconds: 30 });
  setTimeout(() => {
    if (knobs.touch === "touch") {
      emit({ kind: "touch_cleared", id });
      done(true);
    } else {
      emit({ kind: "touch_timeout", id });
      done(false);
    }
  }, knobs.touchMs);
}

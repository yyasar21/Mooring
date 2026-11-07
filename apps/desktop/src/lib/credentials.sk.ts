// ADR-0024 FIDO2 (`sk-*`) key helpers for instant feedback. Shape checks only: Rust parses the
// key, derives `fingerprint` / `application` and decides. Public material only; a key-handle
// file is looked at only to tell whether it holds an `sk-*` key (its type name is in clear text).
import { base64ToBytes } from "./ipc.decode.session";

export const SK_KEY_TYPES = ["sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"] as const;
export type SkKeyType = (typeof SK_KEY_TYPES)[number];
const SK_CERT_TYPES = ["sk-ssh-ed25519-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"] as const;

export const SK_TYPE_LABEL: Record<SkKeyType, string> = {
  "sk-ssh-ed25519@openssh.com": "Ed25519 security key",
  "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA P-256 security key",
};

/** Rust caps (`credential::sk_key`): blob 4 KiB, application 256 B. */
const MAX_BLOB = 4096;
const MAX_APPLICATION = 256;

const LINE = /^([a-z0-9@.-]+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+(.*))?$/;

export interface SkPublicKey {
  type: SkKeyType;
  /** FIDO application read from the blob (`ssh:` by default). */
  application: string;
  comment: string;
}

/** Reads SSH wire strings from a blob; null on any overrun. */
function wireStrings(blob: Uint8Array, count: number): Uint8Array[] | null {
  const out: Uint8Array[] = [];
  let at = 0;
  for (let i = 0; i < count; i++) {
    if (at + 4 > blob.length) return null;
    const len = ((blob[at] ?? 0) << 24) | ((blob[at + 1] ?? 0) << 16) | ((blob[at + 2] ?? 0) << 8) | (blob[at + 3] ?? 0);
    at += 4;
    if (len < 0 || at + len > blob.length) return null;
    out.push(blob.subarray(at, at + len));
    at += len;
  }
  return at === blob.length ? out : null;
}

const dec = new TextDecoder();

/** Parse one `sk-*` public key line, or explain what is wrong with it (null problem = ok). */
export function parseSkPublicLine(line: string): { key: SkPublicKey | null; problem: string | null } {
  const t = line.trim();
  if (t === "") return { key: null, problem: null };
  if (/[\r\n]/.test(t)) return { key: null, problem: "Paste one public key line (the contents of the .pub file)." };
  const m = LINE.exec(t);
  const type = m?.[1] ?? "";
  if (!m || !(SK_KEY_TYPES as readonly string[]).includes(type)) {
    if (/^(ssh-|ecdsa-)/.test(type)) return { key: null, problem: "This is a regular SSH key, not a security key. Use the SSH key kind for it." };
    if ((SK_CERT_TYPES as readonly string[]).includes(type)) return { key: null, problem: "This is a certificate. Paste it under OpenSSH certificate, and the key's .pub line here." };
    return { key: null, problem: "Expected an sk-ssh-ed25519@openssh.com or sk-ecdsa-sha2-nistp256@openssh.com line." };
  }
  let blob: Uint8Array;
  try {
    blob = base64ToBytes(m[2] ?? "");
  } catch {
    return { key: null, problem: "The key data is not valid base64." };
  }
  if (blob.length > MAX_BLOB) return { key: null, problem: "The key data is longer than 4 KiB." };
  const parts = wireStrings(blob, type === "sk-ssh-ed25519@openssh.com" ? 3 : 4);
  const [name] = parts ?? [];
  const app = parts?.[parts.length - 1];
  if (!parts || !name || dec.decode(name) !== type || !app) return { key: null, problem: "The key data does not match its type." };
  const application = dec.decode(app);
  if (!application.startsWith("ssh:") || app.length > MAX_APPLICATION) return { key: null, problem: "The key's FIDO application must start with ssh:." };
  return { key: { type: type as SkKeyType, application, comment: m[3]?.trim() ?? "" }, problem: null };
}

/** Shape of an optional `sk-*` OpenSSH certificate line. */
export function skCertificateProblem(line: string): string | null {
  const t = line.trim();
  if (t === "") return null;
  if (/[\r\n]/.test(t)) return "Paste one certificate line (the contents of the -cert.pub file).";
  const type = LINE.exec(t)?.[1] ?? "";
  return (SK_CERT_TYPES as readonly string[]).includes(type) ? null : "Expected an sk-…-cert-v01@openssh.com certificate of this security key.";
}

const OPENSSH_PEM = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/;

/**
 * Does this text carry `sk-*` key material: a public or certificate line, or an OpenSSH key file
 * whose (clear-text) key type is `sk-*`? Used to route a paste and to explain `credential.use_sk_kind`.
 */
export function isSkMaterial(text: string): boolean {
  const t = text.trim();
  if (/^sk-(ssh-ed25519|ecdsa-sha2-nistp256)(-cert-v01)?@openssh\.com\s/.test(t)) return true;
  const pem = OPENSSH_PEM.exec(t);
  if (!pem) return false;
  try {
    // The header (magic, cipher, kdf, public key) sits in the first few hundred bytes.
    const head = base64ToBytes((pem[1] ?? "").replace(/\s+/g, "").slice(0, 1024));
    const s = dec.decode(head);
    return s.startsWith("openssh-key-v1") && /sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com/.test(s);
  } catch {
    return false;
  }
}

/** `SHA256:0f/IntG4…rdDv4`: the start and end of a fingerprint, for a banner. */
export function shortFingerprint(fp: string): string {
  const i = fp.indexOf(":");
  const algo = i >= 0 ? fp.slice(0, i + 1) : "";
  const rest = i >= 0 ? fp.slice(i + 1) : fp;
  return rest.length <= 14 ? fp : `${algo}${rest.slice(0, 8)}…${rest.slice(-5)}`;
}

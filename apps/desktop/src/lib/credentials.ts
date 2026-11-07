// Pure credential helpers (ADR-0009). No IPC, no state: used by the forms, the pickers and the
// mock transport. The Rust side is authoritative; these mirror its rules for instant feedback.
import type {
  ConnectionSummary,
  CredentialKind,
  CredentialMeta,
  CredentialRole,
  FieldSchema,
  KindSchema,
  ParsedAccount,
  Protocol,
} from "./ipc.types";

const enc = new TextEncoder();

export function utf8Bytes(s: string): number {
  return enc.encode(s).length;
}

// ---------- accounts: DOMAIN\user and user@domain (ADR-0009 §1) ----------

const NETBIOS_FORBIDDEN = /[\\/:*?"<>|]/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const USER_MAX = 256;

export type AccountResult = ParsedAccount | { error: string };

export function isAccountError(r: AccountResult): r is { error: string } {
  return "error" in r;
}

function dnsName(d: string): boolean {
  return d.length > 0 && utf8Bytes(d) <= 253 && d.split(".").every((l) => DNS_LABEL.test(l));
}

/** Mirror of `credential_parse_account`. Never guesses: no separator is an error. */
export function parseAccount(input: string): AccountResult {
  const s = input.trim();
  if (s.length === 0) return { error: "Enter DOMAIN\\user or user@domain." };
  if (hasForbidden(s, false)) return { error: "The account contains a control or invisible character." };
  const bs = s.indexOf("\\");
  if (bs >= 0) {
    const domain = s.slice(0, bs);
    const user = s.slice(bs + 1);
    if (domain.length === 0) return { error: "The domain before \\ is empty." };
    if (domain.length > 15) return { error: "A NetBIOS domain has at most 15 characters." };
    if (NETBIOS_FORBIDDEN.test(domain)) return { error: "A NetBIOS domain cannot contain \\ / : * ? \" < > |." };
    if (user.length === 0) return { error: "The user after \\ is empty." };
    if (user.includes("\\")) return { error: "Use one backslash between domain and user." };
    if (utf8Bytes(user) > USER_MAX) return { error: "The user name is longer than 256 bytes." };
    return { form: "netbios", user, domain };
  }
  const at = s.lastIndexOf("@");
  if (at >= 0) {
    const user = s.slice(0, at);
    const domain = s.slice(at + 1);
    if (user.length === 0) return { error: "The user before @ is empty." };
    if (utf8Bytes(user) > USER_MAX) return { error: "The user name is longer than 256 bytes." };
    if (!dnsName(domain)) return { error: "The part after @ must be a DNS name such as corp.example." };
    return { form: "upn", user, domain };
  }
  return { error: "Add a domain: DOMAIN\\user or user@domain." };
}

export function renderAccount(a: ParsedAccount): string {
  return a.form === "netbios" ? `${a.domain}\\${a.user}` : `${a.user}@${a.domain}`;
}

/** A `user_password` whose username looks like a domain account (stored verbatim, ADR-0009). */
export function looksLikeDomainAccount(username: string): boolean {
  return username.includes("\\") || username.includes("@");
}

// ---------- characters ----------

/** C0/C1 controls, zero-width and bidi controls, BOM (mirror of `model::is_forbidden`). */
function forbiddenCode(c: number, multiline: boolean): boolean {
  if (c === 0x09 || c === 0x0a || c === 0x0d) return !multiline;
  return (
    c < 0x20 ||
    (c >= 0x7f && c <= 0x9f) ||
    (c >= 0x200b && c <= 0x200f) ||
    (c >= 0x202a && c <= 0x202e) ||
    (c >= 0x2066 && c <= 0x2069) ||
    c === 0xfeff
  );
}

/** Multiline values (PEM, YAML) may keep \n \r \t; nothing else below 0x20. */
export function hasForbidden(s: string, multiline: boolean): boolean {
  for (let i = 0; i < s.length; i++) if (forbiddenCode(s.charCodeAt(i), multiline)) return true;
  return false;
}

// ---------- paste detection ----------

/** One piece of a pasted blob and the form field it belongs in. */
export interface PastePart {
  field: string;
  text: string;
}

export interface Detected {
  kind: CredentialKind;
  /** The field the paste is mainly for (the first of `parts`). */
  field: string;
  label: string;
  /**
   * Where each piece goes. A certificate + private key bundle is split (review 3, B-3): the
   * certificate blocks go to the public `cert_pem`, the key to the secret `key_pem`. A private
   * key never lands in a non-secret field.
   */
  parts: PastePart[];
}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;

/** Split PEM text into its certificate blocks and its private-key blocks. */
export function splitPem(text: string): { certs: string[]; keys: string[] } {
  const certs: string[] = [];
  const keys: string[] = [];
  for (const m of text.matchAll(PEM_BLOCK)) {
    const label = m[1] ?? "";
    if (label === "CERTIFICATE") certs.push(m[0]);
    else if (label.endsWith("PRIVATE KEY")) keys.push(m[0]);
  }
  return { certs, keys };
}

function x509Paste(text: string): Detected {
  const { certs, keys } = splitPem(text);
  const parts: PastePart[] = [];
  if (certs.length > 0) parts.push({ field: "cert_pem", text: `${certs.join("\n")}\n` });
  if (keys.length > 0) parts.push({ field: "key_pem", text: `${keys.join("\n")}\n` });
  // Unparsable framing: anything that mentions a private key is treated as secret, never public.
  if (parts.length === 0) parts.push({ field: /PRIVATE KEY/.test(text) ? "key_pem" : "cert_pem", text });
  const [first] = parts;
  const label = keys.length > 0 && certs.length > 0 ? "X.509 certificate and private key" : "X.509 certificate";
  return { kind: "x509", field: first?.field ?? "cert_pem", label, parts };
}

function one(kind: CredentialKind, field: string, label: string, text: string): Detected {
  return { kind, field, label, parts: [{ field, text }] };
}

/** Guess the kind from a pasted blob. Only unambiguous headers count. */
export function detectKind(text: string): Detected | null {
  const t = text.trimStart();
  // A certificate anywhere makes it an X.509 paste, even with a key first (cert+key bundles).
  if (/-----BEGIN CERTIFICATE-----/.test(t)) return x509Paste(text);
  if (/-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----/.test(t)) {
    return one("ssh_key", "private_key", "SSH private key", text);
  }
  if (/-----BEGIN (ENCRYPTED )?PRIVATE KEY-----/.test(t)) return one("x509", "key_pem", "PKCS#8 private key", text);
  if (/^(apiVersion:\s*v1|kind:\s*Config)\b/m.test(t) && /^clusters:/m.test(t)) {
    return one("kubeconfig", "kubeconfig_yaml", "kubeconfig", text);
  }
  return null;
}

/**
 * Context names for the picker while a kubeconfig is being typed, before Rust has parsed it.
 * Reads only `name:` lines in the top-level `contexts:` block. Rust derives the stored list.
 */
export function previewKubeContexts(yaml: string): string[] {
  const out: string[] = [];
  let inBlock = false;
  for (const line of yaml.split(/\r?\n/).slice(0, 20_000)) {
    if (/^contexts:\s*$/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && /^\S/.test(line) && !line.startsWith("-")) inBlock = false;
    if (!inBlock) continue;
    const m = /^[\s-]*name:\s*["']?([^"'\s#]{1,253})["']?\s*$/.exec(line);
    if (m?.[1] && !out.includes(m[1])) out.push(m[1]);
    if (out.length >= 64) break;
  }
  return out;
}

// ---------- field validation ----------

const BASE32 = /^[A-Z2-7]+=*$/;

/** First problem with a field value, or null. Empty optional values are fine. */
export function validateField(f: FieldSchema, raw: string): string | null {
  const v = f.multiline ? raw : raw.trim();
  if (v.length === 0) return f.required ? `${f.label} is required.` : null;
  if (utf8Bytes(v) > f.validation.maxBytes) {
    return f.validation.maxBytes <= 16
      ? `${f.label} is limited to ${f.validation.maxBytes} bytes; longer input is rejected, not truncated.`
      : `${f.label} is longer than ${formatBytes(f.validation.maxBytes)}.`;
  }
  if (hasForbidden(v, f.multiline)) return `${f.label} contains a control or invisible character.`;
  switch (f.validation.format) {
    case "pem":
      if (!/-----BEGIN [A-Z0-9 ]+-----/.test(v)) return `${f.label} must be PEM (-----BEGIN …).`;
      break;
    case "base32": {
      const s = v.replace(/[\s-]/g, "").toUpperCase();
      if (!BASE32.test(s)) return `${f.label} must be base32 (A–Z, 2–7).`;
      if (Math.floor((s.replace(/=+$/, "").length * 5) / 8) < 10) return `${f.label} must decode to at least 10 bytes.`;
      break;
    }
    case "url":
      if (!/^https:\/\/[^\s/]+/.test(v)) return `${f.label} must be an https:// URL.`;
      break;
    case "upn": {
      const a = parseAccount(v);
      if (isAccountError(a) || a.form !== "upn") return `${f.label} must be user@domain.`;
      break;
    }
    case "netbios_or_upn": {
      const a = parseAccount(v);
      if (isAccountError(a)) return a.error;
      break;
    }
    case "enum":
      if (f.validation.options && f.validation.options.length > 0 && !f.validation.options.includes(v)) {
        return `${f.label} must be one of ${f.validation.options.join(", ")}.`;
      }
      break;
    case "text":
    case "yaml":
      break;
  }
  if (f.validation.pattern && !new RegExp(f.validation.pattern).test(v)) return `${f.label} has the wrong format.`;
  return null;
}

export function formatBytes(n: number): string {
  if (n >= 1 << 20) return `${n / (1 << 20)} MiB`;
  if (n >= 1024) return `${n / 1024} KiB`;
  return `${n} bytes`;
}

// ---------- compatibility matrix (served by credential_kinds, ADR-0009 §2) ----------

export const PROTOCOL_LABEL: Record<Protocol, string> = {
  ssh: "SSH",
  rdp: "RDP",
  vnc: "VNC",
  web: "Web",
  kubernetes: "Kubernetes",
  "vsphere-console": "vSphere console",
};

const ROLE_LABEL: Record<CredentialRole, string> = { primary: "sign-in", gateway: "RD Gateway", become: "become / sudo", certificate: "certificate" };

/** Footnotes of the ADR matrix: why an obvious-looking pairing is refused. */
const FOOTNOTE: Partial<Record<CredentialKind, Partial<Record<Protocol, string>>>> = {
  user_password: { kubernetes: "Kubernetes removed static basic auth." },
  domain_user: { kubernetes: "Kubernetes removed static basic auth." },
  x509: { rdp: "Smart-card RDP is planned for later.", vnc: "VeNCrypt X.509 is planned for later." },
};

export type Compat = { ok: true } | { ok: false; reason: string };

export function schemaFor(kinds: KindSchema[], kind: CredentialKind): KindSchema | undefined {
  return kinds.find((k) => k.kind === kind);
}

/** Can a kind fill `role` on `protocol`? */
export function kindValidFor(schema: KindSchema, protocol: Protocol, role: CredentialRole): Compat {
  const p = schema.protocols.find((x) => x.protocol === protocol);
  if (p?.roles.includes(role)) return { ok: true };
  const note = FOOTNOTE[schema.kind]?.[protocol];
  if (note) return { ok: false, reason: note };
  const uses = schema.protocols.flatMap((x) => x.roles.map((r) => (r === "primary" ? PROTOCOL_LABEL[x.protocol] : `${PROTOCOL_LABEL[x.protocol]} ${ROLE_LABEL[r]}`)));
  // ADR-0016/0017: consumer-only kinds never sign in anywhere (Rust: "… is only for secret sources.").
  const only = schema.consumers?.map((c) => (c === "secret_source" ? "secret sources" : "vault sync")) ?? [];
  if (only.length > 0) return { ok: false, reason: `${schema.label} is only for ${only.join(" and ")}.` };
  if (uses.length === 0) return { ok: false, reason: `${schema.label} has no supported protocol yet.` };
  return { ok: false, reason: `${schema.label} is for ${uses.join(", ")}, not ${PROTOCOL_LABEL[protocol]} ${ROLE_LABEL[role]}.` };
}

/** ADR-0026: a Vault `ssh_sign` reference (the only kind the `certificate` role takes). */
export function isSshSignRef(cred: CredentialMeta): boolean {
  return cred.kind === "external_ref" && cred.fields.provider === "vault" && cred.fields.engine === "ssh_sign";
}

/** Same as `kindValidFor` for a stored credential; `external_ref` follows its `target_kind`. */
export function credentialValidFor(kinds: KindSchema[], cred: CredentialMeta, protocol: Protocol, role: CredentialRole): Compat {
  // ADR-0026 (R3 `check_compatible`): the certificate role takes only an SSH-sign reference, on SSH,
  // and an SSH-sign reference fills no other role.
  if (role === "certificate") {
    if (protocol !== "ssh") return { ok: false, reason: "Only SSH connections take a certificate." };
    return isSshSignRef(cred) ? { ok: true } : { ok: false, reason: "The certificate role takes a Vault SSH sign reference only." };
  }
  if (isSshSignRef(cred)) {
    return { ok: false, reason: "A Vault SSH sign reference only certifies an SSH key: pick it as the connection's certificate." };
  }
  let kind = cred.kind;
  if (kind === "external_ref") {
    const target = cred.fields.target_kind;
    if (typeof target !== "string") return { ok: false, reason: "The reference has no target kind." };
    kind = target as CredentialKind;
  }
  const schema = schemaFor(kinds, kind);
  if (!schema) return { ok: false, reason: "Unknown credential kind." };
  return kindValidFor(schema, protocol, role);
}

/** Kinds whose account fields a connection override can replace (ADR-0009 §3). */
export function supportsOverride(kind: CredentialKind, which: "username" | "domain"): boolean {
  const user: CredentialKind[] = ["user_password", "domain_user", "ssh_key", "ssh_agent", "vnc_user_password", "prompt", "x509"];
  const domain: CredentialKind[] = ["user_password", "domain_user", "prompt"];
  return (which === "username" ? user : domain).includes(kind);
}

/** One-line account summary for lists: never a secret, only plain fields. */
export function accountSummary(c: CredentialMeta): string {
  const f = c.fields;
  const s = (k: string) => {
    const v = f[k];
    return typeof v === "string" ? v : "";
  };
  switch (c.kind) {
    case "domain_user":
      return s("user") && s("domain") ? renderAccount({ form: s("form") === "upn" ? "upn" : "netbios", user: s("user"), domain: s("domain") }) : "";
    case "user_password":
    case "prompt":
      return s("domain") && s("username") ? `${s("domain")}\\${s("username")}` : s("username") || (c.kind === "prompt" ? "asked at connect" : "");
    case "vsphere_user":
      return s("upn");
    case "kubeconfig":
      return s("context") ? `context ${s("context")}` : "";
    case "oauth_client":
      return s("client_id");
    case "external_ref":
      return `${s("provider")}${s("engine") && s("engine") !== "kv2" ? ` ${s("engine").replace("_", " ")}` : ""} ${s("reference")}`.trim();
    case "sudo_become":
      return `${s("method") || "sudo"} → ${s("become_user") || "root"}`;
    case "kube_token":
      return s("subject");
    default:
      return s("username");
  }
}

/** The attachable TOTP seed (ADR-0009 §1): base32, decoded ≥ 10 bytes, at most 128 bytes. */
export const OTP_SEED_SCHEMA: FieldSchema = {
  name: "otp_seed",
  label: "TOTP seed",
  secret: true,
  required: false,
  multiline: false,
  placeholder: "JBSWY3DPEHPK3PXPJBSWY3DP",
  copyable: false,
  validation: { maxBytes: 128, format: "base32" },
};

/** Connections and folders that reference a credential in any role. */
export function usedByCount(id: string, connections: ConnectionSummary[], folderDefaults: (string | null)[]): number {
  const conns = connections.filter(
    (c) => c.credentialId === id || c.gatewayCredentialId === id || c.becomeCredentialId === id || c.certificateCredentialId === id,
  ).length;
  return conns + folderDefaults.filter((d) => d === id).length;
}

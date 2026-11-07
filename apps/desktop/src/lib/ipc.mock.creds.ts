// Credential half of MockTransport (ADR-0009). Secrets are validated and then discarded: only
// their names are kept, exactly like the metadata Rust returns.
import type {
  CredentialCreate,
  CredentialFields,
  CredentialKind,
  CredentialMeta,
  CredentialReplaceSecrets,
  FieldSchema,
  KindSchema,
  OtpSettings,
} from "./ipc.types";
import { CREDENTIAL_KINDS } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { KIND_SCHEMAS } from "./ipc.kinds";
import { OTP_SEED_SCHEMA, isAccountError, parseAccount, previewKubeContexts, validateField } from "./credentials";
import { validateExternalRef } from "./validate.secrets";

const OTP_FIELD = "otp";
// eslint-disable-next-line no-control-regex
const CONTROL = /[\s\u0000-\u001f\u007f-\u009f]/u;
const OTP_SEED = "otp_seed";
const ENGINE_FIXES = new Set(["database", "ssh_sign", "ssh_otp", "pki"]);

function invalid(message: string): IpcError {
  return new IpcError("input.invalid", message);
}

function schemaOf(kind: CredentialKind): KindSchema {
  const s = KIND_SCHEMAS.find((k) => k.kind === kind);
  if (!s) throw invalid("unknown credential kind");
  return s;
}

function isOtp(v: unknown): v is OtpSettings {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    (o.digits === 6 || o.digits === 8) &&
    (o.period === 30 || o.period === 60) &&
    (o.algorithm === "sha1" || o.algorithm === "sha256" || o.algorithm === "sha512")
  );
}

/** Fake but stable `SHA256:` fingerprint so the UI has something realistic to render. */
function fakeFingerprint(seed: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let h = 2166136261;
  let out = "";
  for (let i = 0; i < 43; i++) {
    h ^= seed.charCodeAt(i % Math.max(1, seed.length)) + i;
    h = Math.imul(h, 16777619) >>> 0;
    out += alphabet[h % 64] ?? "A";
  }
  return `SHA256:${out}`;
}

/** Plain-field check, shaped like Rust's `deny_unknown_fields` + caps. Derived names are refused. */
function checkFields(schema: KindSchema, fields: CredentialFields, contexts: string[]): CredentialFields {
  const plain = new Map(schema.fields.filter((f) => !f.secret).map((f) => [f.name, f]));
  const out: CredentialFields = {};
  for (const [k, v] of Object.entries(fields)) {
    if (k === OTP_FIELD) {
      if (!schema.supportsOtp) throw invalid(`${schema.label} has no second factor`);
      if (!isOtp(v)) throw invalid("otp needs digits 6|8, period 30|60, algorithm sha1|sha256|sha512");
      out[k] = { ...v };
      continue;
    }
    // ADR-0016 §2 (E1): `external_ref.version` is a number ≥ 1 and `field_map` an object.
    if (schema.kind === "external_ref" && k === "field_map") {
      const p = fieldMapProblem(v);
      if (p) throw invalid(p);
      out[k] = { ...(v as Record<string, string>) };
      continue;
    }
    if (schema.kind === "external_ref" && k === "version") {
      if (typeof v !== "number" || !Number.isInteger(v) || v < 1) throw invalid("version must be a whole number from 1");
      out[k] = v;
      continue;
    }
    // ADR-0026: `ttl` is a number, `principals` / `alt_names` string arrays (no schema row).
    if (schema.kind === "external_ref" && k === "ttl") {
      if (typeof v !== "number" || !Number.isInteger(v)) throw invalid("ttl must be a whole number of seconds");
      out[k] = v;
      continue;
    }
    if (schema.kind === "external_ref" && (k === "principals" || k === "alt_names")) {
      if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) throw invalid(`${k} must be a list of names`);
      out[k] = [...v];
      continue;
    }
    const f = plain.get(k);
    if (!f) throw invalid(`unknown field ${k} for ${schema.kind}`);
    if (typeof v !== "string") throw invalid(`${k} must be text`);
    // The account field arrives already split (user / domain / form); check it as text here and
    // as a whole account below.
    const asText = f.validation.format === "netbios_or_upn" ? { ...f, validation: { ...f.validation, format: "text" as const } } : f;
    const problem = f.name === "context" ? contextProblem(v, contexts) : validateField(asText, v);
    if (problem) throw invalid(problem);
    if (v.trim() !== "") out[k] = f.multiline ? v : v.trim();
  }
  for (const f of plain.values()) {
    if (f.required && !(f.name in out)) throw invalid(`${f.label} is required`);
  }
  if (schema.kind === "external_ref") {
    // R3: `source` is required for every provider; reference shapes and engine rules as Rust.
    const str = (x: unknown) => (typeof x === "string" ? x : "");
    const list = (x: unknown) => (Array.isArray(x) ? x.filter((y): y is string => typeof y === "string") : []);
    if (typeof out.source !== "string") throw invalid("source is required");
    const errors = validateExternalRef({
      provider: str(out.provider), source: str(out.source), reference: str(out.reference), target_kind: str(out.target_kind),
      version: typeof out.version === "number" ? String(out.version) : "", field_map: {},
      engine: str(out.engine), ttl: typeof out.ttl === "number" ? String(out.ttl) : "", common_name: str(out.common_name),
      username: str(out.username), principals: list(out.principals), alt_names: list(out.alt_names),
    }, []);
    if (typeof out.field_map === "object" && ENGINE_FIXES.has(str(out.engine))) errors.field_map = "dynamic engines have no field_map";
    const field = Object.keys(errors)[0];
    if (field) throw invalid(`${field}: ${errors[field] ?? "invalid"}`);
  }
  if (schema.kind === "domain_user") {
    const text = (v: unknown) => (typeof v === "string" ? v : "");
    const [user, domain] = [text(out.user), text(out.domain)];
    const a = parseAccount(out.form === "upn" ? `${user}@${domain}` : `${domain}\\${user}`);
    if (isAccountError(a)) throw invalid(a.error);
  }
  return out;
}

/** `field_map`: ≤ 32 entries of `name → visible key ≤ 128 B` (names are checked against the target in Rust). */
function fieldMapProblem(v: unknown): string | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return "field_map must be an object";
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > 32) return "field_map has more than 32 entries";
  for (const [name, key] of entries) {
    if (typeof key !== "string" || key === "" || new TextEncoder().encode(key).length > 128 || CONTROL.test(key)) return `field_map.${name} must be visible text up to 128 bytes`;
  }
  return null;
}

function contextProblem(v: string, contexts: string[]): string | null {
  if (v === "" || contexts.includes(v)) return null;
  return "the context is not in this kubeconfig";
}

function checkSecret(schema: KindSchema, name: string, value: string): FieldSchema | null {
  if (name === OTP_SEED) {
    if (!schema.supportsOtp) throw invalid(`${schema.label} has no second factor`);
    const p = validateField(OTP_SEED_SCHEMA, value);
    if (p) throw invalid(p);
    return null;
  }
  const f = schema.fields.find((x) => x.secret && x.name === name);
  if (!f) throw invalid(`unknown secret ${name} for ${schema.kind}`);
  const p = validateField(f, value);
  if (p) throw invalid(p);
  if (value.length === 0) throw invalid(`${f.label} cannot be empty; clear it instead`);
  return f;
}

/** kubeconfig rules the UI should see rejected (ADR-0009 §1). Rust parses for real. */
function kubeconfigProblem(yaml: string): string | null {
  if (/^\s*(exec|auth-provider|tokenFile|client-certificate|client-key):/m.test(yaml)) {
    return "kubeconfig uses exec, auth-provider or a file path; only self-contained configs are accepted";
  }
  return null;
}

export class MockCredentials {
  items: CredentialMeta[];
  private seq = 0;
  readonly kinds = KIND_SCHEMAS;

  constructor(seed: CredentialMeta[]) {
    this.items = seed;
  }

  get(id: string): CredentialMeta {
    const m = this.items.find((c) => c.id === id);
    if (!m) throw new IpcError("credential.not_found", "credential not found");
    return m;
  }

  clone(m: CredentialMeta): CredentialMeta {
    return { ...m, fields: structuredClone(m.fields), secretNames: [...m.secretNames] };
  }

  create(a: CredentialCreate, name: string): CredentialMeta {
    if (!(CREDENTIAL_KINDS as readonly string[]).includes(a.kind)) throw invalid("unknown credential kind");
    const schema = schemaOf(a.kind);
    const yaml = a.secrets.kubeconfig_yaml ?? "";
    if (a.kind === "kubeconfig") {
      const p = kubeconfigProblem(yaml);
      if (p) throw new IpcError("credential.kubeconfig_rejected", p);
    }
    const contexts = a.kind === "kubeconfig" ? previewKubeContexts(yaml) : [];
    const fields = checkFields(schema, a.fields, contexts);
    for (const [k, v] of Object.entries(a.secrets)) if (v !== "") checkSecret(schema, k, v);
    const present = Object.keys(a.secrets).filter((k) => a.secrets[k] !== "");
    for (const f of schema.fields) {
      if (f.secret && f.required && !present.includes(f.name)) throw invalid(`${f.label} is required`);
    }
    if (a.kind === "kubeconfig") fields.contexts = contexts;
    this.seq += 1;
    const now = new Date().toISOString();
    const m: CredentialMeta = {
      id: `cr-new-${this.seq.toString(16).padStart(4, "0")}`,
      name,
      kind: a.kind,
      fields,
      secretNames: present.sort(),
      fingerprint: fingerprintFor(a.kind, a.secrets.private_key ?? (typeof fields.cert_pem === "string" ? fields.cert_pem : "")),
      createdAt: now,
      updatedAt: now,
    };
    this.items.push(m);
    return this.clone(m);
  }

  updateFields(id: string, name: string, fields: CredentialFields): CredentialMeta {
    const m = this.get(id);
    const contexts = Array.isArray(m.fields.contexts) ? m.fields.contexts : [];
    const next = checkFields(schemaOf(m.kind), fields, contexts);
    if (m.kind === "kubeconfig") next.contexts = contexts;
    Object.assign(m, { name, fields: next, updatedAt: new Date().toISOString() });
    if (m.kind === "x509" && typeof next.cert_pem === "string") m.fingerprint = fakeFingerprint(next.cert_pem);
    return this.clone(m);
  }

  replaceSecrets({ id, set, clear }: CredentialReplaceSecrets): void {
    const m = this.get(id);
    const schema = schemaOf(m.kind);
    for (const [k, v] of Object.entries(set)) checkSecret(schema, k, v);
    for (const k of clear) {
      const f = schema.fields.find((x) => x.secret && x.name === k);
      if (k !== OTP_SEED && !f) throw invalid(`unknown secret ${k} for ${schema.kind}`);
      if (f?.required) throw invalid(`${f.label} is required and cannot be cleared`);
    }
    if (m.kind === "kubeconfig" && set.kubeconfig_yaml !== undefined) {
      const p = kubeconfigProblem(set.kubeconfig_yaml);
      if (p) throw new IpcError("credential.kubeconfig_rejected", p);
      m.fields.contexts = previewKubeContexts(set.kubeconfig_yaml);
    }
    if (m.kind === "ssh_key" && set.private_key !== undefined) m.fingerprint = fakeFingerprint(set.private_key);
    const names = new Set(m.secretNames);
    for (const k of Object.keys(set)) names.add(k);
    for (const k of clear) names.delete(k);
    if (!names.has(OTP_SEED)) m.fields = Object.fromEntries(Object.entries(m.fields).filter(([k]) => k !== OTP_FIELD));
    m.secretNames = [...names].sort();
    m.updatedAt = new Date().toISOString();
  }

  remove(id: string): void {
    this.get(id);
    this.items = this.items.filter((c) => c.id !== id);
  }

  copySecret(id: string, name: string): void {
    const m = this.get(id);
    const f = schemaOf(m.kind).fields.find((x) => x.secret && x.name === name);
    if (!f?.copyable) throw invalid(`${name} cannot be copied`);
    if (!m.secretNames.includes(name)) throw new IpcError("credential.secret_missing", `${f.label} is not stored`);
  }

  copyOtp(id: string, now: number): { clearsInMs: number; validForMs: number } {
    const m = this.get(id);
    if (!m.secretNames.includes(OTP_SEED)) throw new IpcError("credential.secret_missing", "no TOTP seed is stored");
    const otp = m.fields[OTP_FIELD];
    const periodMs = (isOtp(otp) ? otp.period : 30) * 1000;
    const validForMs = periodMs - (now % periodMs);
    return { clearsInMs: Math.min(30_000, validForMs), validForMs };
  }
}

function fingerprintFor(kind: CredentialKind, material: string): string | null {
  return kind === "ssh_key" || kind === "x509" ? fakeFingerprint(material) : null;
}

export function parseAccountOrThrow(input: string) {
  const r = parseAccount(input);
  if (isAccountError(r)) throw invalid(r.error);
  return r;
}

export { fakeFingerprint };

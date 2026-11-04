// Form model for the schema-driven credential editor. Pure functions so tests can drive them.
//
// Typed secrets never enter this state: they live in uncontrolled inputs and are read once, at
// submit, through a `SecretReader`. The state only keeps facts derived from them (filled, byte
// count, first problem, kubeconfig context names), which are not secret.
//
// Conventions read from the schema, never from the kind name:
// - a plain field with format `netbios_or_upn` is an account field: it owns the sibling plain
//   fields `domain` and `form` and fills all three from one typed account;
// - an `enum` field without `options` takes them from the derived list `contexts`;
// - the TOTP slot (`otp_seed` secret + `otp` field) exists when `supportsOtp` is true.
import { isOtpSettings, type CredentialFields, type CredentialMeta, type FieldSchema, type KindSchema, type OtpSettings } from "../../lib/ipc";
import { validateExternalRef, type ExternalRefDraft } from "../../lib/validate.secrets";
import {
  OTP_SEED_SCHEMA,
  isAccountError,
  parseAccount,
  previewKubeContexts,
  renderAccount,
  utf8Bytes,
  validateField,
} from "../../lib/credentials";

export type SecretMode = "keep" | "replace" | "clear";

export interface SecretInfo {
  filled: boolean;
  bytes: number;
  problem: string | null;
}

export interface FormState {
  name: string;
  values: Record<string, string>;
  /** Derived facts about each typed secret; never the value. */
  secretInfo: Record<string, SecretInfo>;
  /** Edit only: what to do with each stored secret. Create: always "replace". */
  mode: Record<string, SecretMode>;
  /** Raw text of the account field (`CORP\alice`), when the kind has one. */
  account: string;
  /** Context names read from a kubeconfig being typed (null = none typed). */
  typedContexts: string[] | null;
  otpOn: boolean;
  otp: OtpSettings;
  /** `external_ref` only (ADR-0016 §2): target field or secret name → KV key. */
  fieldMap: Record<string, string>;
}

/** Reads a typed secret from its input at submit time. */
export type SecretReader = (name: string) => string;

export const OTP_SEED = OTP_SEED_SCHEMA.name;
export const DEFAULT_OTP: OtpSettings = { digits: 6, period: 30, algorithm: "sha1" };

export function accountField(schema: KindSchema): FieldSchema | undefined {
  return schema.fields.find((f) => !f.secret && f.validation.format === "netbios_or_upn");
}

/** Plain fields shown as their own input (account siblings are folded into the account field). */
export function plainFields(schema: KindSchema): FieldSchema[] {
  const acct = accountField(schema);
  return schema.fields.filter((f) => !f.secret && f !== acct && !(acct && (f.name === "domain" || f.name === "form")));
}

export function secretFields(schema: KindSchema): FieldSchema[] {
  return schema.fields.filter((f) => f.secret);
}

const str = (v: unknown) => (typeof v === "string" ? v : "");

export function initialState(schema: KindSchema, meta?: CredentialMeta): FormState {
  const values: Record<string, string> = {};
  for (const f of schema.fields) if (!f.secret) values[f.name] = str(meta?.fields[f.name]);
  const otp = meta?.fields.otp;
  const otpSettings = isOtpSettings(otp) ? otp : DEFAULT_OTP;
  const storedMap = meta?.fields.field_map;
  const fieldMap = typeof storedMap === "object" && !Array.isArray(storedMap) && !isOtpSettings(storedMap) ? { ...storedMap } : {};
  if (typeof meta?.fields.version === "number") values.version = String(meta.fields.version);
  const acct = accountField(schema);
  const user = acct ? (values[acct.name] ?? "") : "";
  const account =
    acct && user && values.domain
      ? renderAccount({ form: values.form === "upn" ? "upn" : "netbios", user, domain: values.domain })
      : "";
  return {
    name: meta?.name ?? "",
    values,
    secretInfo: {},
    mode: {},
    account,
    typedContexts: null,
    otpOn: meta?.secretNames.includes(OTP_SEED) ?? false,
    otp: { ...otpSettings },
    fieldMap,
  };
}

/** Names an `external_ref` field map may rename: every field and secret of the target kind, plus the TOTP seed. */
export function targetNames(kinds: KindSchema[], targetKind: string): string[] {
  const t = kinds.find((k) => k.kind === targetKind);
  if (!t) return [];
  return [...t.fields.map((f) => f.name), ...(t.supportsOtp ? [OTP_SEED] : [])];
}

/** Apply a typed account: the split lands in user/domain/form, or they are emptied. */
export function withAccount(s: FormState, schema: KindSchema, raw: string): FormState {
  const acct = accountField(schema);
  if (!acct) return s;
  const parsed = parseAccount(raw);
  const values = { ...s.values };
  if (isAccountError(parsed)) {
    values[acct.name] = "";
    values.domain = "";
    values.form = "";
  } else {
    values[acct.name] = parsed.user;
    values.domain = parsed.domain;
    values.form = parsed.form;
  }
  return { ...s, account: raw, values };
}

/** Record what a secret input now holds, without keeping the value. */
export function withSecretTyped(s: FormState, f: FieldSchema, value: string): FormState {
  const info: SecretInfo = {
    filled: value.length > 0,
    bytes: utf8Bytes(value),
    problem: value.length > 0 ? validateField(f, value) : null,
  };
  const next: FormState = { ...s, secretInfo: { ...s.secretInfo, [f.name]: info } };
  if (f.validation.format === "yaml") {
    const contexts = value ? previewKubeContexts(value) : null;
    next.typedContexts = contexts;
    if (contexts && contexts.length > 0 && !contexts.includes(next.values.context ?? "")) {
      next.values = { ...next.values, context: "" };
    }
  }
  return next;
}

/** Options for an enum field: its own list, or the derived context names. */
export function enumOptions(f: FieldSchema, s: FormState, meta?: CredentialMeta): string[] {
  if (f.validation.options && f.validation.options.length > 0) return f.validation.options;
  if (s.typedContexts) return s.typedContexts;
  const stored = meta?.fields.contexts;
  return Array.isArray(stored) ? stored : [];
}

/** Will this secret be sent: always on create, on edit only when set to "replace". */
export function secretActive(name: string, s: FormState, editing: boolean): boolean {
  return !editing || s.mode[name] === "replace";
}

export type Problems = Record<string, string>;

export function validate(schema: KindSchema, s: FormState, meta?: CredentialMeta, kinds: KindSchema[] = []): Problems {
  const p: Problems = {};
  const editing = meta !== undefined;
  if (s.name.trim() === "") p.name = "Name is required.";
  if (schema.kind === "external_ref") {
    const v = s.values;
    const d: ExternalRefDraft = { provider: v.provider ?? "", source: v.source ?? "", reference: v.reference ?? "", target_kind: v.target_kind ?? "", version: v.version ?? "", field_map: s.fieldMap };
    return { ...p, ...validateExternalRef(d, targetNames(kinds, d.target_kind)) };
  }
  const acct = accountField(schema);
  if (acct) {
    const r = parseAccount(s.account);
    if (isAccountError(r)) p[acct.name] = r.error;
  }
  for (const f of plainFields(schema)) {
    const v = s.values[f.name] ?? "";
    if (f.validation.format === "enum") {
      const opts = enumOptions(f, s, meta);
      if (v === "" && f.required) p[f.name] = `Choose a ${f.label.toLowerCase()}.`;
      else if (v !== "" && opts.length > 0 && !opts.includes(v)) p[f.name] = `${f.label} is not one of the choices.`;
      continue;
    }
    const e = validateField(f, v);
    if (e) p[f.name] = e;
  }
  for (const f of secretFields(schema)) {
    if (!secretActive(f.name, s, editing)) continue;
    const info = s.secretInfo[f.name];
    if (info?.problem) p[f.name] = info.problem;
    else if (!info?.filled && (f.required || editing)) {
      p[f.name] = editing ? `Enter the new ${f.label.toLowerCase()}, or keep the stored one.` : `${f.label} is required.`;
    }
  }
  if (schema.supportsOtp && s.otpOn) {
    const stored = meta?.secretNames.includes(OTP_SEED) ?? false;
    if (!stored || s.mode[OTP_SEED] === "replace") {
      const info = s.secretInfo[OTP_SEED];
      if (info?.problem) p[OTP_SEED] = info.problem;
      else if (!info?.filled) p[OTP_SEED] = "Enter the TOTP seed.";
    }
  }
  return p;
}

/** Non-secret fields for create / update_fields. */
export function buildFields(schema: KindSchema, s: FormState): CredentialFields {
  const out: CredentialFields = {};
  for (const f of schema.fields) {
    if (f.secret) continue;
    const raw = s.values[f.name] ?? "";
    const v = f.multiline ? raw : raw.trim();
    if (v !== "") out[f.name] = v;
  }
  if (schema.supportsOtp && s.otpOn) out.otp = { ...s.otp };
  if (schema.kind === "external_ref") {
    // ADR-0016 §2 (E1): `version` travels as a number, `field_map` as an object; empty = omitted.
    const v = (s.values.version ?? "").trim();
    if (v !== "") out.version = Number(v);
    const map: Record<string, string> = {};
    for (const [k, val] of Object.entries(s.fieldMap)) if (val.trim() !== "") map[k] = val.trim();
    if (Object.keys(map).length > 0) out.field_map = map;
  }
  return out;
}

function normaliseSeed(v: string): string {
  return v.replace(/[\s-]/g, "").toUpperCase();
}

/** Secrets for create: every non-empty typed value, plus the seed when TOTP is on. */
export function buildCreateSecrets(schema: KindSchema, s: FormState, read: SecretReader): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of secretFields(schema)) {
    const v = read(f.name);
    if (v !== "") out[f.name] = v;
  }
  if (schema.supportsOtp && s.otpOn) {
    const seed = read(OTP_SEED);
    if (seed) out[OTP_SEED] = normaliseSeed(seed);
  }
  return out;
}

/** `credential_replace_secrets` arguments for an edit. */
export function buildReplace(
  schema: KindSchema,
  s: FormState,
  meta: CredentialMeta,
  read: SecretReader,
): { set: Record<string, string>; clear: string[] } {
  const set: Record<string, string> = {};
  const clear: string[] = [];
  for (const f of secretFields(schema)) {
    const v = s.mode[f.name] === "replace" ? read(f.name) : "";
    if (v) set[f.name] = v;
    if (s.mode[f.name] === "clear" && meta.secretNames.includes(f.name)) clear.push(f.name);
  }
  if (schema.supportsOtp) {
    const stored = meta.secretNames.includes(OTP_SEED);
    const seed = s.otpOn && (!stored || s.mode[OTP_SEED] === "replace") ? read(OTP_SEED) : "";
    if (seed) set[OTP_SEED] = normaliseSeed(seed);
    if (!s.otpOn && stored) clear.push(OTP_SEED);
  }
  return { set, clear };
}

/** The same form with every derived secret fact dropped (inputs are wiped separately). */
export function wipeSecrets(s: FormState): FormState {
  return { ...s, secretInfo: {}, typedContexts: null };
}

// Form-side checks for the ADR-0026 half of an `external_ref`: 1Password and Bitwarden reference
// shapes (`mooring-core::credential::external_refs`) and the Vault engine parameters
// (`external_engine.rs::check`). Rust decides; these mirror it for the form and MockTransport.
import { ENGINE_CAPS, ENGINE_TARGET, VAULT_ENGINES, type VaultEngine } from "./ipc.types.secrets";
import type { ExternalRefDraft, SecretErrors } from "./validate.secrets";

const utf8Len = (s: string): number => new TextEncoder().encode(s).length;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;
/** `?`, `#`, `\`, control and bidi characters are refused in an `op://` segment. */
// eslint-disable-next-line no-control-regex
const OP_BAD = /[?#\\\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
const NAME_OK = /^[A-Za-z0-9._@-]+$/;
const DNS_OK = /^[A-Za-z0-9._*@-]+$/;

/** Rust `parse_op_reference`: `op://vault/item`, `op://vault/item/field` or `op://vault/item/section/field`. */
export function checkOpReference(ref: string): string | null {
  const r = ref.trim();
  if (!r.startsWith("op://")) return "A 1Password reference starts with op://, for example op://Infra/prod-db/password.";
  const segs = r.slice(5).split("/");
  if (segs.length < 2 || segs.length > 4) return "Use op://vault/item, op://vault/item/field or op://vault/item/section/field.";
  for (const s of segs) {
    if (s === "") return "The reference has an empty segment.";
    if (utf8Len(s) > 256) return "Each part of the reference is at most 256 bytes.";
    if (OP_BAD.test(s)) return "The reference must not contain ?, #, \\ or control characters.";
  }
  return null;
}

/** `op://vault/item` without a field: the item's fields are mapped like KV keys. */
export function opNamesItemOnly(ref: string): boolean {
  const r = ref.trim();
  return r.startsWith("op://") && r.slice(5).split("/").length === 2;
}

/** Rust `parse_bws_reference`: `<secret uuid>` or `<project uuid>/<key>`. */
export function checkBwsReference(ref: string): string | null {
  const r = ref.trim();
  if (r === "") return "Reference is required.";
  if (UUID.test(r)) return null;
  const slash = r.indexOf("/");
  const project = slash > 0 ? r.slice(0, slash) : "";
  const key = slash > 0 ? r.slice(slash + 1) : "";
  if (UUID.test(project) && key !== "" && utf8Len(key) <= 256 && !CONTROL.test(key)) return null;
  return "Use a secret id (a UUID) or <project id>/<key>.";
}

export const isVaultEngine = (v: string): v is VaultEngine => (VAULT_ENGINES as readonly string[]).includes(v);

/** The engine of a draft or a stored row (`kv2` when absent or unknown). */
export function engineOf(v: unknown): VaultEngine {
  return typeof v === "string" && isVaultEngine(v) ? v : "kv2";
}

/** The role of a dynamic reference: the last segment of `<mount…>/<role>`. */
export function roleOf(reference: string): string {
  const segs = reference.trim().split("/");
  return segs[segs.length - 1] ?? "";
}

function checkNames(list: string[] | undefined, max: number, re: RegExp, what: string): string | null {
  if (!list || list.length === 0) return null;
  const one = what.replace(/s$/, "");
  if (list.length > ENGINE_CAPS.names) return `At most ${ENGINE_CAPS.names} ${what}.`;
  if (new Set(list).size !== list.length) return `A ${one} is listed twice.`;
  for (const n of list) if (utf8Len(n) > max || !re.test(n)) return `${n} is not a valid ${one}: letters, digits, '.', '_', '@' and '-', at most ${max} bytes.`;
  return null;
}

/** ADR-0026 §1 engine rules: target kind, parameters that belong to the engine, caps. */
export function checkEngine(d: ExternalRefDraft): SecretErrors {
  const e: SecretErrors = {};
  const raw = d.engine ?? "";
  const engine = raw === "" ? "kv2" : raw;
  if (!isVaultEngine(engine)) return { engine: "Choose a Vault engine." };
  if (d.provider !== "vault" && engine !== "kv2") return { engine: "Only Vault references have an engine." };
  const target = ENGINE_TARGET[engine];
  if (target && d.target_kind !== target) e.target_kind = `The ${engine} engine yields ${target}.`;
  if (target && d.version.trim() !== "") e.version = "Dynamic engines have no KV version.";
  if (target && Object.keys(d.field_map).length > 0) e.field_map = "Dynamic engines have no field map.";
  const ttl = (d.ttl ?? "").trim();
  if (ttl !== "") {
    if (engine !== "ssh_sign" && engine !== "pki") e.ttl = "Only SSH sign and PKI take a TTL.";
    else if (!/^\d{1,5}$/.test(ttl) || Number(ttl) < 1 || Number(ttl) > ENGINE_CAPS.ttl) e.ttl = "TTL is 1 to 86400 seconds, or empty for the role default.";
  }
  if ((d.principals?.length ?? 0) > 0 && engine !== "ssh_sign") e.principals = "Only SSH sign takes principals.";
  else {
    const p = checkNames(d.principals, ENGINE_CAPS.principal, NAME_OK, "principals");
    if (p) e.principals = p;
  }
  const cn = (d.common_name ?? "").trim();
  if (engine === "pki") {
    if (cn === "") e.common_name = "PKI needs a common name.";
    else if (utf8Len(cn) > ENGINE_CAPS.commonName || !DNS_OK.test(cn)) e.common_name = "The common name is a host name of at most 255 bytes.";
    const a = checkNames(d.alt_names, ENGINE_CAPS.commonName, DNS_OK, "alt names");
    if (a) e.alt_names = a;
  } else {
    if (cn !== "") e.common_name = "Only PKI takes a common name.";
    if ((d.alt_names?.length ?? 0) > 0) e.alt_names = "Only PKI takes alt names.";
  }
  const user = (d.username ?? "").trim();
  if (engine === "ssh_otp") {
    if (user === "") e.username = "SSH OTP needs the login the password is issued for.";
    else if (utf8Len(user) > ENGINE_CAPS.otpUser || !NAME_OK.test(user)) e.username = "The login is at most 64 bytes of letters, digits, '.', '_', '@' or '-'.";
  } else if (user !== "") e.username = "Only SSH OTP takes a login.";
  return e;
}

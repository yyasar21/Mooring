// Form-side checks for ADR-0016 secret sources / external references and ADR-0017 sync settings,
// shaped like the Rust validators (mooring-core `secret_source`, `credential::parse_vault_reference`,
// src-tauri `sync_config`). Rust decides; these catch the common mistakes before the IPC hop and
// feed MockTransport. Nothing here sees a secret value.
import { BWS_PATHS, EXTERNAL_TARGET_KINDS, SYNC_INTERVAL, type ExternalTargetKind, type SecretSourceInput, type SyncBackend, type SyncConfig } from "./ipc.types.secrets";
import { checkCaPem, checkUrl, originOf } from "./validate.options";
import { checkBwsReference, checkEngine, checkOpReference } from "./validate.refs";

export type SecretErrors = Record<string, string>;

const utf8Len = (s: string): number => new TextEncoder().encode(s).length;
const PATHLIKE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;
const LOOPBACK_HTTP = /^http:\/\/(127(\.\d{1,3}){3}|\[::1\])(:\d{1,5})?\/?$/i;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\s\u0000-\u001f\u007f-\u009f]/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** `[A-Za-z0-9._-]+` segments joined by `/`, ≤ 256 bytes (namespace, mount, role). */
export function checkPathlike(v: string, what: string): string | null {
  if (utf8Len(v) > 256) return `${what} is longer than 256 bytes.`;
  if (!PATHLIKE.test(v)) return `${what} may contain letters, digits, '.', '_', '-' and '/' between segments.`;
  return null;
}

/** `https://host[:port]`; `http://` only to a loopback literal with `allowHttp`. */
export function checkSourceAddress(address: string, allowHttp: boolean): string | null {
  const a = address.trim();
  if (a === "") return "Address is required.";
  if (/^http:\/\//i.test(a)) {
    if (!allowHttp) return "Address uses http://. Turn on \"Allow http://\" (loopback only) or use https://.";
    return LOOPBACK_HTTP.test(a) ? null : "Plain http:// is allowed only for 127.0.0.1 or [::1].";
  }
  const e = checkUrl(a, false, true);
  if (e) return e.replace(/^Origin/, "Address").replace(/^Origins have no path/, "Address has no path");
  if (a.includes("%")) return "Address must not contain percent-escapes.";
  return null;
}

/** Field errors for a secret source; empty = valid. Keys are the input's field names. */
export function validateSecretSource(a: SecretSourceInput): SecretErrors {
  const e: SecretErrors = {};
  const kind = a.kind ?? "vault";
  const name = a.name.trim();
  if (name === "" || name.length > 200) e.name = "Name must be 1 to 200 characters.";
  const addr = checkSourceAddress(a.address, a.options.allowHttp);
  if (addr) e.address = addr;
  const bws = a.options.bwsPath ?? null;
  // ADR-0026: 1Password Connect and Bitwarden sign in with a token only and have no namespace.
  if (kind !== "vault") {
    if (a.namespace && a.namespace.trim() !== "") e.namespace = "Only Vault sources have a namespace.";
    if (a.authMethod !== "token") e.authMethod = "This provider signs in with a token only.";
    if (a.credentialId === null) {
      e.credentialId = kind === "onepassword" ? "Choose the API token credential that holds the Connect token." : "Choose the Bitwarden access token credential.";
    }
    if (a.options.allowedOrigins.length > 0) e.allowedOrigins = "Only OIDC sources open a window.";
    if (kind === "bitwarden") {
      if (a.options.caPem !== null) e.caPem = "bws uses its own TLS, so a Bitwarden source has no CA.";
      if (bws !== null && !(BWS_PATHS as readonly string[]).includes(bws)) e.bwsPath = "Choose one of the listed bws locations.";
    } else {
      if (bws !== null) e.bwsPath = "Only Bitwarden sources run bws.";
      const ca = checkCaPem(a.options.caPem);
      if (ca) e.caPem = ca;
    }
    return e;
  }
  if (bws !== null) e.bwsPath = "Only Bitwarden sources run bws.";
  if (a.namespace && a.namespace.trim() !== "") {
    const ns = checkPathlike(a.namespace.trim().replace(/^\/+|\/+$/g, ""), "Namespace");
    if (ns) e.namespace = ns;
  }
  const mount = a.authMount.trim().replace(/^\/+|\/+$/g, "");
  if (mount !== "") {
    const m = checkPathlike(mount, "Auth mount");
    if (m) e.authMount = m;
    else if (a.authMethod === "token" && mount !== "token") e.authMount = "The token method uses the token mount.";
  }
  if (a.authMethod === "oidc") {
    if (!a.oidcRole || a.oidcRole.trim() === "") e.oidcRole = "OIDC needs a role.";
    else {
      const r = checkPathlike(a.oidcRole.trim(), "Role");
      if (r) e.oidcRole = r;
    }
    if (a.credentialId !== null) e.credentialId = "An OIDC source has no stored credential.";
  } else {
    if (a.credentialId === null) e.credentialId = a.authMethod === "token" ? "Choose the API token credential that holds the Vault token." : "Choose the Vault AppRole credential.";
    if (a.oidcRole && a.oidcRole.trim() !== "") e.oidcRole = "Only OIDC sources have a role.";
    if (a.options.allowedOrigins.length > 0) e.allowedOrigins = "Only OIDC sources open a window.";
  }
  if (a.options.allowedOrigins.length > 16) e.allowedOrigins = "At most 16 origins.";
  for (const o of a.options.allowedOrigins) {
    const p = checkUrl(o, false, true);
    if (p || originOf(o) !== o.toLowerCase()) { e.allowedOrigins = p ?? "Origins are scheme://host[:port], lowercase."; break; }
  }
  const ca = checkCaPem(a.options.caPem);
  if (ca) e.caPem = ca;
  return e;
}

/** Rust `parse_vault_reference`: `<mount>/<path>`, ≤ 1 KiB, ≤ 64 segments, no `.`/`..`. */
export function checkReference(ref: string): string | null {
  const r = ref.trim();
  if (r === "") return "Reference is required.";
  if (utf8Len(r) > 1024) return "Reference is longer than 1 KiB.";
  const segs = r.split("/");
  if (segs.length < 2) return "Reference is <mount>/<path>, for example kv/ops/db.";
  if (segs.length > 64) return "Reference has more than 64 segments.";
  for (const s of segs) {
    if (s === "" ) return "Reference has an empty segment.";
    if (s === "." || s === "..") return "Reference must not contain '.' or '..' segments.";
    if (!/^[A-Za-z0-9._-]+$/.test(s)) return "Reference segments may contain letters, digits, '.', '_' and '-'.";
  }
  return null;
}

export interface ExternalRefDraft {
  provider: string;
  source: string;
  reference: string;
  target_kind: string;
  /** Raw text; empty = latest. */
  version: string;
  /** target name → KV key (names are validated against the target kind by the form). */
  field_map: Record<string, string>;
  /** ADR-0026 (Vault only); empty or absent = `kv2`. */
  engine?: string;
  /** Raw text in seconds; empty = the role default. */
  ttl?: string;
  principals?: string[];
  common_name?: string;
  alt_names?: string[];
  username?: string;
}

/** Field errors for an `external_ref` form; empty = valid. */
export function validateExternalRef(d: ExternalRefDraft, targetNames: string[]): SecretErrors {
  const e: SecretErrors = {};
  if (!(EXTERNAL_TARGET_KINDS as readonly string[]).includes(d.target_kind)) e.target_kind = "Choose what the secret resolves to.";
  if (!["vault", "onepassword", "bitwarden"].includes(d.provider)) e.provider = "Choose a provider.";
  // ADR-0026: every provider resolves through a secret source now.
  if (d.source === "") e.source = "Choose a secret source.";
  const dynamic = d.provider === "vault" && (d.engine ?? "") !== "" && d.engine !== "kv2";
  if (d.provider === "vault") {
    const r = checkReference(d.reference);
    if (r) e.reference = dynamic ? r.replace("<mount>/<path>, for example kv/ops/db", "<mount>/<role>, for example database/readonly") : r;
  } else if (d.provider === "onepassword") {
    const r = checkOpReference(d.reference);
    if (r) e.reference = r;
  } else if (d.provider === "bitwarden") {
    const r = checkBwsReference(d.reference);
    if (r) e.reference = r;
  } else if (d.reference.trim() === "") e.reference = "Reference is required.";
  const v = d.version.trim();
  if (v !== "" && d.provider !== "vault") e.version = "Only Vault KV references have a version.";
  else if (v !== "" && !(/^\d{1,19}$/.test(v) && Number(v) >= 1)) e.version = "Version is a whole number from 1, or empty for the latest.";
  const entries = Object.entries(d.field_map);
  if (entries.length > 32) e.field_map = "At most 32 mappings.";
  for (const [name, key] of entries) {
    if (!targetNames.includes(name)) { e.field_map = `${name} is not a field of the target kind.`; break; }
    if (key.trim() === "") { e.field_map = `Enter the KV key for ${name}.`; break; }
    if (utf8Len(key) > 128 || CONTROL.test(key)) { e.field_map = `The key for ${name} must be visible text up to 128 bytes.`; break; }
  }
  return { ...e, ...checkEngine(d) };
}

export const isExternalTargetKind = (k: string): k is ExternalTargetKind => (EXTERNAL_TARGET_KINDS as readonly string[]).includes(k);

// ---------- sync (ADR-0017) ----------

/** Rust `check_endpoint`: `https://host[:port]` without a path; `http://` only to a loopback literal. */
export function checkEndpoint(raw: string): string | null {
  const r = raw.trim().replace(/\/+$/, "");
  const m = /^(https?):\/\/(.+)$/i.exec(r);
  if (!m) return "Endpoint must start with https://.";
  const [, scheme, authority] = m;
  if (!authority || authority.length > 255 || !/^[A-Za-z0-9.:[\]-]+$/.test(authority)) return "Endpoint is https://host[:port] without a path.";
  if (scheme?.toLowerCase() === "http" && !LOOPBACK_HTTP.test(`http://${authority}`)) return "Plain http:// is allowed only for a loopback address.";
  return null;
}

export function checkBucket(b: string): string | null {
  const ok = b.length >= 3 && b.length <= 63 && /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(b) && !b.includes("..");
  return ok ? null : "Bucket is 3 to 63 lowercase letters, digits, '-' or '.'.";
}

export function checkRegion(r: string): string | null {
  return /^[a-z0-9-]{1,64}$/.test(r) ? null : "Region looks like us-east-1.";
}

export function checkPrefix(p: string): string | null {
  const t = p.trim().replace(/^\/+|\/+$/g, "");
  if (t === "") return null;
  return PATHLIKE.test(t) && utf8Len(t) <= 512 ? null : "Prefix is segments of letters, digits, '.', '_' and '-' joined by '/'.";
}

export function checkInterval(v: number | null): string | null {
  if (v === null) return null;
  return Number.isInteger(v) && v >= SYNC_INTERVAL.min && v <= SYNC_INTERVAL.max ? null : `Interval is a whole number of minutes from ${SYNC_INTERVAL.min} to ${SYNC_INTERVAL.max}, or manual.`;
}

export function validateBackend(b: SyncBackend): SecretErrors {
  const e: SecretErrors = {};
  const checks: [string, string | null][] = [
    ["endpoint", checkEndpoint(b.endpoint)], ["region", checkRegion(b.region.trim())], ["bucket", checkBucket(b.bucket.trim())], ["prefix", checkPrefix(b.prefix)],
  ];
  for (const [k, p] of checks) if (p) e[k] = p;
  return e;
}

export function validateSyncConfig(c: SyncConfig): SecretErrors {
  const e = validateBackend(c.backend);
  if (c.credentialId === "") e.credentialId = "Choose the S3 access key credential.";
  const i = checkInterval(c.intervalMinutes);
  if (i) e.intervalMinutes = i;
  return e;
}

export const isVaultId = (v: string): boolean => UUID.test(v.trim());

/** Normalise a backend the way Rust stores it (lowercase origin, trimmed prefix). */
export function normalizeBackend(b: SyncBackend): SyncBackend {
  return {
    kind: "s3",
    endpoint: b.endpoint.trim().replace(/\/+$/, "").toLowerCase(),
    region: b.region.trim(),
    bucket: b.bucket.trim(),
    prefix: b.prefix.trim().replace(/^\/+|\/+$/g, ""),
    pathStyle: b.pathStyle,
  };
}

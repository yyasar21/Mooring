// The directory step's form (ADR-0019 §4, I2): defaults, client-side checks that mirror Rust's
// (`LdapTarget::parse`, `Dn::parse`, the filter and size caps) so the obvious mistakes are caught
// before a bind, and the two argument shapes of `ldap_import_test` / `ldap_import_preview`.
import { LDAP_LIMITS, type LdapImportPreviewArgs, type LdapImportTestArgs, type LdapKind, type LdapScope } from "../../lib/ipc";
import { checkCaPem } from "../../lib/validate.options";

export interface LdapForm {
  url: string;
  baseDn: string;
  scope: LdapScope;
  kind: LdapKind;
  filter: string;
  credentialId: string;
  /** null = the extra-CA box is off (the field is the shared `CaPemField`). */
  caPem: string | null;
  /** Kept as text so a half-typed number does not snap; checked on submit. */
  sizeLimit: string;
}

export const LDAP_FORM_DEFAULT: LdapForm = {
  url: "ldaps://",
  baseDn: "",
  scope: "sub",
  kind: "ad",
  filter: "",
  credentialId: "",
  caPem: null,
  sizeLimit: String(LDAP_LIMITS.defaultSizeLimit),
};

export type LdapFormErrors = Partial<Record<keyof LdapForm, string>>;

export const LDAP_URL_EXAMPLE = "ldaps://dc01.example.test:636";
export const LDAP_DN_EXAMPLE = "DC=corp,DC=example,DC=test";

/** `ldaps://host[:port]`, nothing else: no user info, path or query (Rust refuses them too). */
const LDAPS_URL = /^ldaps:\/\/(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*)(?::(\d{1,5}))?\/?$/;
/** One RDN of RFC 4514 as typed by hand: `type=value`; escapes are left to Rust. */
const RDN = /^[A-Za-z][A-Za-z0-9-]*=[^,+=]+$/;

export function checkUrl(url: string): string | undefined {
  const v = url.trim();
  if (v === "" || v === "ldaps://") return "Enter the server as ldaps://host, with :port when it is not 636.";
  if (/^ldaps?i?:\/\//i.test(v) && !/^ldaps:\/\//i.test(v)) return "Only ldaps:// is supported: Mooring never talks to a directory without TLS, and does not use StartTLS.";
  const m = LDAPS_URL.exec(v);
  if (!m) return "That is not an ldaps://host[:port] address. No user name, path or query is allowed.";
  const port = m[2] === undefined ? 636 : Number(m[2]);
  if (port < 1 || port > 65535) return "The port must be between 1 and 65535.";
  return undefined;
}

export function checkBaseDn(dn: string): string | undefined {
  const v = dn.trim();
  if (v === "") return `Enter where the search starts, for example ${LDAP_DN_EXAMPLE}.`;
  if (v.length > 1024) return "The base DN is longer than 1 024 characters.";
  const rdns = v.split(/\s*,\s*/);
  if (rdns.length > 64 || !rdns.every((r) => RDN.test(r))) return `That is not a distinguished name. Use type=value pairs separated by commas, for example ${LDAP_DN_EXAMPLE}.`;
  return undefined;
}

export function checkFilter(filter: string): string | undefined {
  if (filter.length > LDAP_LIMITS.maxFilterChars) return `The name filter is longer than ${String(LDAP_LIMITS.maxFilterChars)} characters.`;
  if (/\p{Cc}/u.test(filter)) return "The name filter contains a control character.";
  return undefined;
}

export function checkSizeLimit(text: string): string | undefined {
  const v = text.trim();
  if (!/^\d+$/.test(v)) return "Enter a whole number.";
  const n = Number(v);
  if (n < 1 || n > LDAP_LIMITS.maxSizeLimit) return `The size limit must be between 1 and ${String(LDAP_LIMITS.maxSizeLimit)}.`;
  return undefined;
}

/** Everything a bind needs (Test bind); `all` adds the search fields (Preview). */
export function validateLdapForm(f: LdapForm, all: boolean): LdapFormErrors {
  const e: LdapFormErrors = {};
  const url = checkUrl(f.url);
  if (url) e.url = url;
  const dn = checkBaseDn(f.baseDn);
  if (dn) e.baseDn = dn;
  if (f.credentialId === "") e.credentialId = "Choose the credential Mooring binds with.";
  const ca = checkCaPem(f.caPem);
  if (ca) e.caPem = ca;
  if (all) {
    const filter = checkFilter(f.filter);
    if (filter) e.filter = filter;
    const size = checkSizeLimit(f.sizeLimit);
    if (size) e.sizeLimit = size;
  }
  return e;
}

export function toTestArgs(f: LdapForm): LdapImportTestArgs {
  return {
    url: f.url.trim(),
    baseDn: f.baseDn.trim(),
    kind: f.kind,
    credentialId: f.credentialId,
    ...(f.caPem !== null && f.caPem.trim() !== "" ? { caPem: f.caPem } : {}),
  };
}

export function toPreviewArgs(f: LdapForm): LdapImportPreviewArgs {
  const filter = f.filter.trim();
  return {
    ...toTestArgs(f),
    scope: f.scope,
    ...(filter !== "" ? { filter } : {}),
    sizeLimit: Number(f.sizeLimit.trim()),
  };
}

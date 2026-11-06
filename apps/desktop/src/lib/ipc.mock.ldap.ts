// The mock directory behind `ldap_import_test` / `ldap_import_preview` (rust-core I2): one AD-style
// forest at `DC=example,DC=test` with a few OpenLDAP `ipHost` objects in a lab OU, searched the way
// `mooring-import::ldap` does it (bind, scope, object class by kind, a substring on cn /
// dNSHostName, the size cap) and mapped the way `plan.rs` does (OU path → folders ≤ 8 deep,
// Windows OS → RDP else SSH, one shared `prompt` credential). Nothing here is a secret: the bind
// "password" is never looked at; a credential binds or not by its id. Fake hosts only.
import type { CredentialMeta } from "./ipc.types";
import type { ImportItem, ImportSkipped, ImportWarning, LdapImportPreviewArgs, LdapImportTestArgs, LdapKind, LdapScope } from "./ipc.types.import";
import { LDAP_CREDENTIAL_KINDS, LDAP_LIMITS } from "./ipc.types.import";
import { IpcError } from "./ipc.error";
import type { MockPlan } from "./ipc.mock.import.data";
import { renderAccount } from "./credentials";

/** `plan.rs`: folders deeper than this are cut and a `path_truncated` warning is added. */
export const LDAP_MAX_DEPTH = 8;

/** The DN suffix every fixture entry lives under; a base DN outside it is `ldap.dn_invalid` (rc 32). */
export const LDAP_FIXTURE_BASE = "DC=example,DC=test";

interface Entry {
  /** RDNs below the fixture base, outermost first (`OU=Servers`, `OU=Web`); the entry's own RDN is `cn`. */
  path: string[];
  cn: string;
  classes: ("computer" | "ipHost" | "device")[];
  dNSHostName?: string;
  operatingSystem?: string;
  ipHostNumber?: string;
}

const ou = (...names: string[]) => names.map((n) => `OU=${n}`);
const DEEP = ou("Archive", "2019", "Q1", "Batch-1", "Rack-A", "Shelf-2", "Slot-3", "Bay-4", "Old");

/** Five computers under OU=Servers (two Windows), workstations, a lab OU of ipHosts, one stale entry, one nine-deep. */
const FIXTURE: readonly Entry[] = [
  { path: ou("Servers"), cn: "DC01", classes: ["computer"], dNSHostName: "dc01.example.test", operatingSystem: "Windows Server 2022 Standard" },
  { path: ou("Servers"), cn: "FS01", classes: ["computer"], dNSHostName: "fs01.example.test", operatingSystem: "Windows Server 2019 Standard" },
  { path: ou("Servers", "Web"), cn: "WEB01", classes: ["computer"], dNSHostName: "web01.example.test", operatingSystem: "Ubuntu 24.04 LTS" },
  { path: ou("Servers", "Web"), cn: "WEB03", classes: ["computer"], dNSHostName: "web03.example.test", operatingSystem: "Ubuntu 24.04 LTS" },
  { path: ou("Servers", "Database"), cn: "PG02", classes: ["computer"], dNSHostName: "pg02.example.test", operatingSystem: "Red Hat Enterprise Linux 9.6" },
  { path: ou("Workstations"), cn: "WS-OPS-01", classes: ["computer"], dNSHostName: "ws-ops-01.example.test", operatingSystem: "Windows 11 Enterprise" },
  { path: ou("Workstations"), cn: "WS-DEV-02", classes: ["computer"], dNSHostName: "ws-dev-02.example.test", operatingSystem: "Windows 11 Enterprise" },
  // A pre-staged computer account: no dNSHostName yet → skipped(invalid) under AD.
  { path: ou("Workstations"), cn: "WS-NEW-09", classes: ["computer"] },
  // OpenLDAP-style objects: ipHost with an address, no OS → SSH.
  { path: ou("Lab"), cn: "lab-nas", classes: ["ipHost", "device"], ipHostNumber: "203.0.113.20" },
  { path: ou("Lab"), cn: "lab-switch", classes: ["device"], ipHostNumber: "203.0.113.21" },
  // Nine OUs deep: the folder path is cut at eight with a `path_truncated` warning.
  { path: DEEP, cn: "LEGACY-01", classes: ["computer"], dNSHostName: "legacy-01.example.test", operatingSystem: "Windows Server 2012 R2 Standard" },
];

/** `LdapTarget::parse`: `ldaps://host[:port][/]`; `ldap://` / `ldapi://` are refused as insecure. */
export function parseLdapUrl(url: string): { host: string; port: number } {
  if (/^ldaps?i?:\/\//i.test(url) && !/^ldaps:\/\//i.test(url)) throw new IpcError("ldap.insecure", "only ldaps:// is accepted");
  const m = /^ldaps:\/\/(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?\/?$/.exec(url);
  if (!m?.[1]) throw new IpcError("ldap.invalid", "url");
  const port = m[2] === undefined ? 636 : Number(m[2]);
  if (port < 1 || port > 65535) throw new IpcError("ldap.invalid", "url");
  return { host: m[1].toLowerCase(), port };
}

/** A loose RFC 4514 check: `type=value(,type=value)*`, ≤ 1 KiB, ≤ 64 RDNs, not the root DSE. */
export function parseDn(dn: string): string[] {
  if (dn.length === 0 || dn.length > 1024) throw new IpcError("ldap.dn_invalid", "base DN");
  const rdns = dn.split(/\s*,\s*/);
  if (rdns.length > 64 || !rdns.every((r) => /^[A-Za-z][A-Za-z0-9-]*=[^,+=\s][^,+=]*$/.test(r))) throw new IpcError("ldap.dn_invalid", "base DN");
  return rdns.map((r) => {
    const [t, v] = r.split("=", 2);
    return `${(t ?? "").toUpperCase()}=${(v ?? "").trim()}`;
  });
}

function sameDn(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x.toLowerCase() === b[i]?.toLowerCase());
}

/** The bind name Rust derives from the credential (`domain_user` by `form`; `user_password` as typed). */
export function bindName(c: CredentialMeta): string {
  const s = (k: string) => {
    const v = c.fields[k];
    return typeof v === "string" ? v : "";
  };
  if (c.kind === "domain_user") return renderAccount({ form: s("form") === "upn" ? "upn" : "netbios", user: s("user"), domain: s("domain") });
  return s("domain") ? `${s("username")}@${s("domain")}` : s("username");
}

/** Argument checks shared by test and preview (`input.invalid` / `ldap.*` / `credential.*`), in Rust's order. */
export function checkLdapArgs(a: LdapImportTestArgs, creds: CredentialMeta[]): { host: string; port: number; base: string[]; cred: CredentialMeta } {
  if (a.caPem !== undefined && new TextEncoder().encode(a.caPem).length > LDAP_LIMITS.maxCaPemBytes) throw new IpcError("input.invalid", "caPem");
  if (!(["ad", "openldap"] as string[]).includes(a.kind)) throw new IpcError("input.invalid", "kind");
  const target = parseLdapUrl(a.url);
  const base = parseDn(a.baseDn);
  const cred = creds.find((c) => c.id === a.credentialId);
  if (!cred) throw new IpcError("credential.not_found", "credential not found");
  if (!(LDAP_CREDENTIAL_KINDS as readonly string[]).includes(cred.kind)) throw new IpcError("credential.incompatible", "only domain_user or user_password can bind");
  return { ...target, base, cred };
}

export function checkPreviewArgs(a: LdapImportPreviewArgs): { scope: LdapScope; filter: string; sizeLimit: number } {
  const scope = a.scope ?? "sub";
  if (!(["base", "one", "sub"] as string[]).includes(scope)) throw new IpcError("input.invalid", "scope");
  const filter = a.filter ?? "";
  if (filter.length > LDAP_LIMITS.maxFilterChars || /\p{Cc}/u.test(filter)) throw new IpcError("input.invalid", "filter");
  const sizeLimit = a.sizeLimit ?? LDAP_LIMITS.defaultSizeLimit;
  if (!Number.isInteger(sizeLimit) || sizeLimit < 0) throw new IpcError("input.invalid", "sizeLimit");
  if (sizeLimit === 0) throw new IpcError("ldap.invalid", "sizeLimit");
  return { scope, filter, sizeLimit: Math.min(sizeLimit, LDAP_LIMITS.maxSizeLimit) };
}

/** The search as the mock server runs it: base must exist, then scope, object class and the substring. */
export function searchFixture(base: string[], scope: LdapScope, kind: LdapKind, filter: string): Entry[] {
  const fixtureBase = LDAP_FIXTURE_BASE.split(",");
  const n = fixtureBase.length;
  if (base.length < n || !sameDn(base.slice(-n), fixtureBase)) throw new IpcError("ldap.dn_invalid", "no such object (rc 32)");
  const under = [...base.slice(0, base.length - n)].reverse(); // outermost OU first
  const known = under.length === 0 || FIXTURE.some((e) => e.path.length >= under.length && sameDn(e.path.slice(0, under.length), under));
  if (!known) throw new IpcError("ldap.dn_invalid", "no such object (rc 32)");
  const needle = filter.toLowerCase();
  return FIXTURE.filter((e) => {
    if (!sameDn(e.path.slice(0, under.length), under)) return false;
    const depth = e.path.length - under.length;
    if (scope === "base" || (scope === "one" && depth !== 0)) return false;
    if (kind === "ad" ? !e.classes.includes("computer") : !e.classes.some((c) => c === "ipHost" || c === "device")) return false;
    return needle === "" || e.cn.toLowerCase().includes(needle) || (e.dNSHostName ?? "").toLowerCase().includes(needle);
  });
}

/** `plan.rs`: entries → folders (OU path under the base, ≤ 8), connections (rdp / ssh), one `prompt` credential. */
export function ldapPlan(entries: Entry[], base: string[], kind: LdapKind): MockPlan {
  const items: ImportItem[] = [];
  const skipped: ImportSkipped[] = [];
  const warnings: ImportWarning[] = [];
  const folders = new Map<string, string>(); // OU path joined → item key
  const under = base.length - LDAP_FIXTURE_BASE.split(",").length;
  const domain = base.slice(under).map((r) => r.slice(3)).join(".").toLowerCase();
  const credKey = "k-dir";
  entries.forEach((e, i) => {
    const host = kind === "ad" ? e.dNSHostName : (e.ipHostNumber ?? e.dNSHostName ?? e.cn.toLowerCase());
    if (!host) { skipped.push({ sourceRef: `entry ${String(i + 1)}`, reason: "invalid" }); return; }
    let rel = e.path.slice(under);
    if (rel.length > LDAP_MAX_DEPTH) { rel = rel.slice(0, LDAP_MAX_DEPTH); warnings.push({ code: "path_truncated", sourceRef: `entry ${String(i + 1)}` }); }
    let parent: string | null = null;
    for (let d = 0; d < rel.length; d++) {
      const key = rel.slice(0, d + 1).join("/");
      let k = folders.get(key);
      if (!k) {
        k = `f${String(folders.size + 1)}`;
        folders.set(key, k);
        items.push({ key: k, parent, kind: "folder", name: rel[d]?.slice(3) ?? "" });
      }
      parent = k;
    }
    const windows = (e.operatingSystem ?? "").toLowerCase().includes("windows");
    items.push({ key: `c${String(i + 1)}`, parent, kind: "connection", name: e.cn, protocol: windows ? "rdp" : "ssh", host, credentialKey: credKey });
  });
  const credentials: MockPlan["credentials"] = items.some((it) => it.kind === "connection")
    ? [{ key: credKey, name: kind === "ad" ? `Directory account (${domain})` : "Directory account", kind: "prompt", hasSecret: false }]
    : [];
  // Folders before the connections they hold (the tree renders parents first).
  return { items: [...items.filter((i) => i.kind === "folder"), ...items.filter((i) => i.kind === "connection")], credentials, skipped, warnings };
}

// Mock ADR-0019 importers as rust-core I1 serves them: the Rust-side pick dialog (a queue of
// file names here; the "path" never exists), a dry-run preview held under a single-use plan id
// with a 10 minute TTL, and an all-or-nothing apply into a new root folder. No file is parsed:
// `ipc.mock.import.data.ts` holds one realistic plan per format. Nothing here is a secret;
// `hasSecret` is a flag. Methods stay `async` to mirror the IPC signature.
/* eslint-disable @typescript-eslint/require-await */
import type { ConnectionSummary, CredentialMeta, Folder } from "./ipc.types";
import type {
  ImportCredentialItem, ImportFormat, ImportFormatInfo, ImportIpc, ImportItem, ImportPick, ImportPlanFormat, ImportPreview, ImportReport,
  ImportSkipped, ImportWarning, KnownLocation, LdapImportTestArgs,
} from "./ipc.types.import";
import { IMPORT_FORMATS } from "./ipc.types.import";
import { IpcError } from "./ipc.error";
import { DEMO_IMPORT_FILES, demoPlan } from "./ipc.mock.import.data";
import { bindName, checkLdapArgs, checkPreviewArgs, ldapPlan, searchFixture } from "./ipc.mock.ldap";
import { MockNetBase } from "./ipc.mock.net";

/** What the user answers in the Rust-native certificate dialog; `no_dialog` = it could not be shown. */
export type LdapTrustAnswer = "trust" | "reject" | "no_dialog";
/** What the native "Directory sign-in" confirmation (F2, review 7 L-43) answers; `no_dialog` = no prompter at all. */
export type LdapSignInAnswer = "confirm" | "decline" | "no_dialog";
/** Transport outcomes the mock directory can fake before the bind. */
export type LdapFault = "ldap.unavailable" | "ldap.timeout" | "ldap.response" | "http.tls";

/** ADR-0019 §3: a held plan lives at most this long. */
export const IMPORT_PLAN_TTL_MS = 10 * 60_000;
/** I1: at most this many plans are held at once. */
export const IMPORT_PLAN_MAX = 8;

const LABELS: Record<ImportFormat, string> = {
  royal_ts: "Royal TS", rdm: "Remote Desktop Manager", termius: "Termius", mremoteng: "mRemoteNG", putty: "PuTTY", openssh: "OpenSSH config",
};
const EXTENSIONS: Record<ImportFormat, string[]> = {
  royal_ts: ["rtsx", "rtsz"], rdm: ["rdm", "xml"], termius: ["csv", "json"], mremoteng: ["xml"], putty: ["reg"], openssh: [],
};
const KNOWN: Partial<Record<ImportFormat, KnownLocation>> = { openssh: "openssh", putty: "putty" };
const DEFAULT_PORT: Record<string, number> = { ssh: 22, rdp: 3389, vnc: 5900, web: 443 };

/** What the next `import_pick` dialog returns: a file, with an optional parser failure at preview. */
export interface ImportPickSpec {
  fileName?: string;
  size?: number;
  /** The preview of this file fails with this parser code. */
  error?: ImportRefusal;
}

/** Codes a parser can refuse a file with (`src-tauri/ipc-codes.json`, `import.*`). */
export type ImportRefusal = "import.encrypted" | "import.doctype" | "import.format" | "import.limits" | "import.too_large" | "import.unsupported_container";

interface HeldPlan {
  preview: ImportPreview;
  at: number;
}

export abstract class MockImportBase extends MockNetBase implements ImportIpc {
  /** Next dialog answers, in order; `null` = the user cancels. Empty = the demo file of the format. */
  importPicks: (ImportPickSpec | null)[] = [];
  /** Known locations that exist on this "machine"; a missing one previews with `import.not_found`. */
  importKnown: Record<KnownLocation, boolean> = { openssh: true, putty: true };
  importPlans = new Map<string, HeldPlan>();
  private importPickRows = new Map<string, { format: ImportFormat; spec: ImportPickSpec; at: number }>();
  private importSeq = 0;
  abstract override folders: Folder[];
  abstract override connections: ConnectionSummary[];
  protected abstract override credentialRows(): CredentialMeta[];

  /** Test hook: every held plan is past its TTL from now on. */
  expireImportPlans(): void {
    for (const p of this.importPlans.values()) p.at = Number.NEGATIVE_INFINITY;
  }

  /** `vault_lock` drops picks and plans (secrets zeroized in Rust). */
  protected override lockBackend(): void {
    super.lockBackend();
    this.importPlans.clear();
    this.importPickRows.clear();
    this.ldapConfirmed.clear(); // F2 L-43: confirmed (credential, host:port) pairs live until lock
  }

  private importId(prefix: string): string {
    this.importSeq += 1;
    return `${prefix}-${this.importSeq.toString(16).padStart(4, "0")}-${Math.random().toString(16).slice(2, 10)}`;
  }

  importFormats: ImportIpc["importFormats"] = async () =>
    IMPORT_FORMATS.map((format): ImportFormatInfo => ({
      format, label: LABELS[format], extensions: [...EXTENSIONS[format]], knownLocation: KNOWN[format] ?? null,
      secretsPossible: format === "termius" || format === "openssh",
    }));

  importPick: ImportIpc["importPick"] = async ({ format }) => {
    await this.unlocked();
    if (!IMPORT_FORMATS.includes(format)) throw new IpcError("input.invalid", "invalid format");
    const spec = this.importPicks.length > 0 ? this.importPicks.shift() : {};
    if (spec === null || spec === undefined) return null;
    const demo = DEMO_IMPORT_FILES[format];
    const pick: ImportPick = { pickId: this.importId("pick"), fileName: spec.fileName ?? demo.fileName, size: spec.size ?? demo.size };
    this.importPickRows.set(pick.pickId, { format, spec, at: Date.now() });
    return pick;
  };

  importPreview: ImportIpc["importPreview"] = async ({ source, includePlaintextSecrets, importKeyFiles }) => {
    await this.unlocked();
    let format: ImportFormat;
    if ("pickId" in source) {
      const row = this.importPickRows.get(source.pickId);
      if (!row || Date.now() - row.at > IMPORT_PLAN_TTL_MS) throw new IpcError("input.invalid", "invalid pick: unknown, used, expired or from another session");
      this.importPickRows.delete(source.pickId);
      if (row.spec.error) {
        this.record("import_refused", { code: row.spec.error });
        throw refusal(row.spec.error);
      }
      format = row.format;
    } else {
      if (!(source.known in this.importKnown)) throw new IpcError("input.invalid", "invalid known location");
      if (!this.importKnown[source.known]) {
        this.record("import_refused", { code: "import.not_found" });
        throw new IpcError("import.not_found", source.known === "openssh" ? "~/.ssh/config does not exist" : "~/.putty/sessions does not exist");
      }
      format = source.known;
    }
    const plan = demoPlan(format);
    const skipped: ImportSkipped[] = [...plan.skipped];
    const warnings: ImportWarning[] = [...plan.warnings];
    // F2 (L-41): the key-file opt-in is honoured only for the known location; a picked file ignores it with a warning.
    const keyFiles = importKeyFiles && "known" in source && source.known === "openssh";
    if (importKeyFiles && !keyFiles) warnings.push({ code: "key_files_only_for_known_location", sourceRef: "importKeyFiles" });
    const credentials: ImportCredentialItem[] = [];
    for (const c of plan.credentials) {
      const { plaintext, keyFile, ...dto } = c;
      if (plaintext && !includePlaintextSecrets) {
        credentials.push({ ...dto, kind: "prompt", hasSecret: false });
        warnings.push({ code: "password_dropped", sourceRef: dto.name });
      } else if (keyFile && keyFiles) {
        if (keyFile === "readable") credentials.push({ ...dto, kind: "ssh_key", hasSecret: true });
        else {
          credentials.push(dto);
          skipped.push({ sourceRef: dto.name, reason: "key_unreadable" });
        }
      } else credentials.push(dto);
    }
    return this.finishPreview(format, LABELS[format], { items: plan.items, credentials, skipped, warnings });
  };

  /** I1's `finish_preview`: duplicates against the store, the plan store (cap, TTL), `import_previewed`. */
  private finishPreview(format: ImportPlanFormat, label: string, plan: { items: ImportItem[]; credentials: ImportCredentialItem[]; skipped: ImportSkipped[]; warnings: ImportWarning[] }): ImportPreview {
    if (this.importPlans.size >= IMPORT_PLAN_MAX) throw new IpcError("import.limits", "too many import plans are held; discard one first");
    const items = plan.items.map((it): ImportItem => {
      const dup = it.kind === "connection" ? this.duplicateOf(it) : null;
      return dup ? { ...it, duplicateOf: dup } : { ...it };
    });
    const { credentials, skipped, warnings } = plan;
    const preview: ImportPreview = {
      planId: this.importId("plan"),
      format,
      rootName: `Imported from ${label} (${new Date().toISOString().slice(0, 10)})`,
      counts: {
        folders: items.filter((i) => i.kind === "folder").length,
        connections: items.filter((i) => i.kind === "connection").length,
        credentials: credentials.length,
        secrets: credentials.filter((c) => c.hasSecret).length,
        skipped: skipped.length,
        warnings: warnings.length,
      },
      items, credentials, skipped, warnings,
    };
    this.importPlans.set(preview.planId, { preview, at: Date.now() });
    this.record("import_previewed", { format });
    return structuredClone(preview);
  }

  // ---------- ADR-0019 §4 (I2): the directory importer ----------

  /** The next certificate decisions for a host that is not pinned yet (Rust-native dialog); empty = trust. */
  ldapTrust: LdapTrustAnswer[] = [];
  /** `known_ldap_certs`: `host:port` pins; a pinned host never prompts again. */
  ldapPinned = new Set<string>();
  /** Credential ids the directory refuses to bind (wrong password): `ldap.bind`. */
  ldapRejects = new Set<string>(["cr-legacy"]);
  /** The next connects fail with this transport fault (`ldap.unavailable`, `ldap.timeout`, ...). */
  ldapFaults: LdapFault[] = [];
  /** The next answers of the native "Sign in to <host:port>" dialog for an unconfirmed pair; empty = confirm. */
  ldapSignIn: LdapSignInAnswer[] = [];
  /** `AppState::ldap_binds`: `credentialId@host:port` pairs confirmed this unlocked session. */
  ldapConfirmed = new Set<string>();

  /** Vault gate, argument checks, trust, bind: everything before a search, with the I2 audit rows. */
  private async ldapConnect(a: LdapImportTestArgs): Promise<{ host: string; port: number; base: string[]; boundAs: string }> {
    await this.unlocked();
    const refuse = (e: unknown): never => {
      if (e instanceof IpcError) this.record("import_refused", { code: e.code });
      throw e;
    };
    let checked;
    try {
      checked = checkLdapArgs(a, this.credentialRows());
    } catch (e: unknown) {
      return refuse(e);
    }
    const { host, port, base, cred } = checked;
    const fault = this.ldapFaults.shift();
    if (fault) return refuse(faultError(fault));
    const pin = `${host}:${String(port)}`;
    if (!this.ldapPinned.has(pin) && a.caPem === undefined) {
      const answer = this.ldapTrust.shift() ?? "trust";
      if (answer === "no_dialog") return refuse(new IpcError("http.trust_prompt", "the certificate is not trusted yet and no dialog could be shown"));
      this.record("cert_decision", { protocol: "ldap", host: pin, decision: answer === "trust" ? "trusted" : "rejected" });
      if (answer === "reject") return refuse(new IpcError("http.trust_rejected", "the certificate was rejected"));
      this.ldapPinned.add(pin);
    }
    // F2 (L-43): trust → confirm → bind. The first bind of a (credential, host:port) pair asks in a
    // Rust-native dialog before the password leaves the vault; a refusal never binds.
    const pair = `${cred.id}@${pin}`;
    if (!this.ldapConfirmed.has(pair)) {
      const answer = this.ldapSignIn.shift() ?? "confirm";
      if (answer === "no_dialog") return refuse(new IpcError("ldap.confirm_required", "the sign-in needs a confirmation and no dialog could be shown"));
      if (answer === "decline") {
        this.record("confirm_refused", { kind: "ldap_bind", target: pin, reason: "declined" });
        return refuse(new IpcError("ldap.bind_declined", "the sign-in was not confirmed"));
      }
      this.ldapConfirmed.add(pair);
    }
    const ok = !this.ldapRejects.has(cred.id);
    this.record("ldap_bind", { host: pin, success: String(ok) });
    if (!ok) return refuse(new IpcError("ldap.bind", "the directory refused the bind (rc 49)"));
    return { host, port, base, boundAs: bindName(cred) };
  }

  ldapImportTest: ImportIpc["ldapImportTest"] = async (a) => {
    const { host, port, boundAs } = await this.ldapConnect(a);
    return { host, port, boundAs };
  };

  ldapImportPreview: ImportIpc["ldapImportPreview"] = async (a) => {
    const { base } = await this.ldapConnect(a);
    try {
      const { scope, filter, sizeLimit } = checkPreviewArgs(a);
      const entries = searchFixture(base, scope, a.kind, filter);
      if (entries.length > sizeLimit) throw new IpcError("ldap.size_limit", `more than ${String(sizeLimit)} entries matched`);
      return this.finishPreview("ldap", "LDAP directory", ldapPlan(entries, base, a.kind));
    } catch (e: unknown) {
      // Only the code is audited: nothing about the base, the filter or the entries.
      if (e instanceof IpcError) this.record("import_refused", { code: e.code });
      throw e;
    }
  };

  /** I1 rule: `(protocol, host lower-cased, effective port, user)` against the store. */
  private duplicateOf(it: ImportItem): string | null {
    const port = it.port ?? DEFAULT_PORT[it.protocol ?? ""] ?? 0;
    const hit = this.connections.find((c) => {
      if (c.protocol !== it.protocol || c.host.toLowerCase() !== (it.host ?? "").toLowerCase()) return false;
      if ((c.port ?? DEFAULT_PORT[c.protocol] ?? 0) !== port) return false;
      const cred = this.credentialRows().find((r) => r.id === (c.credentialId ?? c.effectiveCredentialId));
      const user = c.usernameOverride ?? (typeof cred?.fields.username === "string" ? cred.fields.username : null);
      return user === (it.username ?? null);
    });
    return hit?.id ?? null;
  }

  private takePlan(planId: string): ImportPreview {
    const held = this.importPlans.get(planId);
    this.importPlans.delete(planId);
    if (!held || Date.now() - held.at > IMPORT_PLAN_TTL_MS) throw new IpcError("import.plan_expired", "the import plan expired or was already used; preview the file again");
    return held.preview;
  }

  importApply: ImportIpc["importApply"] = async ({ planId, exclude, duplicates }) => {
    await this.unlocked();
    if (!(duplicates === undefined || (["skip", "import"] as string[]).includes(duplicates))) throw new IpcError("input.invalid", "invalid duplicates");
    const p = this.takePlan(planId);
    const out = new Set(exclude);
    const top = this.folders.find((f) => f.parentId === null);
    if (!top) throw new IpcError("tree.not_found", "folder not found");
    const report: ImportReport = { rootFolderId: this.importId("f-imp"), folders: 0, connections: 0, credentials: 0, secrets: 0, skipped: p.skipped.length };
    this.folders.push({ id: report.rootFolderId, parentId: top.id, name: p.rootName, defaultCredentialId: null, sort: this.folders.length });

    // Folders first (parents precede children); an excluded folder lifts its children to the nearest kept ancestor.
    const folderId = new Map<string, string>();
    const resolveParent = (parent: string | null): string => (parent === null ? report.rootFolderId : (folderId.get(parent) ?? report.rootFolderId));
    for (const it of p.items.filter((i) => i.kind === "folder")) {
      if (out.has(it.key)) { folderId.set(it.key, resolveParent(it.parent)); report.skipped += 1; continue; }
      const id = this.importId("f-imp");
      this.folders.push({ id, parentId: resolveParent(it.parent), name: it.name, defaultCredentialId: null, sort: this.folders.length });
      folderId.set(it.key, id);
      report.folders += 1;
    }
    // Credentials only where a kept connection references them (prompt / ssh_agent are never written unreferenced).
    const kept = p.items.filter((i) => i.kind === "connection" && !out.has(i.key) && (duplicates === "import" || !i.duplicateOf));
    const referenced = new Set(kept.map((i) => i.credentialKey).filter((k): k is string => k !== undefined && !out.has(k)));
    const credId = new Map<string, string>();
    for (const c of p.credentials) {
      if (out.has(c.key)) { report.skipped += 1; continue; }
      if (!referenced.has(c.key) && (c.kind === "prompt" || c.kind === "ssh_agent")) continue;
      const id = this.importId("cr-imp");
      const now = new Date().toISOString();
      const username = c.name.split(/\s|·/)[0] ?? c.name;
      this.credentialRows().push({
        id, name: c.name, kind: c.kind as CredentialMeta["kind"], fields: c.kind === "prompt" ? { username } : { username },
        secretNames: c.hasSecret ? (c.kind === "ssh_key" ? ["private_key"] : ["password"]) : [], fingerprint: null, createdAt: now, updatedAt: now,
      });
      credId.set(c.key, id);
      report.credentials += 1;
      if (c.hasSecret) report.secrets += 1;
    }
    for (const it of p.items.filter((i) => i.kind === "connection")) {
      if (!kept.includes(it)) { report.skipped += 1; continue; }
      const now = new Date().toISOString();
      this.connections.push({
        id: this.importId("c-imp"), folderId: resolveParent(it.parent), name: it.name, protocol: it.protocol ?? "ssh", host: it.host ?? "",
        port: it.port ?? null, credentialId: it.credentialKey ? (credId.get(it.credentialKey) ?? null) : null, effectiveCredentialId: null,
        usernameOverride: it.credentialKey ? null : (it.username ?? null), domainOverride: null, gatewayCredentialId: null, becomeCredentialId: null,
        tags: [], createdAt: now, updatedAt: now,
      });
      report.connections += 1;
    }
    this.record("import_applied", {
      format: p.format, folders: String(report.folders), connections: String(report.connections), credentials: String(report.credentials),
      secrets: String(report.secrets), skipped: String(report.skipped),
    });
    return report;
  };

  importDiscard: ImportIpc["importDiscard"] = async ({ planId }) => {
    await this.unlocked();
    this.importPlans.delete(planId); // unknown or expired: nothing to drop, no error
  };
}

/** A transport fault before the bind (literal codes: the N-14 guard reads them). */
function faultError(fault: LdapFault): IpcError {
  switch (fault) {
    case "ldap.unavailable": return new IpcError("ldap.unavailable", "the directory did not answer");
    case "ldap.timeout": return new IpcError("ldap.timeout", "the directory did not answer within 30 s");
    case "ldap.response": return new IpcError("ldap.response", "the directory sent a malformed reply");
    case "http.tls": return new IpcError("http.tls", "the TLS handshake failed");
  }
}

/** The fixed, content-free reason Rust pairs with a parser refusal (literal codes: the N-14 guard reads them). */
function refusal(code: ImportRefusal): IpcError {
  switch (code) {
    case "import.encrypted": return new IpcError("import.encrypted", "the document is password protected");
    case "import.doctype": return new IpcError("import.doctype", "the XML declares a DOCTYPE");
    case "import.format": return new IpcError("import.format", "the file is not a valid export (record 3)");
    case "import.limits": return new IpcError("import.limits", "the file exceeds an import limit");
    case "import.too_large": return new IpcError("import.too_large", "the file is larger than 16 MiB");
    case "import.unsupported_container": return new IpcError("import.unsupported_container", "the file is a ZIP archive");
  }
}

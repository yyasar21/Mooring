// Mock tree (folders, connections with their ADR-0025 jump-host chains) and credential commands
// of ADR-0008 / ADR-0009. Split out of `ipc.mock.ts`, which keeps app/vault and SSH sessions.
/* eslint-disable @typescript-eslint/require-await */
import type { ConnectionFields, ConnectionSummary, CredentialRole, Folder, Ipc } from "./ipc.types";
import { MAX_VIA } from "./ipc.types.a5";
import { IpcError } from "./ipc.error";
import { bestScore } from "./fuzzy";
import { MockCredentials, parseAccountOrThrow } from "./ipc.mock.creds";
import { credentialValidFor, supportsOverride } from "./credentials";
import { seedConnections, seedCredentials, seedFolders } from "./ipc.seed";
import { MockA5Base } from "./ipc.mock.a5";

export abstract class MockTreeBase extends MockA5Base {
  folders = seedFolders();
  connections = seedConnections();
  creds = new MockCredentials(seedCredentials());
  private ids = 0;

  protected id(prefix: string): string {
    this.ids += 1;
    return `${prefix}-${this.ids.toString(16).padStart(4, "0")}`;
  }

  protected folder(id: string): Folder {
    const f = this.folders.find((x) => x.id === id);
    if (!f) throw new IpcError("tree.not_found", "folder not found");
    return f;
  }

  protected connection(id: string): ConnectionSummary {
    const c = this.connections.find((x) => x.id === id);
    if (!c) throw new IpcError("tree.not_found", "connection not found");
    return c;
  }

  protected name(n: string): string {
    const t = n.trim();
    if (t.length === 0 || t.length > 200) throw new IpcError("input.invalid", "name must be 1 to 200 characters");
    return t;
  }

  protected effective(credentialId: string | null, folderId: string): string | null {
    let cred = credentialId;
    let fid: string | null = folderId;
    while (!cred && fid) {
      const f = this.folders.find((x) => x.id === fid);
      cred = f?.defaultCredentialId ?? null;
      fid = f?.parentId ?? null;
    }
    return cred;
  }

  protected resolve(c: ConnectionSummary): ConnectionSummary {
    return { ...c, tags: [...c.tags], via: [...(c.via ?? [])], effectiveCredentialId: this.effective(c.credentialId, c.folderId) };
  }

  private isDescendant(id: string, of: string): boolean {
    let cur: string | null = id;
    while (cur) {
      if (cur === of) return true;
      cur = this.folders.find((f) => f.id === cur)?.parentId ?? null;
    }
    return false;
  }

  protected compatible(credentialId: string, protocol: ConnectionSummary["protocol"], role: CredentialRole): void {
    const r = credentialValidFor(this.creds.kinds, this.creds.get(credentialId), protocol, role);
    if (!r.ok) throw new IpcError("credential.incompatible", r.reason);
  }

  /** ADR-0025 / R1 `validate_via` + the store checks. Ids are never echoed in the message. */
  private checkVia(via: string[], self: string | null, protocol: ConnectionSummary["protocol"]): void {
    const bad = (why: string) => new IpcError("connection.via_invalid", `invalid via: ${why}`);
    if (via.length === 0) return;
    if (protocol === "vsphere-console") throw bad("vCenter connections cannot use jump hosts");
    if (via.length > MAX_VIA) throw bad("at most 3 jump hosts");
    if (new Set(via).size !== via.length) throw bad("a jump host is listed twice");
    for (const id of via) {
      if (id === self) throw bad("a connection cannot be its own jump host");
      const hop = this.connections.find((c) => c.id === id);
      if (!hop) throw bad("a jump host does not exist");
      if (hop.protocol !== "ssh") throw bad("jump hosts must be SSH connections");
      if (self !== null && (hop.via ?? []).includes(self)) throw bad("the chain loops back");
    }
  }

  private checkFields(a: ConnectionFields, self: string | null): void {
    this.folder(a.folderId);
    this.name(a.name);
    if (a.host.trim().length === 0) throw new IpcError("input.invalid", "host is required");
    if (a.port !== null && (a.port < 1 || a.port > 65535)) throw new IpcError("input.invalid", "port out of range");
    if (a.via) this.checkVia(a.via, self, a.protocol);
    const roles: [string | null, CredentialRole][] = [
      [a.credentialId, "primary"],
      [a.gatewayCredentialId, "gateway"],
      [a.becomeCredentialId, "become"],
    ];
    for (const [id, role] of roles) if (id) this.compatible(id, a.protocol, role);
    const effective = this.effective(a.credentialId, a.folderId);
    const kind = effective ? this.creds.get(effective).kind : null;
    for (const which of ["username", "domain"] as const) {
      const v = which === "username" ? a.usernameOverride : a.domainOverride;
      if (v === null) continue;
      if (v.trim() === "" || v.length > 256) throw new IpcError("input.invalid", `${which} override must be 1 to 256 characters`);
      if (kind && !supportsOverride(kind, which)) throw new IpcError("input.invalid", `the credential has no ${which} to override`);
    }
  }

  /** Connections outside `doomed` that hop through one of `ids`. */
  private hopUsers(ids: Set<string>, doomed: Set<string>): ConnectionSummary[] {
    return this.connections.filter((c) => !doomed.has(c.id) && (c.via ?? []).some((h) => ids.has(h)));
  }

  // ---------- tree ----------

  treeList: Ipc["treeList"] = async () => {
    await this.unlocked();
    return {
      folders: this.folders.map((f) => ({ ...f })),
      connections: this.connections.map((c) => this.resolve(c)),
    };
  };

  folderCreate: Ipc["folderCreate"] = async ({ parentId, name }) => {
    await this.unlocked();
    this.folder(parentId);
    const sort = this.folders.filter((f) => f.parentId === parentId).length;
    const f: Folder = { id: this.id("f"), parentId, name: this.name(name), defaultCredentialId: null, sort };
    this.folders.push(f);
    return { ...f };
  };

  folderRename: Ipc["folderRename"] = async ({ id, name }) => {
    await this.unlocked();
    const f = this.folder(id);
    f.name = this.name(name);
    return { ...f };
  };

  folderMove: Ipc["folderMove"] = async ({ id, parentId }) => {
    await this.unlocked();
    const f = this.folder(id);
    if (f.parentId === null) throw new IpcError("tree.root", "the root folder cannot move");
    this.folder(parentId);
    if (this.isDescendant(parentId, id)) throw new IpcError("tree.cycle", "a folder cannot move into itself");
    f.parentId = parentId;
    return { ...f };
  };

  folderSetDefaultCredential: Ipc["folderSetDefaultCredential"] = async ({ id, credentialId }) => {
    await this.unlocked();
    const f = this.folder(id);
    if (credentialId) this.creds.get(credentialId);
    f.defaultCredentialId = credentialId;
    return { ...f };
  };

  folderDelete: Ipc["folderDelete"] = async ({ id }) => {
    await this.unlocked();
    const f = this.folder(id);
    if (f.parentId === null) throw new IpcError("tree.root", "the root folder cannot be deleted");
    const doomed = new Set(this.folders.filter((x) => this.isDescendant(x.id, id)).map((x) => x.id));
    const doomedConns = new Set(this.connections.filter((c) => doomed.has(c.folderId)).map((c) => c.id));
    if (this.hopUsers(doomedConns, doomedConns).length > 0) {
      throw new IpcError("connection.in_use_as_hop", "a connection in this folder is a jump host of a connection outside it");
    }
    this.folders = this.folders.filter((x) => !doomed.has(x.id));
    this.connections = this.connections.filter((c) => !doomed.has(c.folderId));
  };

  connectionCreate: Ipc["connectionCreate"] = async (a) => {
    await this.unlocked();
    this.checkFields(a, null);
    const now = new Date().toISOString();
    const c: ConnectionSummary = {
      ...a,
      name: a.name.trim(),
      host: a.host.trim(),
      tags: [...a.tags],
      via: [...(a.via ?? [])],
      id: this.id("c"),
      effectiveCredentialId: null,
      createdAt: now,
      updatedAt: now,
    };
    this.connections.push(c);
    return this.resolve(c);
  };

  connectionUpdate: Ipc["connectionUpdate"] = async (a) => {
    await this.unlocked();
    const c = this.connection(a.id);
    this.checkFields(a, a.id);
    // Rust keeps options_json only while the protocol stays the same; `via` omitted keeps the chain.
    const options = a.options ?? (a.protocol === c.protocol ? c.options : undefined);
    const via = a.via ? [...a.via] : (c.via ?? []);
    Object.assign(c, { ...a, name: a.name.trim(), host: a.host.trim(), tags: [...a.tags], options, via });
    c.updatedAt = new Date().toISOString();
    return this.resolve(c);
  };

  connectionMove: Ipc["connectionMove"] = async ({ id, folderId }) => {
    await this.unlocked();
    const c = this.connection(id);
    this.folder(folderId);
    c.folderId = folderId;
    return this.resolve(c);
  };

  connectionDelete: Ipc["connectionDelete"] = async ({ id }) => {
    await this.unlocked();
    this.connection(id);
    if (this.hopUsers(new Set([id]), new Set([id])).length > 0) {
      throw new IpcError("connection.in_use_as_hop", "another connection uses this one as a jump host");
    }
    this.connections = this.connections.filter((c) => c.id !== id);
  };

  connectionSearch: Ipc["connectionSearch"] = async ({ query, limit }) => {
    await this.unlocked();
    const q = query.trim();
    return this.connections
      .map((c) => ({ c, s: q ? bestScore(q, [c.name, c.host, ...c.tags]) : 0 }))
      .filter((x): x is { c: ConnectionSummary; s: number } => x.s !== null)
      .sort((a, b) => b.s - a.s || a.c.name.localeCompare(b.c.name))
      .slice(0, Math.max(1, Math.min(limit, 100)))
      .map(({ c }) => ({ id: c.id, name: c.name, host: c.host, folderId: c.folderId, protocol: c.protocol }));
  };

  connectionSetRoleCredential: Ipc["connectionSetRoleCredential"] = async ({ id, role, credentialId }) => {
    await this.unlocked();
    const c = this.connection(id);
    if (credentialId) this.compatible(credentialId, c.protocol, role);
    if (role === "gateway") c.gatewayCredentialId = credentialId;
    else if (role === "certificate") c.certificateCredentialId = credentialId;
    else c.becomeCredentialId = credentialId;
    c.updatedAt = new Date().toISOString();
    return this.resolve(c);
  };

  // ---------- credentials (ADR-0009) ----------

  credentialKinds: Ipc["credentialKinds"] = async () => structuredClone(this.creds.kinds);

  credentialList: Ipc["credentialList"] = async () => {
    await this.unlocked();
    return this.creds.items.map((c) => this.creds.clone(c));
  };

  credentialCreate: Ipc["credentialCreate"] = async (a) => {
    await this.unlocked();
    return this.creds.create(a, this.name(a.name));
  };

  credentialUpdateFields: Ipc["credentialUpdateFields"] = async ({ id, name, fields }) => {
    await this.unlocked();
    return this.creds.updateFields(id, this.name(name), fields);
  };

  credentialReplaceSecrets: Ipc["credentialReplaceSecrets"] = async (a) => {
    await this.unlocked();
    this.creds.replaceSecrets(a);
  };

  credentialDelete: Ipc["credentialDelete"] = async ({ id }) => {
    await this.unlocked();
    this.creds.remove(id);
    for (const c of this.connections) {
      if (c.credentialId === id) c.credentialId = null;
      if (c.gatewayCredentialId === id) c.gatewayCredentialId = null;
      if (c.becomeCredentialId === id) c.becomeCredentialId = null;
      if (c.certificateCredentialId === id) c.certificateCredentialId = null;
    }
    for (const f of this.folders) if (f.defaultCredentialId === id) f.defaultCredentialId = null;
  };

  credentialCopySecret: Ipc["credentialCopySecret"] = async ({ id, name }) => {
    await this.unlocked();
    this.creds.copySecret(id, name);
    this.record("credential_copied", { credential: id, name });
    return { clearsInMs: 30_000 };
  };

  credentialCopyOtp: Ipc["credentialCopyOtp"] = async ({ id }) => {
    await this.unlocked();
    const r = this.creds.copyOtp(id, Date.now());
    this.record("credential_copied", { credential: id, name: "otp" });
    return r;
  };

  credentialParseAccount: Ipc["credentialParseAccount"] = async ({ input }) => parseAccountOrThrow(input);
}

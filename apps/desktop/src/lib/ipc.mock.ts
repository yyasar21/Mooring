// In-memory implementation of the ADR-0008 / ADR-0009 contract for `vite dev` (no Tauri) and vitest.
// Hosts are fake (*.example.test); no credential secret is ever stored, only discarded.
// Session/audit methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type {
  ConnectionFields,
  ConnectionSummary,
  CredentialRole,
  Folder,
  Ipc,
  SessionEventHandler,
  SessionInfo,
} from "./ipc.types";
import { IpcError } from "./ipc.error";
import { bestScore } from "./fuzzy";
import { MockCredentials, parseAccountOrThrow } from "./ipc.mock.creds";
import { echo } from "./ipc.mock.shell";
import { credentialValidFor, supportsOverride } from "./credentials";

import { seedConnections, seedCredentials, seedFolders } from "./ipc.seed";
import { MockExitBase, type MockOptions } from "./ipc.mock.exit";

export type { MockOptions } from "./ipc.mock.exit";
const enc = new TextEncoder();
const dec = new TextDecoder();

interface MockSession {
  info: SessionInfo;
  host: string;
  emit: SessionEventHandler;
  pending: "tofu" | "otp" | "credential" | null;
  needsOtp: boolean;
  /** The connection's effective credential is `prompt`: ask for the account after TOFU. */
  askCredential: { username: string | null; domain: string | null; needsDomain: boolean } | null;
  line: string;
}

export class MockTransport extends MockExitBase implements Ipc {
  folders = seedFolders();
  connections = seedConnections();
  creds = new MockCredentials(seedCredentials());
  trustedHosts = new Set<string>();
  sessions = new Map<string, MockSession>();
  detached: string[] = [];
  private ids = 0;

  constructor(opts: MockOptions = {}) {
    super(opts);
    this.record("vault_unlocked", {});
    this.record("session_opened", { connection: "c-web01", protocol: "ssh", peer_identity: "SHA256:mock-web01" });
    this.record("session_closed", { connection: "c-web01", reason: "closed by user" });
  }

  // ---------- helpers ----------

  private id(prefix: string): string {
    this.ids += 1;
    return `${prefix}-${this.ids.toString(16).padStart(4, "0")}`;
  }

  protected requireSsh(sessionId: string): void {
    const s = this.sessions.get(sessionId);
    if (!s) throw new IpcError("session.not_found", "session not found");
    if (s.info.protocol !== "ssh") throw new IpcError("input.invalid", "invalid sessionId: not an SSH session");
    if (s.info.state !== "connected") throw new IpcError("session.not_connected", "the session is not connected yet");
  }

  private folder(id: string): Folder {
    const f = this.folders.find((x) => x.id === id);
    if (!f) throw new IpcError("tree.not_found", "folder not found");
    return f;
  }

  private connection(id: string): ConnectionSummary {
    const c = this.connections.find((x) => x.id === id);
    if (!c) throw new IpcError("tree.not_found", "connection not found");
    return c;
  }

  private name(n: string): string {
    const t = n.trim();
    if (t.length === 0 || t.length > 200) throw new IpcError("input.invalid", "name must be 1 to 200 characters");
    return t;
  }

  private effective(credentialId: string | null, folderId: string): string | null {
    let cred = credentialId;
    let fid: string | null = folderId;
    while (!cred && fid) {
      const f = this.folders.find((x) => x.id === fid);
      cred = f?.defaultCredentialId ?? null;
      fid = f?.parentId ?? null;
    }
    return cred;
  }

  private resolve(c: ConnectionSummary): ConnectionSummary {
    return { ...c, tags: [...c.tags], effectiveCredentialId: this.effective(c.credentialId, c.folderId) };
  }

  private isDescendant(id: string, of: string): boolean {
    let cur: string | null = id;
    while (cur) {
      if (cur === of) return true;
      cur = this.folders.find((f) => f.id === cur)?.parentId ?? null;
    }
    return false;
  }

  // ---------- app / vault ----------

  appInfo: Ipc["appInfo"] = () =>
    Promise.resolve({ name: "Mooring", version: "dev", os: "browser", arch: "mock", debug: true });
  vaultStatus: Ipc["vaultStatus"] = () => Promise.resolve(this.vault);
  vaultCreate: Ipc["vaultCreate"] = () => {
    this.vault = "unlocked";
    this.record("vault_created", {});
    return Promise.resolve(this.vault);
  };
  vaultUnlock: Ipc["vaultUnlock"] = (password) => {
    if (password.length === 0) return Promise.reject(new IpcError("vault.unlock", "wrong password"));
    this.vault = "unlocked";
    this.record("vault_unlocked", {});
    return Promise.resolve(this.vault);
  };
  /** Sessions survive a lock (ADR-0006, ADR-0010 M-10); see `lockBackend` for what does not. */
  vaultLock: Ipc["vaultLock"] = (reason) => {
    this.lockBackend();
    this.record("vault_locked", { reason });
    return Promise.resolve(this.vault);
  };
  vaultChangePassword: Ipc["vaultChangePassword"] = ({ next }) => {
    if (next.length < 12) return Promise.reject(new IpcError("vault.weak_password", "use at least 12 characters"));
    this.record("password_changed", {});
    return Promise.resolve(this.vault);
  };

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
    this.folders = this.folders.filter((x) => !doomed.has(x.id));
    this.connections = this.connections.filter((c) => !doomed.has(c.folderId));
  };

  private checkFields(a: ConnectionFields): void {
    this.folder(a.folderId);
    this.name(a.name);
    if (a.host.trim().length === 0) throw new IpcError("input.invalid", "host is required");
    if (a.port !== null && (a.port < 1 || a.port > 65535)) throw new IpcError("input.invalid", "port out of range");
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

  private compatible(credentialId: string, protocol: ConnectionSummary["protocol"], role: CredentialRole): void {
    const r = credentialValidFor(this.creds.kinds, this.creds.get(credentialId), protocol, role);
    if (!r.ok) throw new IpcError("credential.incompatible", r.reason);
  }

  connectionCreate: Ipc["connectionCreate"] = async (a) => {
    await this.unlocked();
    this.checkFields(a);
    const now = new Date().toISOString();
    const c: ConnectionSummary = {
      ...a,
      name: a.name.trim(),
      host: a.host.trim(),
      tags: [...a.tags],
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
    this.checkFields(a);
    Object.assign(c, { ...a, name: a.name.trim(), host: a.host.trim(), tags: [...a.tags] });
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

  // ---------- sessions ----------

  sessionOpen: Ipc["sessionOpen"] = async ({ connectionId, onEvent }) => {
    await this.unlocked();
    const c = this.resolve(this.connection(connectionId));
    const cred = c.effectiveCredentialId ? this.creds.get(c.effectiveCredentialId) : null;
    if (cred) this.compatible(cred.id, c.protocol, "primary");
    const str = (v: unknown) => (typeof v === "string" ? v : null);
    const askCredential =
      cred?.kind === "prompt"
        ? {
            username: c.usernameOverride ?? str(cred.fields.username),
            domain: c.domainOverride ?? str(cred.fields.domain),
            needsDomain: c.protocol === "rdp",
          }
        : null;
    const sessionId = this.id("s");
    const s: MockSession = {
      info: { sessionId, connectionId, protocol: c.protocol, state: "connecting", openedAt: new Date().toISOString() },
      host: c.host,
      emit: onEvent,
      pending: null,
      needsOtp: c.tags.includes("otp"),
      askCredential,
      line: "",
    };
    this.sessions.set(sessionId, s);
    this.later(() => {
      if (!this.trustedHosts.has(c.host)) {
        s.pending = "tofu";
        onEvent({
          kind: "prompt",
          id: 1,
          message: `The authenticity of host ${c.host} can't be established.\nED25519 key fingerprint is SHA256:mock-${c.name}.\nTrust this host and continue?`,
          secret: false,
          purpose: "host_key_trust",
          account: null,
        });
      } else this.afterTrust(s);
    });
    return { sessionId };
  };

  private afterTrust(s: MockSession): void {
    if (s.askCredential) {
      const a = s.askCredential;
      s.pending = "credential";
      s.emit({
        kind: "prompt",
        id: 3,
        message: `Sign in to ${s.host}`,
        secret: true,
        purpose: "credential",
        account: { username: a.username, domain: a.domain, needsUsername: true, needsDomain: a.needsDomain },
      });
      return;
    }
    if (s.needsOtp) {
      s.pending = "otp";
      s.emit({ kind: "prompt", id: 2, message: "Verification code:", secret: true, purpose: "keyboard_interactive", account: null });
      return;
    }
    this.connect(s);
  }

  private connect(s: MockSession): void {
    s.pending = null;
    s.info.state = "connected";
    this.record("session_opened", { connection: s.info.connectionId, protocol: s.info.protocol });
    s.emit({ kind: "connected", protocol: s.info.protocol, peerIdentity: `SHA256:mock-${s.host}` });
    s.emit({ kind: "bytes", data: enc.encode(`Mock shell on ${s.host}. Input is echoed.\r\n$ `) });
  }

  private end(s: MockSession, reason: string): void {
    s.info.state = "closed";
    this.dropSession(s.info.sessionId);
    this.sessions.delete(s.info.sessionId);
    this.record("session_closed", { connection: s.info.connectionId, reason });
    s.emit({ kind: "closed", reason });
  }

  sessionSend: Ipc["sessionSend"] = async ({ sessionId, input }) => {
    const s = this.sessions.get(sessionId);
    if (!s) throw new IpcError("session.not_found", "session not found");
    switch (input.kind) {
      case "credential_answer": {
        if (s.pending !== "credential" || input.id !== 3) throw new IpcError("input.invalid", "no such prompt");
        const ok = input.username.trim() !== "" && input.password.length > 0;
        this.record("credential_prompted", { connection: s.info.connectionId, username: input.username.trim() });
        this.later(() => { if (ok) this.connect(s); else this.end(s, "authentication failed"); });
        return;
      }
      case "answer": {
        const yes = /^(y|yes|accept)$/i.test(input.text.trim());
        if (s.pending === "tofu" && input.id === 1) {
          this.record("trust_decision", { host: s.host, fingerprint: `SHA256:mock-${s.host}`, decision: yes ? "accepted" : "rejected" });
          if (yes) {
            this.trustedHosts.add(s.host);
            this.later(() => { this.afterTrust(s); });
          } else this.later(() => { this.end(s, "host key rejected"); });
        } else if (s.pending === "otp" && input.id === 2) {
          this.later(() => { if (input.text.length > 0) this.connect(s); else this.end(s, "authentication failed"); });
        } else throw new IpcError("input.invalid", "no such prompt");
        return;
      }
      case "bytes": {
        const { out, exit } = echo(s, dec.decode(input.data));
        if (exit) this.later(() => { this.end(s, "remote closed the session"); });
        else if (out) this.later(() => { s.emit({ kind: "bytes", data: enc.encode(out) }); });
        return;
      }
      default:
        return;
    }
  };

  sessionClose: Ipc["sessionClose"] = async ({ sessionId }) => {
    const s = this.sessions.get(sessionId);
    if (!s) throw new IpcError("session.not_found", "session not found");
    this.end(s, "closed by user");
  };

  sessionList: Ipc["sessionList"] = async () => [...this.sessions.values()].map((s) => ({ ...s.info }));

  // ---------- audit ----------

  auditTail: Ipc["auditTail"] = async ({ limit, before }) => {
    const capped = Math.max(1, Math.min(limit, 500));
    return this.audit
      .filter((e) => before === null || e.seq < before)
      .slice()
      .reverse()
      .slice(0, capped)
      .map((e) => ({ ...e, details: { ...e.details } }));
  };

  auditVerify: Ipc["auditVerify"] = async () => ({ ok: true, entries: this.audit.length, brokenAt: null });

  windowDetach: Ipc["windowDetach"] = async ({ sessionId }) => {
    // No-op in the browser: there is no second window to move the session into.
    this.detached.push(sessionId);
  };
}

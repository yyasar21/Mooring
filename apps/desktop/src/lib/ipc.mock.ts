// In-memory implementation of the ADR-0008 contract for `vite dev` (no Tauri) and vitest.
// Hosts are fake (*.example.test); no credential secret is ever stored, only discarded.
// Session/audit methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type {
  AuditEntry,
  ConnectionFields,
  ConnectionSummary,
  CredentialMeta,
  Folder,
  Ipc,
  SessionEventHandler,
  SessionInfo,
  VaultStatus,
} from "./ipc.types";
import { IpcError } from "./ipc.error";
import { bestScore } from "./fuzzy";

import { T0, seedConnections, seedCredentials, seedFolders } from "./ipc.seed";
const enc = new TextEncoder();
const dec = new TextDecoder();

interface MockSession {
  info: SessionInfo;
  host: string;
  emit: SessionEventHandler;
  pending: "tofu" | "otp" | null;
  needsOtp: boolean;
  line: string;
}

export interface MockOptions {
  vault?: VaultStatus;
  /** Delay for simulated async events; 0 = next macrotask. */
  delayMs?: number;
}

export class MockTransport implements Ipc {
  folders = seedFolders();
  connections = seedConnections();
  credentials = seedCredentials();
  audit: AuditEntry[] = [];
  trustedHosts = new Set<string>();
  sessions = new Map<string, MockSession>();
  detached: string[] = [];
  vault: VaultStatus;
  private seq = 0;
  private ids = 0;
  private readonly delayMs: number;

  constructor(opts: MockOptions = {}) {
    this.vault = opts.vault ?? "unlocked";
    this.delayMs = opts.delayMs ?? 0;
    this.record("vault_unlocked", {});
    this.record("session_opened", { connection: "c-web01", protocol: "ssh", peer_identity: "SHA256:mock-web01" });
    this.record("session_closed", { connection: "c-web01", reason: "closed by user" });
  }

  // ---------- helpers ----------

  private id(prefix: string): string {
    this.ids += 1;
    return `${prefix}-${this.ids.toString(16).padStart(4, "0")}`;
  }

  private record(event: string, details: Record<string, string>): void {
    this.seq += 1;
    const at = new Date(Date.parse(T0) + this.seq * 61_000).toISOString();
    this.audit.push({ seq: this.seq, at, prev: this.seq === 1 ? "0".repeat(64) : `mock-${this.seq - 1}`, event, details });
  }

  private later(fn: () => void): void {
    setTimeout(fn, this.delayMs);
  }

  /** Async like a real IPC hop, so callers never rely on synchronous mock behaviour. */
  private unlocked(): Promise<void> {
    return this.vault === "unlocked"
      ? Promise.resolve()
      : Promise.reject(new IpcError("vault.locked", "unlock the vault first"));
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

  private resolve(c: ConnectionSummary): ConnectionSummary {
    let cred = c.credentialId;
    let fid: string | null = c.folderId;
    while (!cred && fid) {
      const f = this.folders.find((x) => x.id === fid);
      cred = f?.defaultCredentialId ?? null;
      fid = f?.parentId ?? null;
    }
    return { ...c, tags: [...c.tags], effectiveCredentialId: cred };
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
  vaultLock: Ipc["vaultLock"] = (reason) => {
    this.vault = "locked";
    this.sessions.clear();
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
    if (credentialId && !this.credentials.some((c) => c.id === credentialId)) {
      throw new IpcError("credential.not_found", "credential not found");
    }
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

  // ---------- credentials ----------

  credentialList: Ipc["credentialList"] = async () => {
    await this.unlocked();
    return this.credentials.map((c) => ({ ...c }));
  };

  credentialCreate: Ipc["credentialCreate"] = async ({ name, kind, username, secret }) => {
    await this.unlocked();
    if (secret.length === 0) throw new IpcError("input.invalid", "secret is required");
    const now = new Date().toISOString();
    const m: CredentialMeta = { id: this.id("cr"), name: this.name(name), kind, username: username.trim(), createdAt: now, updatedAt: now };
    this.credentials.push(m);
    return { ...m };
  };

  credentialUpdateMeta: Ipc["credentialUpdateMeta"] = async ({ id, name, username }) => {
    await this.unlocked();
    const m = this.credentials.find((c) => c.id === id);
    if (!m) throw new IpcError("credential.not_found", "credential not found");
    Object.assign(m, { name: this.name(name), username: username.trim(), updatedAt: new Date().toISOString() });
    return { ...m };
  };

  credentialReplaceSecret: Ipc["credentialReplaceSecret"] = async ({ id, secret }) => {
    await this.unlocked();
    if (!this.credentials.some((c) => c.id === id)) throw new IpcError("credential.not_found", "credential not found");
    if (secret.length === 0) throw new IpcError("input.invalid", "secret is required");
  };

  credentialDelete: Ipc["credentialDelete"] = async ({ id }) => {
    await this.unlocked();
    if (!this.credentials.some((c) => c.id === id)) throw new IpcError("credential.not_found", "credential not found");
    this.credentials = this.credentials.filter((c) => c.id !== id);
    for (const c of this.connections) if (c.credentialId === id) c.credentialId = null;
    for (const f of this.folders) if (f.defaultCredentialId === id) f.defaultCredentialId = null;
  };

  credentialCopyPassword: Ipc["credentialCopyPassword"] = async ({ id }) => {
    await this.unlocked();
    if (!this.credentials.some((c) => c.id === id)) throw new IpcError("credential.not_found", "credential not found");
    this.record("credential_used", { credential: id, purpose: "copy" });
    return { clearsInMs: 30_000 };
  };

  // ---------- sessions ----------

  sessionOpen: Ipc["sessionOpen"] = async ({ connectionId, onEvent }) => {
    await this.unlocked();
    const c = this.connection(connectionId);
    const sessionId = this.id("s");
    const s: MockSession = {
      info: { sessionId, connectionId, protocol: c.protocol, state: "connecting", openedAt: new Date().toISOString() },
      host: c.host,
      emit: onEvent,
      pending: null,
      needsOtp: c.tags.includes("otp"),
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
        });
      } else this.afterTrust(s);
    });
    return { sessionId };
  };

  private afterTrust(s: MockSession): void {
    if (s.needsOtp) {
      s.pending = "otp";
      s.emit({ kind: "prompt", id: 2, message: "Verification code:", secret: true, purpose: "keyboard_interactive" });
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
    this.sessions.delete(s.info.sessionId);
    this.record("session_closed", { connection: s.info.connectionId, reason });
    s.emit({ kind: "closed", reason });
  }

  sessionSend: Ipc["sessionSend"] = async ({ sessionId, input }) => {
    const s = this.sessions.get(sessionId);
    if (!s) throw new IpcError("session.not_found", "session not found");
    switch (input.kind) {
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
        const text = dec.decode(input.data);
        let out = "";
        for (const ch of text) {
          if (ch === "\r") {
            const cmd = s.line.trim();
            s.line = "";
            if (cmd === "exit") {
              this.later(() => { this.end(s, "remote closed the session"); });
              return;
            }
            out += `\r\n${cmd ? `${cmd}\r\n` : ""}$ `;
          } else if (ch === "\x7f") {
            if (s.line.length > 0) {
              s.line = s.line.slice(0, -1);
              out += "\b \b";
            }
          } else {
            s.line += ch;
            out += ch;
          }
        }
        if (out) this.later(() => { s.emit({ kind: "bytes", data: enc.encode(out) }); });
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

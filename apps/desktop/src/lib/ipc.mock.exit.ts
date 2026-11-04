// Base of MockTransport: shared mock plumbing (vault state, audit, timers) and the ADR-0010
// commands — forwards, SFTP with progress, auto-lock policy, syslog mirror, the `vault:locked` event.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type {
  AuditEntry,
  AutoLockPolicy,
  ExitIpc,
  ForwardInfo,
  LockReason,
  ProgressHandler,
  SyslogConfig,
  VaultLockedHandler,
  VaultStatus,
} from "./ipc.types";
import { FORWARD_LIMITS } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { T0 } from "./ipc.seed";
import { MockRemoteFs } from "./ipc.mock.fs";
import { MockPicks } from "./ipc.mock.picks";
import { baseName, normalizeRemote } from "./remotePath";
import { hasErrors, validateForward, validatePolicy, validateSyslog } from "./validate.exit";

export interface MockOptions {
  vault?: VaultStatus;
  /** Delay for simulated async events; 0 = next macrotask. */
  delayMs?: number;
  /** Delay between simulated transfer blocks; 0 = next macrotask. */
  transferStepMs?: number;
}

interface MockTransfer {
  sessionId: string;
  /** Latest progress, for `sftp_transfers`. */
  state: "running";
  timer: ReturnType<typeof setTimeout> | null;
  emit: ProgressHandler;
  done: number;
  total: number;
}

/** Simulated transfers move in this many blocks. */
const STEPS = 8;

export abstract class MockExitBase implements ExitIpc {
  audit: AuditEntry[] = [];
  vault: VaultStatus;
  forwards = new Map<string, ForwardInfo[]>();
  fs = new Map<string, MockRemoteFs>();
  transfers = new Map<string, MockTransfer>();
  /** Local picks made through the Rust-side dialog (B-4). */
  picks = new MockPicks();
  policy: AutoLockPolicy = { idleMinutes: 15, onScreenLock: true, onSleep: true, onWindowHidden: true };
  syslog: SyslogConfig | null = null;
  /** Set to make every new transfer fail half way (tests). */
  failTransfers = false;
  protected readonly delayMs: number;
  protected readonly stepMs: number;
  private lockHandlers = new Set<VaultLockedHandler>();
  private seq = 0;
  private exitIds = 0;

  constructor(opts: MockOptions) {
    this.vault = opts.vault ?? "unlocked";
    this.delayMs = opts.delayMs ?? 0;
    this.stepMs = opts.transferStepMs ?? 0;
  }

  /** Throws unless `sessionId` is a live, connected SSH session. */
  protected abstract requireSsh(sessionId: string): void;

  protected record(event: string, details: Record<string, string>): void {
    this.seq += 1;
    const at = new Date(Date.parse(T0) + this.seq * 61_000).toISOString();
    this.audit.push({ seq: this.seq, at, prev: this.seq === 1 ? "0".repeat(64) : `mock-${this.seq - 1}`, event, details });
  }

  protected later(fn: () => void): void {
    setTimeout(fn, this.delayMs);
  }

  /** Async like a real IPC hop, so callers never rely on synchronous mock behaviour. */
  protected unlocked(): Promise<void> {
    return this.vault === "unlocked"
      ? Promise.resolve()
      : Promise.reject(new IpcError("vault.locked", "unlock the vault first"));
  }

  private exitId(prefix: string): string {
    this.exitIds += 1;
    return `${prefix}-${this.exitIds.toString(16).padStart(4, "0")}`;
  }

  /** Forwards and transfers die with their session (ADR-0010). */
  protected dropSession(sessionId: string): void {
    for (const [id, t] of this.transfers) {
      if (t.sessionId !== sessionId) continue;
      if (t.timer) clearTimeout(t.timer);
      this.transfers.delete(id);
      t.emit({ transferId: id, bytesDone: t.done, bytesTotal: t.total, state: "failed", error: "session closed" });
    }
    this.forwards.delete(sessionId);
    this.fs.delete(sessionId);
  }

  /**
   * What every lock does on the backend (ADR-0010, M-10): picks are forgotten and forwards with
   * external exposure are closed and audited. Sessions, loopback forwards and transfers survive.
   */
  protected lockBackend(): void {
    this.vault = "locked";
    this.picks.clear();
    for (const [sessionId, list] of this.forwards) {
      for (const f of list.filter((x) => x.exposure === "external")) {
        this.record("session.forward.close", { session: sessionId, forward: f.id, reason: "vault locked" });
      }
      this.forwards.set(sessionId, list.filter((x) => x.exposure !== "external"));
    }
  }

  /** Test/dev hook: the backend locks on its own and emits `vault:locked`. */
  fireAutoLock(reason: LockReason): void {
    this.lockBackend();
    this.record("vault.lock", { reason });
    for (const h of [...this.lockHandlers]) h({ reason });
  }

  onVaultLocked(handler: VaultLockedHandler): () => void {
    this.lockHandlers.add(handler);
    return () => { this.lockHandlers.delete(handler); };
  }

  // ---------- forwarding ----------

  private live(sessionId: string): ForwardInfo[] {
    this.requireSsh(sessionId);
    let list = this.forwards.get(sessionId);
    if (!list) {
      list = [];
      this.forwards.set(sessionId, list);
    }
    return list;
  }

  forwardOpen: ExitIpc["forwardOpen"] = async ({ sessionId, ...f }) => {
    await this.unlocked();
    const list = this.live(sessionId);
    const errors = validateForward(f);
    if (hasErrors(errors)) throw new IpcError("input.invalid", Object.values(errors)[0] ?? "invalid forward");
    if (list.length >= FORWARD_LIMITS.perSession) throw new IpcError("forward.limit", "too many forwards on this session");
    let port = f.bind.port;
    if (port === 0) port = 40_000 + this.exitIds;
    if (list.some((x) => x.bind.port === port && x.kind !== "remote" && f.kind !== "remote")) {
      throw new IpcError("forward.bind", "bind failed: address already in use");
    }
    const info: ForwardInfo = {
      id: this.exitId("fw"),
      kind: f.kind,
      bind: { host: f.bind.host, port },
      target: f.target ? { ...f.target } : null,
      exposure: f.exposure,
      openedAt: new Date().toISOString(),
      connections: 0,
    };
    list.push(info);
    this.record("session.forward.open", { session: sessionId, kind: f.kind, exposure: f.exposure });
    return structuredClone(info);
  };

  forwardClose: ExitIpc["forwardClose"] = async ({ sessionId, forwardId }) => {
    await this.unlocked();
    const list = this.live(sessionId);
    const i = list.findIndex((x) => x.id === forwardId);
    if (i < 0) throw new IpcError("forward.not_found", "forward not found");
    list.splice(i, 1);
    this.record("session.forward.close", { session: sessionId, forward: forwardId });
  };

  forwardList: ExitIpc["forwardList"] = async ({ sessionId }) => {
    await this.unlocked();
    return structuredClone(this.live(sessionId));
  };

  // ---------- SFTP ----------

  private sftp(sessionId: string): MockRemoteFs {
    this.requireSsh(sessionId);
    let fs = this.fs.get(sessionId);
    if (!fs) {
      fs = new MockRemoteFs();
      this.fs.set(sessionId, fs);
    }
    return fs;
  }

  sftpList: ExitIpc["sftpList"] = async ({ sessionId, path }) => {
    await this.unlocked();
    return this.sftp(sessionId).list(path);
  };
  sftpStat: ExitIpc["sftpStat"] = async ({ sessionId, path }) => {
    await this.unlocked();
    return this.sftp(sessionId).stat(path);
  };
  sftpMkdir: ExitIpc["sftpMkdir"] = async ({ sessionId, path }) => {
    await this.unlocked();
    this.sftp(sessionId).mkdir(path);
  };
  sftpRename: ExitIpc["sftpRename"] = async ({ sessionId, from, to }) => {
    await this.unlocked();
    this.sftp(sessionId).rename(from, to);
  };
  sftpRemove: ExitIpc["sftpRemove"] = async ({ sessionId, path }) => {
    await this.unlocked();
    this.sftp(sessionId).remove(path);
  };

  private startTransfer(sessionId: string, total: number, direction: string, emit: ProgressHandler, land: () => void): string {
    const id = this.exitId("tx");
    const fail = this.failTransfers;
    const t: MockTransfer = { sessionId, state: "running", timer: null, emit, done: 0, total };
    const outcome = (state: "done" | "failed", error: string | null) => {
      this.transfers.delete(id);
      this.record("session.sftp.transfer", { session: sessionId, direction, bytes: String(t.done), outcome: state });
      emit({ transferId: id, bytesDone: t.done, bytesTotal: total, state, error });
    };
    const step = () => {
      t.done = Math.min(total, t.done + Math.ceil(total / STEPS));
      if (fail && t.done >= total / 2) {
        outcome("failed", "permission denied");
        return;
      }
      if (t.done >= total) {
        land();
        outcome("done", null);
        return;
      }
      emit({ transferId: id, bytesDone: t.done, bytesTotal: total, state: "running", error: null });
      t.timer = setTimeout(step, this.stepMs);
    };
    this.transfers.set(id, t);
    // The first message (0 of total) goes out after the command returns, like the real channel.
    t.timer = setTimeout(() => {
      emit({ transferId: id, bytesDone: 0, bytesTotal: total, state: "running", error: null });
      t.timer = setTimeout(step, this.stepMs);
    }, 0);
    return id;
  }

  sftpPickLocal: ExitIpc["sftpPickLocal"] = async ({ sessionId, mode }) => {
    await this.unlocked();
    this.requireSsh(sessionId);
    return this.picks.open(sessionId, mode);
  };

  sftpDownload: ExitIpc["sftpDownload"] = async ({ sessionId, remote, pick, overwrite, onProgress }) => {
    await this.unlocked();
    const folder = this.picks.peek(pick, sessionId, "folder");
    const fs = this.sftp(sessionId);
    const target = `${folder}/${baseName(normalizeRemote(remote))}`;
    let total: number;
    try {
      total = fs.fileSize(remote);
    } catch (e: unknown) {
      this.picks.consume(pick);
      throw e;
    }
    // Refused before the pick is used, so the overwrite retry can present the same pick.
    if (this.picks.localFiles.has(target) && overwrite !== true) throw new IpcError("sftp.exists", "the local file already exists");
    this.picks.consume(pick);
    return { transferId: this.startTransfer(sessionId, total, "download", onProgress, () => { this.picks.localFiles.add(target); }) };
  };

  sftpUpload: ExitIpc["sftpUpload"] = async ({ sessionId, pick, remoteDir, onProgress }) => {
    await this.unlocked();
    const name = this.picks.peek(pick, sessionId, "file");
    this.picks.consume(pick);
    const fs = this.sftp(sessionId);
    const dir = normalizeRemote(remoteDir);
    fs.list(dir);
    const total = 3_145_728 + name.length * 4096;
    return { transferId: this.startTransfer(sessionId, total, "upload", onProgress, () => { fs.put(dir, baseName(`/${name}`), total); }) };
  };

  sftpTransfers: ExitIpc["sftpTransfers"] = async ({ sessionId }) => {
    await this.unlocked();
    this.requireSsh(sessionId);
    return [...this.transfers]
      .filter(([, t]) => t.sessionId === sessionId)
      .map(([transferId, t]) => ({ transferId, bytesDone: t.done, bytesTotal: t.total, state: t.state, error: null }));
  };

  sftpCancel: ExitIpc["sftpCancel"] = async ({ sessionId, transferId }) => {
    const t = this.transfers.get(transferId);
    if (!t || t.sessionId !== sessionId) throw new IpcError("transfer.not_found", "transfer not found");
    if (t.timer) clearTimeout(t.timer);
    this.transfers.delete(transferId);
    this.record("session.sftp.transfer", { session: sessionId, bytes: String(t.done), outcome: "cancelled" });
    this.later(() => { t.emit({ transferId, bytesDone: t.done, bytesTotal: t.total, state: "cancelled", error: null }); });
  };

  // ---------- auto-lock ----------

  autolockGet: ExitIpc["autolockGet"] = async () => {
    await this.unlocked();
    return { ...this.policy };
  };

  autolockSet: ExitIpc["autolockSet"] = async (policy) => {
    await this.unlocked();
    const err = validatePolicy(policy);
    if (err) throw new IpcError("input.invalid", err);
    this.policy = { ...policy };
    this.record("vault.policy_changed", { idle_minutes: String(policy.idleMinutes ?? "never") });
    return { ...this.policy };
  };

  // ---------- syslog mirror ----------

  syslogGet: ExitIpc["syslogGet"] = async () => {
    await this.unlocked();
    return this.syslog ? { ...this.syslog } : null;
  };

  syslogSet: ExitIpc["syslogSet"] = async (config) => {
    await this.unlocked();
    const errors = validateSyslog(config);
    if (hasErrors(errors)) throw new IpcError("input.invalid", Object.values(errors)[0] ?? "invalid syslog settings");
    this.syslog = { ...config };
    this.record("audit.syslog_changed", { transport: config.transport, enabled: String(config.enabled) });
    return { ...this.syslog };
  };

  /** Mock rule: hosts under `.invalid` (RFC 6761) never answer. */
  syslogTest: ExitIpc["syslogTest"] = async () => {
    await this.unlocked();
    if (!this.syslog) throw new IpcError("syslog.not_configured", "save the syslog settings first");
    return this.syslog.host.endsWith(".invalid")
      ? { ok: false, error: "connection refused" }
      : { ok: true, error: null };
  };
}

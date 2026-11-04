// Mock ADR-0017 vault sync as rust-core S2 serves it. No bucket exists: the config and status
// live in memory and runs are simulated. Native dialogs (the certificate trust prompt of
// `sync_configure` / `sync_now`, the "Discard and resolve" confirmation of `sync_resolve_fork`)
// are simulated by the `trustCert` / `confirmResolve` knobs. Nothing here holds a secret.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { CredentialMeta, SyncConfig, SyncIpc, SyncMergeConflict, SyncOutcome, SyncStatus, SyncStatusHandler, SyncTrustConflict } from "./ipc.types";
import { IpcError } from "./ipc.error";
import type { RemoteTarget } from "./ipc.mock.remote";
import { MockVsphereBase } from "./ipc.mock.vsphere";
import { isVaultId, normalizeBackend, validateSyncConfig } from "./validate.secrets";

/** `sync_status.vaultId` of the mock device; a joining device types it. */
export const MOCK_VAULT_ID = "7b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";
const MOCK_T0_UNIX = Math.floor(Date.parse("2026-11-01T08:00:00Z") / 1000);

const EMPTY: SyncStatus = {
  state: "disabled", config: null, vaultId: MOCK_VAULT_ID, deviceId: null, counter: 0, remoteCounter: null, remoteDevice: null,
  remoteCreatedUnix: null, lastPullUnix: null, lastPushUnix: null, lastRunUnix: null, lastOutcome: null, lastError: null, alarm: null,
  conflicts: [], nextRunUnix: null,
};

export abstract class MockSyncBase extends MockVsphereBase implements SyncIpc {
  syncState: SyncStatus = structuredClone(EMPTY);
  /** The native trust prompt: true = "Trust and remember"; false = Cancel (`http.trust_prompt`). */
  trustCert = true;
  /** The native "Discard and resolve" confirmation of `sync_resolve_fork`. */
  confirmResolve = true;
  /** Conflicts the next run "finds" on the remote (the run then merges). */
  remoteEdits: SyncMergeConflict[] = [];
  /**
   * Hosts the other device ("laptop") trusted with a *different* certificate: the next run's
   * apply keeps both pins (review 6b L-35), audits `trust_conflict` and lists the host under
   * `sync_status.conflicts` until the pins are removed.
   */
  remoteTrust: RemoteTarget[] = [];
  private syncHandlers = new Set<SyncStatusHandler>();
  private syncBusy = false;
  private clock = MOCK_T0_UNIX;
  /** Credentials the mock consults for sync keys and `external_ref` rows. */
  protected abstract credentialRows(): CredentialMeta[];

  private now(): number {
    this.clock += 60;
    return this.clock;
  }

  /** The standing trust conflicts, computed live from the pins like `sync_trust::conflicts`. */
  private trustConflicts(): SyncTrustConflict[] {
    return this.conflictingPins().map((k) => {
      const [protocol, name] = k.split("|") as [string, string];
      return { kind: "trust", id: `known_${protocol}_certs`, name };
    });
  }

  /** `sync_status` as the wire carries it: the last merge's conflicts, then the live trust conflicts. */
  private snapshot(): SyncStatus {
    const snap = structuredClone(this.syncState);
    return { ...snap, conflicts: [...snap.conflicts.filter((c) => c.kind !== "trust"), ...this.trustConflicts()] };
  }

  protected emitSync(): void {
    for (const h of [...this.syncHandlers]) h(this.snapshot());
  }

  /** A removal clears a trust conflict at once, so the status event follows it. */
  protected override removePins(protocol: "rdp" | "vnc", host: string, port: number): number {
    const before = this.conflictingPins().length;
    const n = super.removePins(protocol, host, port);
    if (this.conflictingPins().length !== before) this.emitSync();
    return n;
  }

  private patchSync(p: Partial<SyncStatus>): void {
    this.syncState = { ...this.syncState, ...p };
    this.emitSync();
  }

  private needsConfig(): SyncConfig {
    const c = this.syncState.config;
    if (!c) throw new IpcError("sync.not_configured", "sync is not configured");
    return c;
  }

  private checkKey(credentialId: string): void {
    const cred = this.credentialRows().find((c) => c.id === credentialId);
    if (!cred) throw new IpcError("credential.not_found", "credential not found");
    if (cred.kind !== "s3_access_key") throw new IpcError("credential.incompatible", "S3 access key is only for vault sync.");
  }

  /** Mock rule: endpoints under `.invalid` lack conditional writes; hosts named `untrusted` carry an unpinned certificate. */
  private probe(endpoint: string): void {
    if (endpoint.includes(".invalid")) throw new IpcError("sync.unsupported_backend", "the backend has no conditional writes");
    if (endpoint.includes("untrusted") && !this.trustCert) throw new IpcError("http.trust_prompt", "the certificate is not trusted");
    if (endpoint.includes("untrusted")) this.record("cert_decision", { protocol: "sync", decision: "trust_remember" });
  }

  onSyncStatus(handler: SyncStatusHandler): () => void {
    this.syncHandlers.add(handler);
    return () => { this.syncHandlers.delete(handler); };
  }

  syncStatus: SyncIpc["syncStatus"] = async () => this.snapshot();

  syncConfigure: SyncIpc["syncConfigure"] = async (a) => {
    await this.unlocked();
    if ((a.backend.kind as string) !== "s3") throw new IpcError("sync.backend_unsupported", "only S3-compatible storage is supported");
    const errors = validateSyncConfig(a);
    const field = Object.keys(errors)[0];
    if (field) throw new IpcError("input.invalid", `invalid ${field}`);
    this.checkKey(a.credentialId);
    const config: SyncConfig = { backend: normalizeBackend(a.backend), credentialId: a.credentialId, intervalMinutes: a.intervalMinutes };
    this.probe(config.backend.endpoint);
    const t = this.now();
    this.patchSync({
      state: this.syncState.alarm ? this.syncState.state : "idle", config, deviceId: this.syncState.deviceId ?? "dev-0001", lastError: null,
      nextRunUnix: config.intervalMinutes === null || this.syncState.alarm ? null : t + 30,
    });
    this.record("sync.configured", { endpoint: config.backend.endpoint, bucket: config.backend.bucket });
    return structuredClone(config);
  };

  private async run(): Promise<SyncOutcome> {
    const config = this.needsConfig();
    if (this.syncState.alarm?.type === "fork") throw new IpcError("sync.fork", "resolve the fork first");
    if (this.syncState.alarm?.type === "rollback") throw new IpcError("sync.rollback", "resolve the rollback first");
    if (this.syncBusy) throw new IpcError("sync.in_progress", "a sync is already running");
    this.syncBusy = true;
    this.patchSync({ state: "running" });
    try {
      this.probe(config.backend.endpoint);
      const t = this.now();
      const counter = this.syncState.counter + 1;
      let outcome: SyncOutcome;
      const pulledTrust = this.remoteTrust.length > 0;
      for (const target of this.remoteTrust.splice(0)) {
        // The other device's trust line is kept beside ours (never resolved silently); Rust audits the pair.
        await this.pin(target, new Date(t * 1000).toISOString(), "#laptop");
        this.record("trust_conflict", { file: `known_${target.protocol}_certs`, host: `${target.host}:${String(target.port)}` });
      }
      if (this.remoteEdits.length > 0 || pulledTrust) {
        const conflicts = this.remoteEdits.map((c) => structuredClone(c));
        this.remoteEdits = [];
        outcome = { type: "merged", counter, conflicts };
        this.record("sync.merged", { counter: String(counter), conflicts: String(conflicts.length) });
        this.patchSync({ counter, conflicts, lastPullUnix: t, lastPushUnix: t, remoteDevice: "laptop", remoteCreatedUnix: t - 600 });
      } else if (this.syncState.counter === 0) {
        outcome = { type: "pushed", counter };
        this.record("sync.pushed", { counter: String(counter), bytes: "48211" });
        this.patchSync({ counter, lastPushUnix: t, remoteDevice: "dev-0001", remoteCreatedUnix: t });
      } else {
        outcome = { type: "noChange", counter: this.syncState.counter };
        this.record("sync.pulled", { counter: String(this.syncState.counter) });
        this.patchSync({ lastPullUnix: t });
      }
      this.patchSync({ state: "idle", lastRunUnix: t, lastOutcome: outcome, lastError: null, nextRunUnix: config.intervalMinutes === null ? null : t + config.intervalMinutes * 60 });
      return structuredClone(outcome);
    } catch (e: unknown) {
      const err = e instanceof IpcError ? { code: e.code, message: e.message } : { code: "internal", message: "internal error" };
      this.patchSync({ state: "error", lastRunUnix: this.now(), lastError: err });
      throw e;
    } finally {
      this.syncBusy = false;
    }
  }

  syncNow: SyncIpc["syncNow"] = async () => {
    await this.unlocked();
    return this.run();
  };

  /** Test/dev hook: the background runner met an unpinned certificate (no dialog in the background). */
  simulateTrustPrompt(): void {
    this.needsConfig();
    this.patchSync({ state: "error", lastRunUnix: this.now(), lastError: { code: "http.trust_prompt", message: "the certificate is not trusted" } });
  }

  /** Test/dev hook: a pull found a fork or a rollback; the runner stops until it is resolved. */
  simulateAlarm(type: "fork" | "rollback"): void {
    this.needsConfig();
    const remote = this.syncState.counter + 1;
    const alarm = type === "fork" ? { type, remote } as const : { type, remote: remote - 2, last: this.syncState.counter } as const;
    this.record(`sync.${type}_detected`, { remote: String(alarm.remote), last: String(this.syncState.counter) });
    this.patchSync({ state: type, alarm, remoteCounter: alarm.remote, remoteDevice: "laptop", remoteCreatedUnix: this.now() - 300, nextRunUnix: null });
  }

  syncResolveFork: SyncIpc["syncResolveFork"] = async ({ keep }) => {
    await this.unlocked();
    const config = this.needsConfig();
    const alarm = this.syncState.alarm;
    if (!alarm) throw new IpcError("input.invalid", "invalid keep: no fork or rollback is pending");
    if ((keep as string) !== "local" && (keep as string) !== "remote") throw new IpcError("input.invalid", "invalid keep");
    if (!this.confirmResolve) throw new IpcError("sync.cancelled", "the confirmation was cancelled");
    const t = this.now();
    const counter = Math.max(alarm.remote, this.syncState.counter) + 1;
    const outcome: SyncOutcome = keep === "local" ? { type: "pushed", counter } : { type: "pulled", counter };
    this.record("sync.fork_resolved", { keep, counter: String(counter) });
    this.patchSync({
      state: "idle", alarm: null, remoteCounter: null, counter, lastRunUnix: t, lastOutcome: outcome, lastError: null, conflicts: [],
      ...(keep === "local" ? { lastPushUnix: t } : { lastPullUnix: t }), nextRunUnix: config.intervalMinutes === null ? null : t + config.intervalMinutes * 60,
    });
    return structuredClone(outcome);
  };

  syncDisable: SyncIpc["syncDisable"] = async ({ deleteRemote }) => {
    await this.unlocked();
    this.needsConfig();
    this.remoteEdits = [];
    this.syncState = structuredClone(EMPTY);
    this.emitSync();
    this.record("sync.disabled", { delete_remote: String(deleteRemote) });
  };

  /**
   * Mock rule for a fresh device: the bootstrap vault is unlocked and holds nothing created in
   * this process except `s3_access_key` credentials (the seeds stand in for the synced inventory).
   */
  vaultJoin: SyncIpc["vaultJoin"] = async (a) => {
    if (this.vault === "missing") throw new IpcError("vault.missing", "create the bootstrap vault first");
    await this.unlocked();
    if ((a.backend.kind as string) !== "s3") throw new IpcError("sync.backend_unsupported", "only S3-compatible storage is supported");
    const errors = validateSyncConfig({ backend: a.backend, credentialId: a.credentialId, intervalMinutes: a.intervalMinutes });
    const field = Object.keys(errors)[0];
    if (field) throw new IpcError("input.invalid", `invalid ${field}`);
    if (!isVaultId(a.vaultId)) throw new IpcError("input.invalid", "invalid vaultId");
    this.checkKey(a.credentialId);
    const created = this.credentialRows().filter((c) => c.id.startsWith("cr-new-") && c.kind !== "s3_access_key");
    if (this.syncState.deviceId !== null || created.length > 0) throw new IpcError("sync.store_not_empty", "this device already holds data");
    this.probe(a.backend.endpoint);
    if (a.vaultId.trim().toLowerCase() !== MOCK_VAULT_ID) throw new IpcError("sync.wrong_vault", "no vault with this id in the bucket");
    if (a.password.length === 0) throw new IpcError("vault.unlock", "wrong password");
    const t = this.now();
    const config: SyncConfig = { backend: normalizeBackend(a.backend), credentialId: a.credentialId, intervalMinutes: a.intervalMinutes };
    this.record("sync.joined", { vault: MOCK_VAULT_ID, counter: "4" });
    this.patchSync({
      state: "idle", config, deviceId: "dev-0002", counter: 4, lastPullUnix: t, lastRunUnix: t, lastOutcome: { type: "pulled", counter: 4 },
      remoteDevice: "laptop", remoteCreatedUnix: t - 3600, nextRunUnix: config.intervalMinutes === null ? null : t + 30,
    });
    return this.vault;
  };
}

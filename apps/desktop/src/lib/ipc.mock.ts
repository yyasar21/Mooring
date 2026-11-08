// In-memory implementation of the ADR-0008 / ADR-0009 contract for `vite dev` (no Tauri) and vitest.
// Hosts are fake (*.example.test); no credential secret is ever stored, only discarded.
// Session/audit methods stay `async` to mirror the IPC signature even when they do not await.
// The tree and credential commands live in `ipc.mock.tree.ts`; this file keeps app/vault and SSH.
/* eslint-disable @typescript-eslint/require-await */
import type { CloseCode, ConnectionSummary, CredentialMeta, Ipc, SessionEventHandler, SessionInfo } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { echo } from "./ipc.mock.shell";
import type { MockOptions } from "./ipc.mock.exit";
import type { RemoteTarget } from "./ipc.mock.remote";
import { MockTreeBase } from "./ipc.mock.tree";
import { MockHopChain, type MockHop } from "./ipc.mock.hops";
import { MockLeaseBook } from "./ipc.mock.leases";
import { DEFAULT_SK_KNOBS, signWithTouch, skPreflight, type MockSkKnobs } from "./ipc.mock.sk";
import { DEFAULT_PIV_KNOBS, MockAgentCards, PIN_PROMPT_ID, askPin, pinOutcome, pivPreflight, type MockPivKnobs } from "./ipc.mock.piv";

export type { MockOptions } from "./ipc.mock.exit";
const enc = new TextEncoder();
const dec = new TextDecoder();
const str = (v: unknown) => (typeof v === "string" ? v : null);

interface MockSession {
  info: SessionInfo;
  host: string;
  emit: SessionEventHandler;
  pending: "tofu" | "otp" | "credential" | "pin" | null;
  needsOtp: boolean;
  /** The connection's effective credential is `prompt`: ask for the account after TOFU. */
  askCredential: { username: string | null; domain: string | null; needsDomain: boolean } | null;
  line: string;
  /** ADR-0025: the jump hosts brought up before the target (null = direct). */
  chain: MockHopChain | null;
  /** ADR-0024: the target signs in with this security key (its fingerprint). */
  skFingerprint: string | null;
  /** ADR-0027: the target signs in with this smart card (through the agent, with a PIN if needed). */
  piv: CredentialMeta | null;
}

/** The `prompt` credential pre-fills of a connection (null = it stores its own secret). */
function askOf(c: ConnectionSummary, cred: CredentialMeta | null): { username: string | null; domain: string | null } | null {
  if (cred?.kind !== "prompt") return null;
  return { username: c.usernameOverride ?? str(cred.fields.username), domain: c.domainOverride ?? str(cred.fields.domain) };
}

export class MockTransport extends MockTreeBase implements Ipc {
  trustedHosts = new Set<string>();
  sessions = new Map<string, MockSession>();
  /** ADR-0026: leases of sessions whose credential is a Vault `database` reference. */
  leaseBook = new MockLeaseBook();
  /** Knobs: the database role's lease TTL (s), whether Vault refuses the lease or its renewal. */
  leaseTtl = 3600;
  leaseRefused = false;
  leaseRenewFails = false;
  /** ADR-0024 knobs: does the agent hold the security key, and is it touched in time. */
  sk: MockSkKnobs = { ...DEFAULT_SK_KNOBS };
  /** ADR-0027 knobs: does the agent hold the card's key, and does the card take the PIN. */
  piv: MockPivKnobs = { ...DEFAULT_PIV_KNOBS };
  /** L-49: cards loaded into the mock ssh-agent by a PIN, for its 60-minute lifetime. */
  agentCards = new MockAgentCards();

  constructor(opts: MockOptions = {}) {
    super(opts);
    this.webDemo = opts.webDemo ?? false;
    this.guardSyncedTree(); // ADR-0015: synced subtrees are read-only in the store
    this.record("vault_unlocked", {});
    this.record("session_opened", { connection: "c-web01", protocol: "ssh", peer_identity: "SHA256:mock-web01" });
    this.record("session_closed", { connection: "c-web01", reason: "closed by user" });
    this.record("credential.sk_converted", { id: "cr-yubi" });
  }

  // ---------- helpers ----------

  protected requireSsh(sessionId: string): void {
    const s = this.sessions.get(sessionId);
    if (!s && this.remote.has(sessionId)) throw new IpcError("input.invalid", "invalid sessionId: not an SSH session");
    if (!s) throw new IpcError("session.not_found", "session not found");
    if (s.info.protocol !== "ssh") throw new IpcError("input.invalid", "invalid sessionId: not an SSH session");
    if (s.info.state !== "connected") throw new IpcError("session.not_connected", "the session is not connected yet");
  }

  protected target(connectionId: string): RemoteTarget {
    const c = this.connection(connectionId);
    const port = c.port ?? (c.protocol === "rdp" ? 3389 : c.protocol === "vnc" ? 5900 : 443);
    return { connectionId, protocol: c.protocol, name: c.name, host: c.host, port, tags: [...c.tags], options: c.options };
  }

  protected storeOptions(id: string, options: NonNullable<ConnectionSummary["options"]>): void { this.connection(id).options = options; }

  protected connectionHosts(protocol: "rdp" | "vnc"): { host: string; port: number }[] {
    return this.connections.filter((c) => c.protocol === protocol).map((c) => ({ host: c.host, port: c.port ?? (protocol === "rdp" ? 3389 : 5900) }));
  }

  protected credentialRows() { return this.creds.items; }
  protected connectionRows() { return this.connections; }
  protected liveSessionIds(): string[] { return [...this.sessions.keys(), ...this.remoteInfos().map((s) => s.sessionId), ...this.kubeInfos().map((s) => s.sessionId)]; }
  protected closeSessionForUpdate(sessionId: string): Promise<void> { return this.sessionClose({ sessionId }); }

  protected sshSession(sessionId: string): MockSession | null {
    return this.sessions.get(sessionId) ?? null;
  }

  /** The resolved jump hosts of a connection, in chain order. */
  private hopsOf(c: ConnectionSummary): MockHop[] {
    return (c.via ?? []).map((id) => {
      const h = this.resolve(this.connection(id));
      const cred = h.effectiveCredentialId ? this.creds.get(h.effectiveCredentialId) : null;
      return { connectionId: h.id, name: h.name, host: h.host, port: h.port ?? 22, fail: h.tags.includes("hop-fail"), ask: askOf(h, cred) };
    });
  }

  protected viaHopsOf(connectionId: string): MockHop[] { return this.hopsOf(this.resolve(this.connection(connectionId))); }
  protected hopTrusted(host: string): boolean { return this.trustedHosts.has(host); }
  protected hopChainOf(connectionId: string, emit: SessionEventHandler, done: () => void, fail: (reason: string) => void): MockHopChain | null {
    const hops = this.viaHopsOf(connectionId);
    return hops.length > 0 ? new MockHopChain(hops, this.hopEnv(emit, done, fail), connectionId) : null;
  }

  private hopEnv(emit: SessionEventHandler, done: () => void, fail: (reason: string) => void) {
    return {
      emit,
      trusted: this.trustedHosts,
      record: (e: string, d: Record<string, string>) => { this.record(e, d); },
      later: (fn: () => void) => { this.later(fn); },
      done,
      fail,
    };
  }

  // ---------- app / vault ----------

  appInfo: Ipc["appInfo"] = () =>
    Promise.resolve({
      name: this.buildChannel === "dev" ? "Mooring Dev" : "Mooring",
      version: "dev",
      os: "browser",
      arch: "mock",
      debug: true,
      portableDataDir: this.portableDataDir,
      channel: this.buildChannel,
      identifier: this.buildChannel === "dev" ? "io.github.yyasar21.mooring.dev" : "io.github.yyasar21.mooring",
    });
  vaultStatus: Ipc["vaultStatus"] = () => Promise.resolve(this.vault);
  vaultCreate: Ipc["vaultCreate"] = (password) => {
    this.vault = "unlocked";
    this.masterPassword = password;
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
    if (this.masterPassword !== null) this.masterPassword = next;
    this.suspendBiometric("password_changed");
    this.record("password_changed", {});
    return Promise.resolve(this.vault);
  };

  // ---------- sessions ----------

  sessionOpen: Ipc["sessionOpen"] = async ({ connectionId, size, onEvent, onFrame }) => {
    await this.unlocked();
    const c = this.resolve(this.connection(connectionId));
    const cred = c.effectiveCredentialId ? this.creds.get(c.effectiveCredentialId) : null;
    if (cred) this.compatible(cred.id, c.protocol, "primary");
    const hops = this.hopsOf(c);
    if (c.protocol === "rdp" || c.protocol === "vnc") {
      // Hop events are queued first, so they arrive before the target's (R1 emits them in hop order).
      if (hops.length > 0) new MockHopChain(hops, this.hopEnv(onEvent, () => undefined, () => undefined), c.id).startQuiet();
      return this.openRemote(this.target(connectionId), size, onEvent, onFrame);
    }
    // K4: Kubernetes opens with kube_open (the cluster) and kube_exec_open (a shell), never session_open.
    if (c.protocol === "kubernetes") throw new IpcError("input.invalid", "invalid connectionId: Kubernetes sessions open with kube_open");
    if (onFrame && c.protocol === "ssh") throw new IpcError("input.invalid", "invalid onFrame: not accepted for ssh sessions");
    const ask = askOf(c, cred);
    // R3 `connect_plan::prefetch`: a database reference resolves before the connect and needs a lease.
    const dynamicDb = cred?.kind === "external_ref" && cred.fields.engine === "database";
    if (dynamicDb && this.leaseRefused) {
      this.record("secret_failed", { credential: cred.id, category: "lease" });
      throw new IpcError("secret.lease_failed", "Vault returned database credentials without a lease");
    }
    // R4 `sk_keys::preflight`: before any network I/O.
    if (cred?.kind === "ssh_sk_key") skPreflight(cred.fields, this.sk);
    // R5 pre-flight: a card key the agent lacks, with no module to load it, is refused before any I/O.
    if (cred?.kind === "smart_card") pivPreflight(cred, this.piv);
    const sessionId = this.id("s");
    if (dynamicDb) {
      this.leaseBook.issue(sessionId, { ttl: this.leaseTtl, renewable: true, failRenew: this.leaseRenewFails });
      this.record("secret_lease_issued", { credential: cred.id, engine: "database", ttl: String(this.leaseTtl) });
    }
    const s: MockSession = {
      info: { sessionId, connectionId, protocol: c.protocol, state: "connecting", openedAt: new Date().toISOString() },
      host: c.host,
      emit: onEvent,
      pending: null,
      needsOtp: c.tags.includes("otp"),
      askCredential: ask ? { ...ask, needsDomain: false } : null,
      line: "",
      chain: null,
      skFingerprint: cred?.kind === "ssh_sk_key" ? (cred.fingerprint ?? "") : null,
      piv: cred?.kind === "smart_card" ? cred : null,
    };
    this.sessions.set(sessionId, s);
    const target = () => {
      if (!this.trustedHosts.has(c.host)) {
        s.pending = "tofu";
        onEvent({
          kind: "prompt",
          id: 1,
          message: `The authenticity of host ${c.host} can't be established.\nED25519 key fingerprint is SHA256:mock-${c.name}.\nTrust this host and continue?`,
          secret: false,
          purpose: "host_key_trust",
          account: null,
          certificate: null,
        });
      } else this.afterTrust(s);
    };
    if (hops.length > 0) {
      const chain = new MockHopChain(hops, this.hopEnv(onEvent, target, (reason) => { this.end(s, reason, "hop_failed"); }), c.id);
      s.chain = chain;
      this.later(() => { chain.start(); });
    } else this.later(target);
    return { sessionId };
  };

  private afterTrust(s: MockSession): void {
    if (s.piv) {
      if (this.piv.agentHolds || this.agentCards.holds(s.piv.fingerprint ?? "")) this.signedInWithCard(s, "ok");
      else {
        s.pending = "pin";
        askPin(s.emit, s.piv);
      }
      return;
    }
    if (s.skFingerprint !== null) {
      const fingerprint = s.skFingerprint;
      signWithTouch(s.emit, fingerprint, this.sk, (ok) => {
        if (s.info.state === "closed") return;
        this.record("session.auth_sk", { connection: s.info.connectionId, fingerprint, backend: "agent", outcome: ok ? "ok" : "touch_timeout" });
        if (ok) this.connect(s);
        else this.end(s, "security key not touched within 30 s", "auth_failed");
      });
      return;
    }
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
        certificate: null,
      });
      return;
    }
    if (s.needsOtp) {
      s.pending = "otp";
      s.emit({ kind: "prompt", id: 2, message: "Verification code:", secret: true, purpose: "keyboard_interactive", account: null, certificate: null });
      return;
    }
    this.connect(s);
  }

  /** `session.auth_sk { backend: piv }`, then the shell or the close. Never a password fallback. */
  private signedInWithCard(s: MockSession, outcome: "ok" | "cancelled" | "refused"): void {
    this.record("session.auth_sk", { connection: s.info.connectionId, fingerprint: s.piv?.fingerprint ?? "", backend: "piv", outcome });
    if (outcome === "ok") this.connect(s);
    else if (outcome === "cancelled") this.end(s, "smart card PIN cancelled", "user");
    else this.end(s, "the smart card refused the PIN, or the module could not load it", "auth_failed");
  }

  private connect(s: MockSession): void {
    s.pending = null;
    s.info.state = "connected";
    this.record("session_opened", { connection: s.info.connectionId, protocol: s.info.protocol });
    s.emit({ kind: "connected", protocol: s.info.protocol, peerIdentity: `SHA256:mock-${s.host}`, security: null });
    s.emit({ kind: "bytes", data: enc.encode(`Mock shell on ${s.host}. Input is echoed.\r\n$ `) });
  }

  private end(s: MockSession, reason: string, code: CloseCode = "server_ended"): void {
    s.info.state = "closed";
    this.leaseBook.release(s.info.sessionId, code === "user" ? "closed" : "ended", this.recorder);
    this.dropSession(s.info.sessionId);
    this.sessions.delete(s.info.sessionId);
    this.record("session_closed", { connection: s.info.connectionId, reason });
    s.emit({ kind: "closed", reason, code });
  }

  sessionSend: Ipc["sessionSend"] = async ({ sessionId, input }) => {
    if (this.kubeHandles(sessionId)) {
      this.kubeSend(sessionId, input);
      return;
    }
    const r = this.remote.get(sessionId);
    if (r) {
      this.sendRemote(r, input);
      return;
    }
    const s = this.sessions.get(sessionId);
    if (!s) throw new IpcError("session.not_found", "session not found");
    if (s.chain?.active) {
      if (s.chain.answer(input)) return;
      if (input.kind === "answer" || input.kind === "credential_answer") throw new IpcError("input.invalid", "no such prompt");
    }
    switch (input.kind) {
      case "credential_answer": {
        if (s.pending !== "credential" || input.id !== 3) throw new IpcError("input.invalid", "no such prompt");
        const ok = input.username.trim() !== "" && input.password.length > 0;
        this.record("credential_prompted", { connection: s.info.connectionId, username: input.username.trim() });
        this.later(() => { if (ok) this.connect(s); else this.end(s, "authentication failed", "auth_failed"); });
        return;
      }
      case "answer": {
        const yes = /^(y|yes|accept)$/i.test(input.text.trim());
        if (s.pending === "tofu" && input.id === 1) {
          this.record("trust_decision", { host: s.host, fingerprint: `SHA256:mock-${s.host}`, decision: yes ? "accepted" : "rejected" });
          if (yes) {
            this.trustedHosts.add(s.host);
            this.later(() => { this.afterTrust(s); });
          } else this.later(() => { this.end(s, "host key rejected", "trust_rejected"); });
        } else if (s.pending === "pin" && input.id === PIN_PROMPT_ID) {
          const outcome = pinOutcome(input.text, this.piv);
          // The PIN loads the card once; a later sign-in that finds it does not extend the lifetime.
          if (outcome === "ok" && s.piv?.fingerprint) this.agentCards.load(s.piv.fingerprint);
          s.pending = null;
          this.record("credential.pin_prompted", { fingerprint: s.piv?.fingerprint ?? "", outcome: outcome === "cancelled" ? "cancelled" : "entered" });
          this.later(() => { this.signedInWithCard(s, outcome); });
        } else if (s.pending === "otp" && input.id === 2) {
          this.later(() => { if (input.text.length > 0) this.connect(s); else this.end(s, "authentication failed", "auth_failed"); });
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
    if (this.kubeHandles(sessionId)) {
      this.kubeClose(sessionId);
      return;
    }
    const r = this.remote.get(sessionId);
    if (r) {
      this.endRemote(r, "closed by user", "user");
      return;
    }
    const s = this.sessions.get(sessionId);
    if (!s) throw new IpcError("session.not_found", "session not found");
    this.end(s, "closed by user", "user");
  };

  private recorder = (event: string, details: Record<string, string>): void => { this.record(event, details); };

  sessionList: Ipc["sessionList"] = async () => [
    ...[...this.sessions.values()].map((s) => {
      const leases = this.leaseBook.status(s.info.sessionId, this.recorder);
      return leases.length > 0 ? { ...s.info, leases } : { ...s.info };
    }),
    ...this.remoteInfos(),
    ...this.kubeInfos(),
  ];

  /** R3 `on_lock`: leases are drained (revoked) before tokens; the sessions survive. */
  protected override lockBackend(): void {
    super.lockBackend();
    this.leaseBook.drain(this.recorder);
  }
}

// Mock RDP/VNC sessions (ADR-0011/0012) for `vite dev` and vitest: certificate TOFU prompt,
// synthetic MFR1 frames at ~30 fps with the 2-credit flow control, input accounting, view-only,
// clipboard offers, screenshots, the known-certs store and simulated reconnects.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type {
  CertificateInfo,
  CloseCode,
  FrameHandler,
  KnownCert,
  KnownCertProtocol,
  Protocol,
  ProtocolOptions,
  RemoteIpc,
  SessionEventHandler,
  SessionInfo,
  SessionInput,
  Size,
  VncConnOptions,
} from "./ipc.types";
import { INPUT_LIMITS } from "./ipc.types.remote";
import { IpcError } from "./ipc.error";
import { T0 } from "./ipc.seed";
import { MockExitBase } from "./ipc.mock.exit";
import { SyntheticDesktop } from "./frame/synthetic";
import { hashHost, hostMatches } from "./hostHash";
import { DEFAULT_GATEWAY_KNOBS, gatewayMismatchReason, gatewayOf, gatewayPinKey, signInToGateway, type MockGateway, type MockGatewayKnobs } from "./ipc.mock.gateway";

/** What the remote mock needs to know about a connection. */
export interface RemoteTarget {
  connectionId: string;
  protocol: Protocol;
  name: string;
  host: string;
  port: number;
  tags: string[];
  options: ProtocolOptions | undefined;
}

export interface MockRemoteSession {
  info: SessionInfo;
  target: RemoteTarget;
  emit: SessionEventHandler;
  onFrame: FrameHandler;
  desktop: SyntheticDesktop;
  pending: "cert" | "gw-cert" | null;
  /** ADR-0027: the RD Gateway in front of the target (null = direct). */
  gateway: MockGateway | null;
  viewOnly: boolean;
  seq: number;
  acked: number;
  inFlight: number;
  pump: ReturnType<typeof setInterval> | null;
  timers: ReturnType<typeof setTimeout>[];
  /** Every input Rust would forward to the server (view-only drops are not here). */
  inputs: SessionInput[];
  dropped: number;
  /** The `flaky` demo drops the link only once per session. */
  flapped: boolean;
}

/** Credits per session (ADR-0011: at most 2 messages in flight). */
export const FRAME_CREDITS = 2;
/** The mock desktop is capped so frame generation stays cheap in the browser. */
const MOCK_MAX = { width: 1920, height: 1200 };

export function clampDesktop(size: Size): Size {
  const c = (v: number) => Math.max(INPUT_LIMITS.minDesktop, Math.min(INPUT_LIMITS.maxDesktop, Math.round(v)));
  const width = c(size.width) & ~1;
  return { width, height: c(size.height) };
}

/** A fake but stable fingerprint per host (hex SHA-256 shaped). */
export function fakeSha256(host: string): string {
  let h = 0x811c9dc5;
  let out = "";
  for (let i = 0; out.length < 64; i++) {
    h = Math.imul(h ^ (host.charCodeAt(i % Math.max(1, host.length)) + i), 0x01000193) >>> 0;
    out += h.toString(16).padStart(8, "0");
  }
  return out.slice(0, 64);
}

export abstract class MockRemoteBase extends MockExitBase {
  remote = new Map<string, MockRemoteSession>();
  /**
   * `protocol|host:port` → pins. More than one distinct fingerprint for a key is a trust
   * conflict (review 6b L-35, after a sync merge): connects fail closed until they are removed.
   */
  knownCerts = new Map<string, KnownCert[]>();
  /** Frame pump period; tests may set it high and call `pumpOnce`. */
  frameIntervalMs = 33;
  /** Backoff the mock announces per attempt (ADR-0011 schedule, scaled for tests). */
  reconnectDelaysMs: number[] = [1000, 2000];
  /** ADR-0027 knob: how the mock RD Gateway answers once its certificate is trusted. */
  rdg: MockGatewayKnobs = { ...DEFAULT_GATEWAY_KNOBS };
  private remoteIds = 0;

  protected pinKey(t: RemoteTarget): string {
    return `${t.protocol}|${t.host.toLowerCase()}:${String(t.port)}`;
  }

  /** `host:port` of every connection of `protocol` (`known_certs_list` names the pins that match one). */
  protected abstract connectionHosts(protocol: "rdp" | "vnc"): { host: string; port: number }[];

  /** `known_certs_list` candidates: Rust does not name RD Gateway pins from connection options yet (R5). */
  private candidateHosts(protocol: KnownCertProtocol): { host: string; port: number }[] {
    return protocol === "rdg" ? [] : this.connectionHosts(protocol);
  }

  certificateFor(t: RemoteTarget): CertificateInfo {
    return {
      subject: `CN=${t.host}`,
      issuer: `CN=${t.host}`,
      notBefore: T0,
      notAfter: "2027-11-01T08:00:00Z",
      sha256: fakeSha256(t.host),
      san: [t.host],
      problems: ["self_signed"],
    };
  }

  /**
   * Store a pin for `t` with a salted HMAC host field, like `KnownCerts::add_and_save`. `label`
   * varies the fingerprint (a second device's pin of another certificate); a duplicate of an
   * existing fingerprint is kept once, as Rust does.
   */
  async pin(t: RemoteTarget, addedAt = new Date().toISOString(), label = ""): Promise<void> {
    await this.pinAt(this.pinKey(t), t.host, t.port, addedAt, label);
  }

  /** The same for any store key (`rdg|host:port` for an RD Gateway, ADR-0027). */
  async pinAt(key: string, host: string, port: number, addedAt = new Date().toISOString(), label = ""): Promise<void> {
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    const hostHash = await hashHost(host, port, salt);
    const fingerprint = `SHA256:${fakeSha256(label + host)}`;
    const pins = this.knownCerts.get(key) ?? [];
    if (pins.some((p) => p.fingerprint === fingerprint)) return;
    this.knownCerts.set(key, [...pins, { hostHash, fingerprint, addedAt }]);
  }

  /** `protocol|host:port` keys with conflicting pins (`KnownCerts::distinct_pins > 1`). */
  conflictingPins(): string[] {
    return [...this.knownCerts.entries()].filter(([, pins]) => new Set(pins.map((p) => p.fingerprint)).size > 1).map(([k]) => k);
  }

  /** `known_certs_remove`: every pin of the host:port goes, so the next connect is a fresh prompt. */
  protected removePins(protocol: KnownCertProtocol, host: string, port: number): number {
    const key = `${protocol}|${host.toLowerCase()}:${String(port)}`;
    const n = this.knownCerts.get(key)?.length ?? 0;
    this.knownCerts.delete(key);
    return n;
  }

  /** `session_open` for rdp/vnc (called by MockTransport after the shared checks). */
  protected openRemote(t: RemoteTarget, size: Size, onEvent: SessionEventHandler, onFrame: FrameHandler | undefined): { sessionId: string } {
    if (!onFrame) throw new IpcError("input.invalid", "invalid onFrame: required for rdp and vnc sessions");
    this.remoteIds += 1;
    const sessionId = `r-${this.remoteIds.toString(16).padStart(4, "0")}`;
    const d = clampDesktop(size);
    const vnc = t.protocol === "vnc" ? (t.options as Partial<VncConnOptions> | undefined) : undefined;
    const s: MockRemoteSession = {
      info: { sessionId, connectionId: t.connectionId, protocol: t.protocol, state: "connecting", openedAt: new Date().toISOString() },
      target: t,
      emit: onEvent,
      onFrame,
      desktop: new SyntheticDesktop(Math.min(d.width, MOCK_MAX.width), Math.min(d.height, MOCK_MAX.height)),
      pending: null,
      gateway: gatewayOf(t),
      viewOnly: vnc?.viewOnly === true,
      seq: 0,
      acked: 0,
      inFlight: 0,
      pump: null,
      timers: [],
      inputs: [],
      dropped: 0,
      flapped: false,
    };
    this.remote.set(sessionId, s);
    this.later(() => {
      // Conflicting pins (6b L-35) fail closed before anything is presented: no prompt, no retry.
      if (this.conflictingPins().includes(this.pinKey(t))) {
        this.endRemote(s, `the trust store holds conflicting certificates for ${t.host}:${String(t.port)}; remove them in Settings → Trust`, "trust_conflict");
        return;
      }
      if (s.gateway) this.openGateway(s);
      else this.targetTrust(s);
    });
    return { sessionId };
  }

  /** ADR-0027: the gateway's TLS (TOFU over `known_rdg_certs`), then its sign-in, then the target. */
  private openGateway(s: MockRemoteSession, trustedOnce = false): void {
    const g = s.gateway;
    if (!g) return;
    const fingerprint = `SHA256:${fakeSha256(g.host)}`;
    s.emit({ kind: "gateway_status", host: g.label, state: "connecting", peerIdentity: null });
    if (this.rdg.outcome === "mismatch") {
      this.endRemote(s, gatewayMismatchReason(g), "trust_mismatch");
      return;
    }
    if (!trustedOnce && !this.knownCerts.has(gatewayPinKey(g))) {
      s.pending = "gw-cert";
      s.emit({
        kind: "prompt", id: 2, message: `The certificate of the RD Gateway ${g.label} is not trusted.`, secret: false,
        purpose: "gateway_certificate_trust", account: null,
        certificate: this.certificateFor({ ...s.target, host: g.host, port: g.port }),
      });
      return;
    }
    const env = {
      connectionId: s.info.connectionId, emit: s.emit, later: (fn: () => void) => { this.later(fn); },
      record: (e: string, d: Record<string, string>) => { this.record(e, d); }, live: () => this.remote.has(s.info.sessionId),
    };
    signInToGateway(env, g, this.rdg, fingerprint, () => { this.targetTrust(s); }, (reason, code) => { this.endRemote(s, reason, code); });
  }

  /** The target's own certificate: the mock RDP host presents a self-signed one; the mock VNC host has no TLS. */
  private targetTrust(s: MockRemoteSession): void {
    const t = s.target;
    if (t.protocol === "rdp" && !this.knownCerts.has(this.pinKey(t))) {
      s.pending = "cert";
      s.emit({
        kind: "prompt",
        id: 1,
        message: `The certificate of ${t.host}:${t.port} is not trusted.`,
        secret: false,
        purpose: "certificate_trust",
        account: null,
        certificate: this.certificateFor(t),
      });
    } else this.remoteConnected(s);
  }

  private remoteConnected(s: MockRemoteSession): void {
    if (!this.remote.has(s.info.sessionId)) return;
    s.pending = null;
    s.info.state = "connected";
    const t = s.target;
    const rdp = t.protocol === "rdp";
    this.record("session_opened", { connection: t.connectionId, protocol: t.protocol });
    s.emit({
      kind: "connected",
      protocol: t.protocol,
      peerIdentity: rdp ? `x509 SHA256:${fakeSha256(t.host)}` : null,
      security: rdp ? (s.gateway ? "nla+rdg" : "nla") : "vnc-auth",
    });
    s.emit({ kind: "desktop_resized", width: s.desktop.width, height: s.desktop.height });
    this.startPump(s);
    if (t.tags.includes("flaky") && !s.flapped) {
      s.flapped = true;
      s.timers.push(setTimeout(() => { this.dropLink(s.info.sessionId); }, 4000));
    }
  }

  private startPump(s: MockRemoteSession): void {
    this.stopPump(s);
    s.pump = setInterval(() => { this.pumpOnce(s.info.sessionId); }, this.frameIntervalMs);
    this.pumpOnce(s.info.sessionId);
  }

  private stopPump(s: MockRemoteSession): void {
    if (s.pump !== null) clearInterval(s.pump);
    s.pump = null;
  }

  /** Emit one frame if a credit is free. Returns whether a frame went out. */
  pumpOnce(sessionId: string): boolean {
    const s = this.remote.get(sessionId);
    if (!s || s.info.state !== "connected" || s.inFlight >= FRAME_CREDITS) return false;
    s.seq += 1;
    s.inFlight += 1;
    s.onFrame(s.desktop.next(s.seq, Date.now()));
    return true;
  }

  /** Simulate a network drop after `Connected`: backoff events, then a fresh connect. */
  dropLink(sessionId: string, attempts = this.reconnectDelaysMs.length): void {
    const s = this.remote.get(sessionId);
    if (!s || s.info.state !== "connected") return;
    this.stopPump(s);
    s.info.state = "connecting";
    s.inFlight = 0;
    let wait = 0;
    for (let a = 1; a <= attempts; a++) {
      const delayMs = this.reconnectDelaysMs[a - 1] ?? 30_000;
      s.timers.push(setTimeout(() => { if (this.remote.has(sessionId)) s.emit({ kind: "reconnecting", attempt: a, delayMs }); }, wait));
      wait += delayMs;
    }
    s.timers.push(setTimeout(() => {
      s.desktop.resize(s.desktop.width, s.desktop.height);
      this.remoteConnected(s);
    }, wait));
  }

  protected endRemote(s: MockRemoteSession, reason: string, code: CloseCode): void {
    this.stopPump(s);
    for (const t of s.timers) clearTimeout(t);
    s.info.state = "closed";
    this.remote.delete(s.info.sessionId);
    this.record("session_closed", { connection: s.info.connectionId, reason });
    s.emit({ kind: "closed", reason, code });
  }

  private remoteLive(sessionId: string): MockRemoteSession {
    const s = this.remote.get(sessionId);
    if (!s) throw new IpcError("session.not_found", "session not found");
    return s;
  }

  private connected(sessionId: string): MockRemoteSession {
    const s = this.remoteLive(sessionId);
    if (s.info.state !== "connected") throw new IpcError("session.not_connected", "the session is not connected yet");
    return s;
  }

  /** `session_send` for a remote session. */
  protected sendRemote(s: MockRemoteSession, input: SessionInput): void {
    switch (input.kind) {
      case "answer": {
        if (s.pending === "gw-cert" && input.id === 2 && s.gateway) {
          // ADR-0027 Gate: `yes` pins the gateway, `once` trusts it for this connect, anything else rejects.
          const g = s.gateway;
          const a = input.text.trim().toLowerCase();
          const decision = a === "yes" ? "accepted" : a === "once" ? "trusted_once" : "rejected";
          s.pending = null;
          this.record("trust_decision", { protocol: "rdg", host: g.label, fingerprint: `SHA256:${fakeSha256(g.host)}`, decision });
          if (decision === "rejected") this.later(() => { this.endRemote(s, `certificate for ${g.label} was not trusted`, "trust_rejected"); });
          else if (decision === "trusted_once") this.later(() => { this.openGateway(s, true); });
          else void this.pinAt(gatewayPinKey(g), g.host, g.port).then(() => { this.later(() => { this.openGateway(s); }); });
          return;
        }
        if (s.pending !== "cert" || input.id !== 1) throw new IpcError("input.invalid", "invalid id: no such prompt");
        const yes = /^(y|yes|accept)$/i.test(input.text.trim());
        const t = s.target;
        this.record("trust_decision", { host: t.host, fingerprint: `SHA256:${fakeSha256(t.host)}`, decision: yes ? "accepted" : "rejected" });
        if (yes) {
          // ADR-0011: the pin is written (hashed, as Rust does) and the session reconnects on a new TCP connection.
          void this.pin(t).then(() => { this.later(() => { this.remoteConnected(s); }); });
        } else this.later(() => { this.endRemote(s, "certificate rejected", "trust_rejected"); });
        return;
      }
      case "resize": {
        const d = clampDesktop(input.size);
        s.desktop.resize(Math.min(d.width, MOCK_MAX.width), Math.min(d.height, MOCK_MAX.height));
        this.later(() => { if (this.remote.has(s.info.sessionId)) s.emit({ kind: "desktop_resized", width: s.desktop.width, height: s.desktop.height }); });
        return;
      }
      case "key":
        if (input.code.length > INPUT_LIMITS.codeChars || !/^[\x20-\x7e]*$/.test(input.code)) throw new IpcError("input.invalid", "invalid code");
        break;
      case "unicode":
        if (Array.from(input.text).length > INPUT_LIMITS.unicodeChars) throw new IpcError("input.invalid", "invalid text: more than 64 characters");
        break;
      case "bytes":
      case "credential_answer":
        throw new IpcError("input.invalid", `invalid input: ${input.kind} is not accepted by ${s.target.protocol} sessions`);
      default:
        break;
    }
    if (s.info.state !== "connected") return;
    const drops = input.kind !== "release_all";
    if (s.viewOnly && drops) {
      s.dropped += 1;
      return;
    }
    s.inputs.push(input);
    if (input.kind === "clipboard_offer") this.record("session_clipboard", { connection: s.info.connectionId, direction: "to_remote" });
  }

  protected remoteInfos(): SessionInfo[] {
    return [...this.remote.values()].map((s) => ({ ...s.info }));
  }

  // ---------- ADR-0011 / ADR-0012 commands ----------

  sessionFrameAck: RemoteIpc["sessionFrameAck"] = async ({ sessionId, seq }) => {
    const s = this.remoteLive(sessionId);
    if (!Number.isInteger(seq) || seq < 1 || seq > s.seq) throw new IpcError("input.invalid", "invalid seq: no such frame");
    s.acked = Math.max(s.acked, seq);
    s.inFlight = Math.max(0, s.inFlight - 1);
  };

  sessionScreenshot: RemoteIpc["sessionScreenshot"] = async ({ sessionId }) => {
    const s = this.connected(sessionId);
    this.record("session_screenshot", { connection: s.info.connectionId });
    return { width: s.desktop.width, height: s.desktop.height };
  };

  sessionSetViewOnly: RemoteIpc["sessionSetViewOnly"] = async ({ sessionId, viewOnly }) => {
    const s = this.remoteLive(sessionId);
    if (s.target.protocol !== "vnc") throw new IpcError("input.invalid", "invalid sessionId: not a VNC session");
    s.viewOnly = viewOnly;
    this.record("session_view_only", { connection: s.info.connectionId, view_only: String(viewOnly) });
  };

  /** Like `KnownCerts::list_named`: the HMAC check runs here (the mock's side of the wire), never in the UI. */
  knownCertsList: RemoteIpc["knownCertsList"] = async ({ protocol }) => {
    await this.unlocked();
    const candidates = this.candidateHosts(protocol);
    const out: KnownCert[] = [];
    for (const [k, pins] of this.knownCerts.entries()) {
      if (!k.startsWith(`${protocol}|`)) continue;
      for (const v of pins) {
        const named: KnownCert = { ...v };
        for (const c of candidates) {
          if (await hostMatches(v.hostHash, c.host, c.port)) {
            named.host = c.host;
            named.port = c.port;
            break;
          }
        }
        out.push(named);
      }
    }
    return out;
  };

  knownCertsRemove: RemoteIpc["knownCertsRemove"] = async ({ protocol, host, port }) => {
    await this.unlocked();
    if (host.trim() === "") throw new IpcError("input.invalid", "invalid host");
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new IpcError("input.invalid", "invalid port");
    const removed = this.removePins(protocol, host, port);
    if (removed) this.record("trust_cert_removed", { protocol, host });
    return { removed };
  };
}

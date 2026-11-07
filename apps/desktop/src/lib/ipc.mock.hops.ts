// Mock ADR-0025 jump-host chain as R1's `HopChain::open` drives it: each hop gets `hop_status`
// connecting → (host-key prompt) → authenticating → (credential prompt) → up, in chain order,
// before the target sees a byte. A hop tagged `hop-fail` refuses the sign-in; a rejected hop key
// or a failed hop sign-in closes the session with `hop_failed` and the target is never contacted.
import type { HopState, SessionEventHandler, SessionInput } from "./ipc.types";

export interface MockHop {
  connectionId: string;
  name: string;
  host: string;
  port: number;
  /** Tagged `hop-fail`: the hop refuses the sign-in. */
  fail: boolean;
  /** The hop's credential is the `prompt` kind: ask for it, tagged with the hop. */
  ask: { username: string | null; domain: string | null } | null;
}

/** Prompt ids of hop questions (R1 routes hop answers by id above `HOP_PROMPT_ID_BASE`). */
export const HOP_TRUST_ID = 1000;
export const HOP_CREDENTIAL_ID = 2000;

interface Env {
  emit: SessionEventHandler;
  trusted: Set<string>;
  record: (event: string, details: Record<string, string>) => void;
  later: (fn: () => void) => void;
  /** Every hop is up: the target phase starts. */
  done: () => void;
  /** A hop failed: close with `hop_failed`. */
  fail: (reason: string) => void;
}

export class MockHopChain {
  at = 0;
  pending: "tofu" | "credential" | null = null;

  constructor(readonly hops: MockHop[], private readonly env: Env, private readonly target: string) {}

  get active(): boolean {
    return this.at < this.hops.length;
  }

  private status(state: HopState, at = this.at): void {
    const h = this.hops[at];
    if (!h) return;
    const peerIdentity = state === "up" ? `SHA256:mock-${h.host}` : null;
    this.env.emit({ kind: "hop_status", hop: at, of: this.hops.length, state, host: `${h.host}:${String(h.port)}`, peerIdentity });
  }

  private title(): string {
    const h = this.hops[this.at];
    return `Hop ${String(this.at + 1)} of ${String(this.hops.length)} — ${h?.host ?? ""}:${String(h?.port ?? 22)}`;
  }

  start(): void {
    const h = this.hops[this.at];
    if (!h) {
      this.env.done();
      return;
    }
    this.status("connecting");
    if (this.env.trusted.has(h.host)) {
      this.auth();
      return;
    }
    this.pending = "tofu";
    this.env.emit({
      kind: "prompt",
      id: HOP_TRUST_ID + this.at,
      message: `${this.title()}\nThe authenticity of host ${h.host} can't be established.\nED25519 key fingerprint is SHA256:mock-${h.name}.\nTrust this host and continue?`,
      secret: false,
      purpose: "host_key_trust",
      account: null,
      certificate: null,
      hop: this.at,
    });
  }

  /** Graphical targets (ADR-0025 `ViaSession`): the demo chain comes up without questions. */
  startQuiet(): void {
    this.hops.forEach((_, i) => {
      this.env.later(() => {
        this.status("connecting", i);
        this.status("up", i);
      });
    });
    this.at = this.hops.length;
  }

  private auth(): void {
    const h = this.hops[this.at];
    if (!h) return;
    this.status("authenticating");
    if (h.fail) {
      this.failHop(`jump host ${h.name} refused the sign-in`);
      return;
    }
    if (h.ask) {
      this.pending = "credential";
      this.env.emit({
        kind: "prompt",
        id: HOP_CREDENTIAL_ID + this.at,
        message: `${this.title()}\nSign in to ${h.host}`,
        secret: true,
        purpose: "credential",
        account: { username: h.ask.username, domain: h.ask.domain, needsUsername: true, needsDomain: false },
        certificate: null,
        hop: this.at,
      });
      return;
    }
    this.up();
  }

  private up(): void {
    const h = this.hops[this.at];
    this.pending = null;
    this.status("up");
    this.env.record("session_hop_open", { connection: this.target, hop: String(this.at), hop_connection: h?.connectionId ?? "" });
    this.at += 1;
    this.env.later(() => { this.start(); });
  }

  private failHop(reason: string): void {
    this.pending = null;
    this.status("failed");
    this.env.record("session_hop_close", { connection: this.target, hop: String(this.at), code: "hop_failed" });
    this.at = this.hops.length;
    this.env.later(() => { this.env.fail(reason); });
  }

  /** Route an answer to the hop that asked. False = not a hop question (the target's). */
  answer(input: SessionInput): boolean {
    const h = this.hops[this.at];
    if (!h || this.pending === null) return false;
    if (input.kind === "answer" && this.pending === "tofu" && input.id === HOP_TRUST_ID + this.at) {
      const yes = /^(y|yes|accept)$/i.test(input.text.trim());
      this.env.record("trust_decision", { host: h.host, fingerprint: `SHA256:mock-${h.host}`, decision: yes ? "accepted" : "rejected" });
      this.pending = null;
      if (yes) {
        this.env.trusted.add(h.host);
        this.env.later(() => { this.auth(); });
      } else this.failHop(`jump host ${h.name}: host key rejected`);
      return true;
    }
    if (input.kind === "credential_answer" && this.pending === "credential" && input.id === HOP_CREDENTIAL_ID + this.at) {
      const ok = input.username.trim() !== "" && input.password.length > 0;
      this.pending = null;
      if (ok) this.env.later(() => { this.up(); });
      else this.failHop(`jump host ${h.name}: authentication failed`);
      return true;
    }
    return false;
  }
}

// Mock ADR-0027 RD Gateway as rust-core R5 serves it: `gateway_status` before the target's events,
// a `gateway_certificate_trust` prompt for an unknown gateway pin (yes pins `known_rdg_certs`, once
// trusts for this connect), the audit rows, and the close codes of a failing gateway. The knob
// `outcome` picks how the gateway answers once its certificate is trusted.
import type { CloseCode, RdpConnOptions, SessionEventHandler } from "./ipc.types";
import type { RemoteTarget } from "./ipc.mock.remote";

export type MockGatewayOutcome = "ok" | "auth" | "refused" | "unsupported" | "mismatch" | "basic";

export interface MockGatewayKnobs {
  /** `ok`: NTLM passes. `basic`: only Basic (needs allowBasicGateway). `mismatch`: the stored pin changed. */
  outcome: MockGatewayOutcome;
}

export const DEFAULT_GATEWAY_KNOBS: MockGatewayKnobs = { outcome: "ok" };

export interface MockGateway {
  host: string;
  port: number;
  /** `host:port`, as Rust labels it. */
  label: string;
  allowBasic: boolean;
}

/** The connection's RD Gateway, or null for a direct RDP connection (and for VNC). */
export function gatewayOf(t: RemoteTarget): MockGateway | null {
  if (t.protocol !== "rdp") return null;
  const g = (t.options as Partial<RdpConnOptions> | undefined)?.gateway;
  if (!g?.host) return null;
  const port = g.port || 443;
  return { host: g.host, port, label: `${g.host.toLowerCase()}:${String(port)}`, allowBasic: g.allowBasicGateway };
}

/** `known_certs` key of a gateway pin (the mock keys every store by `protocol|host:port`). */
export const gatewayPinKey = (g: MockGateway): string => `rdg|${g.label}`;

interface Env {
  connectionId: string;
  emit: SessionEventHandler;
  later: (fn: () => void) => void;
  record: (event: string, details: Record<string, string>) => void;
  live: () => boolean;
}

/**
 * After the gateway certificate is trusted: authenticating, then `up` (the target's flow goes on)
 * or `failed` + the close. Every outcome writes `session.rdp.gateway`.
 */
export function signInToGateway(
  env: Env,
  g: MockGateway,
  knobs: MockGatewayKnobs,
  fingerprint: string,
  up: () => void,
  fail: (reason: string, code: CloseCode) => void,
): void {
  env.emit({ kind: "gateway_status", host: g.label, state: "authenticating", peerIdentity: fingerprint });
  env.later(() => {
    if (!env.live()) return;
    const basic = knobs.outcome === "basic";
    const refusal: Partial<Record<MockGatewayOutcome, [string, CloseCode]>> = {
      auth: ["the RD Gateway refused the credentials (HTTP 401 after NTLM)", "gateway_auth"],
      refused: ["the RD Gateway refused the channel to the target (HRESULT 0x800759DD)", "gateway_refused"],
      unsupported: ["no RD Gateway WebSocket endpoint (HTTP 404): RPC over HTTP gateways are not supported", "gateway_unsupported"],
    };
    const r = basic && !g.allowBasic
      ? (["the RD Gateway offers only Basic authentication; turn on allowBasicGateway to use it", "gateway_auth"] as [string, CloseCode])
      : refusal[knobs.outcome];
    env.record("session.rdp.gateway", { connection: env.connectionId, host: g.label, auth: basic ? "basic" : "ntlm", outcome: r ? "failed" : "ok" });
    if (r) {
      env.emit({ kind: "gateway_status", host: g.label, state: "failed", peerIdentity: fingerprint });
      fail(r[0], r[1]);
      return;
    }
    if (basic) env.record("session.rdp.gateway_basic", { connection: env.connectionId, host: g.label });
    env.emit({ kind: "gateway_status", host: g.label, state: "up", peerIdentity: fingerprint });
    up();
  });
}

/** The reason Rust gives for a changed gateway pin (a hard stop before any HTTP byte). */
export const gatewayMismatchReason = (g: MockGateway): string =>
  `RD GATEWAY CERTIFICATE CHANGED for ${g.label}: the stored certificate no longer matches; remove it in Settings → Trust if the gateway was reinstalled`;

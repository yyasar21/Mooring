// DTOs of the ADR-0020 network tools as rust-core N1 serves them (`docs/handoff/a4-rust-core-n1.md`).
// Every line of tool output arrives sanitised and capped by Rust; the UI renders it as text only.

/** A stored connection (its effective host and port) or a typed host. */
export type NetTarget = { connectionId: string } | { host: string; port?: number };

export interface NetTools {
  ping: boolean;
  traceroute: "traceroute" | "tracepath" | null;
  wg: boolean;
}

export type PortOutcome = "open" | "closed" | "timeout" | "unreachable" | "dns_failed";

export type PortCheck =
  | { outcome: "open"; addr: string; rttMs: number }
  | { outcome: Exclude<PortOutcome, "open"> };

export interface PingReply {
  seq?: number;
  ttl?: number;
  rttMs: number;
}

export interface PingResult {
  sent: number;
  received: number;
  lossPercent: number;
  minMs?: number;
  avgMs?: number;
  maxMs?: number;
  replies: PingReply[];
  /** Sanitised tool output, ≤ 200 lines × 512 bytes. */
  lines: string[];
}

export interface PingRun {
  result: PingResult;
  /** The 30 s deadline killed the tool; `result` is partial. */
  timedOut: boolean;
  /** The output cap stopped the tool; `result` is partial. */
  truncated: boolean;
  exitCode: number | null;
}

export interface TraceHop {
  hop: number;
  addr?: string;
  rttsMs: number[];
  timeouts: number;
  /** `!H`-style annotation of the tool, already sanitised. */
  note?: string;
}

export interface TraceResult {
  hops: TraceHop[];
  reached: boolean;
  lines: string[];
}

export interface TraceRun {
  result: TraceResult;
  tool: "traceroute" | "tracepath";
  timedOut: boolean;
  truncated: boolean;
  exitCode: number | null;
}

export interface WgPeer {
  /** Shortened by Rust (`AAAAAAAA…AAAA`); the full key never leaves the crate. */
  publicKey: string;
  endpoint?: string;
  lastHandshakeSecs?: number;
  rxBytes: number;
  txBytes: number;
}

export interface WgInterface {
  name: string;
  listenPort?: number;
  peers: WgPeer[];
}

export interface WgStatus {
  interfaces: WgInterface[];
}

export const NET_LIMITS = {
  port: { timeoutMs: { min: 100, max: 10_000, default: 3000 } },
  ping: { count: { min: 1, max: 10, default: 4 } },
  traceroute: { maxHops: { min: 1, max: 30, default: 20 } },
} as const;

/** All five are vault-gated and none is passive: never poll them. */
export interface NetIpc {
  /** Which OS tools exist at their fixed paths (no `PATH` lookup). */
  netTools(): Promise<NetTools>;
  /** One TCP handshake, no bytes; ≤ 1 per second (`net.rate_limited`). The port comes from `port` or the connection. */
  netPortCheck(args: { target: NetTarget; timeoutMs?: number }): Promise<PortCheck>;
  /** Resolves when the tool ends (≤ 30 s); two tool processes at most (`net.busy`). */
  netPing(args: { target: NetTarget; count?: number }): Promise<PingRun>;
  /** Resolves when the tool ends (≤ 60 s). */
  netTraceroute(args: { target: NetTarget; maxHops?: number }): Promise<TraceRun>;
  /** `net.tool_missing` without `wg`; `net.permission_denied` when `wg show` needs rights Mooring does not take. */
  netWgShow(): Promise<WgStatus>;
}

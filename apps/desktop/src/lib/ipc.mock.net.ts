// Mock ADR-0020 network tools as rust-core N1 serves them. No process runs and no socket opens:
// outcomes follow the host name (mock rules below) and the output lines are written to look like
// the real tools'. Everything is deterministic so tests and screenshots are stable.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { ConnectionSummary, NetIpc, NetTarget, NetTools, PingRun, PortCheck, TraceRun, WgStatus } from "./ipc.types";
import { NET_LIMITS } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { MockUpdateBase } from "./ipc.mock.update";

const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^\[?[0-9A-Fa-f:.]+\]?$/;

/**
 * Mock rules (the host decides): `closed` → refused, `slow` → timeout, `unreach` → unreachable
 * (ping loses everything, traceroute never reaches), a name outside `*.example.test` that is not a
 * literal → `dns_failed`. Everything else answers.
 */
function trait(host: string): "closed" | "slow" | "unreach" | "dns" | "ok" {
  if (host.includes("closed")) return "closed";
  if (host.includes("slow")) return "slow";
  if (host.includes("unreach")) return "unreach";
  if (!host.endsWith(".example.test") && !IPV4.test(host) && !IPV6.test(host)) return "dns";
  return "ok";
}

/** `Target::parse` of `mooring-net`, loosely: ASCII, ≤ 253 bytes, RFC 1123 labels or a literal. */
export function validHost(host: string): boolean {
  if (host.length === 0 || host.length > 253 || host.startsWith("-") || host.startsWith("/")) return false;
  if (!/^[\x21-\x7e]+$/.test(host)) return false; // printable ASCII only: no whitespace, controls or non-ASCII
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.includes("%")) return false;
  if (IPV4.test(host) || (host.includes(":") && IPV6.test(host))) return true;
  return host.split(".").every((l) => LABEL.test(l));
}

/** A stable pseudo RTT in ms from the host name (so screenshots and tests repeat). */
function rtt(host: string, i: number): number {
  let h = 7;
  for (const ch of host) h = (h * 31 + ch.charCodeAt(0)) % 9973;
  return Math.round((4 + (h % 40) + ((i * 7) % 5) * 0.8) * 10) / 10;
}

function addrOf(host: string): string {
  if (IPV4.test(host)) return host;
  let h = 0;
  for (const ch of host) h = (h * 17 + ch.charCodeAt(0)) % 251;
  return `192.0.2.${String(1 + h)}`;
}

export abstract class MockNetBase extends MockUpdateBase implements NetIpc {
  /** Which tools "exist" (`net_tools`). */
  netToolsState: NetTools = { ping: true, traceroute: "traceroute", wg: true };
  /** `wg show` answers `net.permission_denied` (the interface exists but needs rights). */
  netWgDenied = false;
  /** Port checks closer than this to the previous one are `net.rate_limited`. */
  netRateWindowMs = 1000;
  /** Tool processes allowed at once (`net.busy` beyond). */
  netSlots = 2;
  netWg: WgStatus = {
    interfaces: [{
      name: "wg0", listenPort: 51820,
      peers: [
        { publicKey: "hQ4m2zYk…9sLp", endpoint: "198.51.100.7:51820", lastHandshakeSecs: 42, rxBytes: 18_432_112, txBytes: 2_201_776 },
        { publicKey: "Zf81nWq3…0bRt", endpoint: "203.0.113.22:51820", rxBytes: 0, txBytes: 1_184 },
      ],
    }],
  };
  private netRunning = 0;
  private lastPortCheckMs: number | null = null;

  protected abstract connectionRows(): ConnectionSummary[];

  /** `TargetArg` → host (+ port): the stored connection's host, or the typed one, both validated. */
  private resolveTarget(target: NetTarget): { host: string; port: number | null } {
    if ("connectionId" in target) {
      const c = this.connectionRows().find((x) => x.id === target.connectionId);
      if (!c) throw new IpcError("tree.not_found", "connection not found");
      if (c.protocol === "kubernetes" || c.protocol === "vsphere-console") throw new IpcError("net.invalid_host", "this connection has no network host to probe");
      if (c.protocol === "web") {
        let url: URL;
        try {
          url = new URL(c.host);
        } catch {
          throw new IpcError("net.invalid_host", "the connection's URL has no host");
        }
        const port = url.port ? Number(url.port) : url.protocol === "http:" ? 80 : 443;
        return { host: url.hostname.replace(/^\[|\]$/g, ""), port };
      }
      if (!validHost(c.host)) throw new IpcError("net.invalid_host", "the connection's host is not a valid name or address");
      return { host: c.host, port: c.port };
    }
    if (typeof target.host !== "string" || !validHost(target.host)) throw new IpcError("net.invalid_host", "the host is not a valid name or address");
    if (target.port !== undefined && (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535)) throw new IpcError("input.invalid", "invalid port");
    return { host: target.host.replace(/^\[|\]$/g, ""), port: target.port ?? null };
  }

  private async withSlot<T>(fn: () => Promise<T>): Promise<T> {
    if (this.netRunning >= this.netSlots) throw new IpcError("net.busy", "two network tools are already running; wait for one to finish");
    this.netRunning += 1;
    try {
      await new Promise((r) => setTimeout(r, this.delayMs));
      return await fn();
    } finally {
      this.netRunning -= 1;
    }
  }

  netTools: NetIpc["netTools"] = async () => {
    await this.unlocked();
    return { ...this.netToolsState };
  };

  netPortCheck: NetIpc["netPortCheck"] = async ({ target, timeoutMs }) => {
    await this.unlocked();
    const { host, port } = this.resolveTarget(target);
    if (port === null) throw new IpcError("input.invalid", "invalid port: the connection has no port");
    const lim = NET_LIMITS.port.timeoutMs;
    if (timeoutMs !== undefined && (!Number.isInteger(timeoutMs) || timeoutMs < lim.min || timeoutMs > lim.max)) throw new IpcError("input.invalid", "invalid timeoutMs");
    const now = Date.now();
    if (this.lastPortCheckMs !== null && now - this.lastPortCheckMs < this.netRateWindowMs) throw new IpcError("net.rate_limited", "one port check per second");
    this.lastPortCheckMs = now;
    await new Promise((r) => setTimeout(r, this.delayMs));
    const t = trait(host);
    const result: PortCheck =
      t === "ok" ? { outcome: "open", addr: `${addrOf(host)}:${String(port)}`, rttMs: rtt(host, 0) }
      : t === "closed" ? { outcome: "closed" }
      : t === "slow" ? { outcome: "timeout" }
      : t === "unreach" ? { outcome: "unreachable" }
      : { outcome: "dns_failed" };
    this.record("net_tcp_check", { host, port: String(port), outcome: result.outcome });
    return result;
  };

  netPing: NetIpc["netPing"] = async ({ target, count }) => {
    await this.unlocked();
    const { host } = this.resolveTarget(target);
    const lim = NET_LIMITS.ping.count;
    if (count !== undefined && (!Number.isInteger(count) || count < lim.min || count > lim.max)) throw new IpcError("input.invalid", "invalid count");
    if (!this.netToolsState.ping) throw new IpcError("net.tool_missing", "ping was not found on this system");
    return this.withSlot(async (): Promise<PingRun> => {
      const n = count ?? lim.default;
      const t = trait(host);
      const addr = addrOf(host);
      const lines = [`PING ${host} (${addr}) 56(84) bytes of data.`];
      const replies: PingRun["result"]["replies"] = [];
      if (t === "dns") {
        lines.length = 0;
        lines.push(`ping: ${host}: Name or service not known`);
      } else if (t !== "unreach") {
        for (let i = 1; i <= n; i++) {
          if (t === "slow" && i % 2 === 0) continue;
          const ms = rtt(host, i);
          replies.push({ seq: i, ttl: 57, rttMs: ms });
          lines.push(`64 bytes from ${addr}: icmp_seq=${String(i)} ttl=57 time=${String(ms)} ms`);
        }
      }
      const rtts = replies.map((r) => r.rttMs);
      const received = replies.length;
      const loss = t === "dns" ? 100 : Math.round(((n - received) / n) * 100);
      if (t !== "dns") {
        lines.push("", `--- ${host} ping statistics ---`, `${String(n)} packets transmitted, ${String(received)} received, ${String(loss)}% packet loss, time ${String(n * 1000)}ms`);
      }
      const stats = rtts.length > 0 ? { minMs: Math.min(...rtts), avgMs: Math.round((rtts.reduce((a, b) => a + b, 0) / rtts.length) * 10) / 10, maxMs: Math.max(...rtts) } : {};
      if (rtts.length > 0) lines.push(`rtt min/avg/max/mdev = ${String(stats.minMs)}/${String(stats.avgMs)}/${String(stats.maxMs)}/0.4 ms`);
      this.record("net_ping", { host, sent: String(t === "dns" ? 0 : n), received: String(received) });
      return { result: { sent: t === "dns" ? 0 : n, received, lossPercent: loss, ...stats, replies, lines }, timedOut: false, truncated: false, exitCode: t === "ok" ? 0 : t === "dns" ? 2 : 1 };
    });
  };

  netTraceroute: NetIpc["netTraceroute"] = async ({ target, maxHops }) => {
    await this.unlocked();
    const { host } = this.resolveTarget(target);
    const lim = NET_LIMITS.traceroute.maxHops;
    if (maxHops !== undefined && (!Number.isInteger(maxHops) || maxHops < lim.min || maxHops > lim.max)) throw new IpcError("input.invalid", "invalid maxHops");
    const tool = this.netToolsState.traceroute;
    if (!tool) throw new IpcError("net.tool_missing", "traceroute was not found on this system");
    return this.withSlot(async (): Promise<TraceRun> => {
      const max = maxHops ?? lim.default;
      const t = trait(host);
      const addr = addrOf(host);
      const lines = [`traceroute to ${host} (${addr}), ${String(max)} hops max, 60 byte packets`];
      const hops: TraceRun["result"]["hops"] = [];
      if (t === "dns") {
        lines.length = 0;
        lines.push(`${tool}: unknown host ${host}`);
        this.record("net_traceroute", { host, hops: "0" });
        return { result: { hops, reached: false, lines }, tool, timedOut: false, truncated: false, exitCode: 1 };
      }
      const path = ["192.0.2.1", "198.51.100.1", "198.51.100.9", "203.0.113.5"];
      const total = t === "unreach" ? max : Math.min(max, path.length + 1);
      for (let i = 1; i <= total; i++) {
        const last = i === path.length + 1 && t !== "unreach";
        const timeout = t === "unreach" && i > 2;
        const hopAddr = last ? addr : path[i - 1];
        if (timeout || hopAddr === undefined) {
          hops.push({ hop: i, rttsMs: [], timeouts: 1 });
          lines.push(`${String(i).padStart(2)}  * `);
          continue;
        }
        const ms = rtt(hopAddr, i);
        hops.push({ hop: i, addr: hopAddr, rttsMs: [ms], timeouts: 0, ...(last && t === "closed" ? { note: "!X" } : {}) });
        lines.push(`${String(i).padStart(2)}  ${hopAddr}  ${String(ms)} ms${last && t === "closed" ? " !X" : ""}`);
      }
      const reached = t !== "unreach" && total === path.length + 1;
      this.record("net_traceroute", { host, hops: String(hops.length) });
      return { result: { hops, reached, lines }, tool, timedOut: false, truncated: false, exitCode: 0 };
    });
  };

  netWgShow: NetIpc["netWgShow"] = async () => {
    await this.unlocked();
    if (!this.netToolsState.wg) throw new IpcError("net.tool_missing", "wg was not found on this system");
    return this.withSlot(async (): Promise<WgStatus> => {
      if (this.netWgDenied) throw new IpcError("net.permission_denied", "WireGuard status needs elevated rights; Mooring does not elevate");
      this.record("net_wg_status", { interfaces: String(this.netWg.interfaces.length) });
      return structuredClone(this.netWg);
    });
  };
}

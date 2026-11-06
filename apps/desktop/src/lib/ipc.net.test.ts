// ADR-0020 mock contract as rust-core N1 serves it: tool table, target resolution (connection or
// host, kube/vSphere refused), the port-check outcomes and rate limit, ping/traceroute shapes,
// the two-slot semaphore, and the WireGuard status with shortened keys.
import { IpcError } from "./ipc";
import { MockTransport } from "./ipc.mock";
import { validHost } from "./ipc.mock.net";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not an IpcError";
  }
};

describe("mock · network tools (ADR-0020, N1)", () => {
  it("validHost follows Target::parse", () => {
    for (const ok of ["web01.example.test", "192.0.2.10", "2001:db8::1", "[2001:db8::1]", "a", "x-y.example.test"]) expect({ ok, valid: validHost(ok) }).toEqual({ ok, valid: true });
    for (const bad of ["", "-x.example.test", "/etc/passwd", "a b", "x_y.example.test", "fe80::1%eth0", "ünïcode.test", "a-.example.test", "a".repeat(254)]) {
      expect({ bad, valid: validHost(bad) }).toEqual({ bad, valid: false });
    }
  });

  it("resolves the target from a connection, refuses kube and vSphere, and gates on the vault", async () => {
    const m = new MockTransport();
    m.netRateWindowMs = 0;
    expect(await m.netPortCheck({ target: { connectionId: "c-web01" } })).toMatchObject({ outcome: "open", addr: expect.stringMatching(/^192\.0\.2\.\d+:22$/) as string });
    expect(await m.netPortCheck({ target: { connectionId: "c-lb" } })).toMatchObject({ outcome: "open", addr: expect.stringMatching(/:443$/) as string });
    expect(await code(m.netPortCheck({ target: { connectionId: "c-k8s" } }))).toBe("net.invalid_host");
    expect(await code(m.netPortCheck({ target: { connectionId: "c-vc" } }))).toBe("net.invalid_host");
    expect(await code(m.netPortCheck({ target: { connectionId: "c-missing" } }))).toBe("tree.not_found");
    expect(await code(m.netPortCheck({ target: { connectionId: "c-stg" } }))).toBe("input.invalid"); // no port stored
    expect(await code(m.netPortCheck({ target: { host: "bad host", port: 22 } }))).toBe("net.invalid_host");
    expect(await code(m.netPortCheck({ target: { host: "web01.example.test", port: 70000 } }))).toBe("input.invalid");
    expect(await code(m.netPortCheck({ target: { host: "web01.example.test", port: 22 }, timeoutMs: 50 }))).toBe("input.invalid");
    expect(m.audit.filter((e) => e.event === "net_tcp_check").at(-1)).toMatchObject({ details: { host: "lb.example.test", port: "443", outcome: "open" } });
    const locked = new MockTransport({ vault: "locked" });
    expect(await code(locked.netTools())).toBe("vault.locked");
    expect(await code(locked.netPing({ target: { host: "web01.example.test" } }))).toBe("vault.locked");
  });

  it("port check: every outcome by mock rule, one per second", async () => {
    const m = new MockTransport();
    expect(await m.netPortCheck({ target: { host: "web01.example.test", port: 22 } })).toMatchObject({ outcome: "open" });
    expect(await code(m.netPortCheck({ target: { host: "web01.example.test", port: 22 } }))).toBe("net.rate_limited");
    m.netRateWindowMs = 0;
    expect(await m.netPortCheck({ target: { host: "closed.example.test", port: 22 } })).toEqual({ outcome: "closed" });
    expect(await m.netPortCheck({ target: { host: "slow.example.test", port: 22 } })).toEqual({ outcome: "timeout" });
    expect(await m.netPortCheck({ target: { host: "unreach.example.test", port: 22 } })).toEqual({ outcome: "unreachable" });
    expect(await m.netPortCheck({ target: { host: "nowhere.invalid", port: 22 } })).toEqual({ outcome: "dns_failed" });
  });

  it("ping: summary, replies and lines; count clamp; loss on unreachable; tool missing", async () => {
    const m = new MockTransport();
    const run = await m.netPing({ target: { connectionId: "c-web01" }, count: 3 });
    expect(run.result).toMatchObject({ sent: 3, received: 3, lossPercent: 0 });
    expect(run.result.replies.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(run.result.minMs).toBeLessThanOrEqual(run.result.avgMs ?? 0);
    expect(run.result.lines[0]).toMatch(/^PING web01\.example\.test/);
    expect(run.result.lines.at(-1)).toMatch(/^rtt min\/avg\/max/);
    expect(run).toMatchObject({ timedOut: false, truncated: false, exitCode: 0 });
    expect(m.audit.at(-1)).toMatchObject({ event: "net_ping", details: { host: "web01.example.test", sent: "3", received: "3" } });
    const lost = await m.netPing({ target: { host: "unreach.example.test" } });
    expect(lost.result).toMatchObject({ sent: 4, received: 0, lossPercent: 100, replies: [] });
    expect(lost.result.minMs).toBeUndefined();
    expect(await code(m.netPing({ target: { host: "web01.example.test" }, count: 11 }))).toBe("input.invalid");
    m.netToolsState = { ...m.netToolsState, ping: false };
    expect(await code(m.netPing({ target: { host: "web01.example.test" } }))).toBe("net.tool_missing");
  });

  it("traceroute: hops with RTTs, timeouts and reached; tracepath flavour; max hops", async () => {
    const m = new MockTransport();
    const run = await m.netTraceroute({ target: { host: "web01.example.test" } });
    expect(run.tool).toBe("traceroute");
    expect(run.result.reached).toBe(true);
    expect(run.result.hops).toHaveLength(5);
    expect(run.result.hops[0]).toMatchObject({ hop: 1, addr: "192.0.2.1", timeouts: 0 });
    expect(run.result.hops[0]?.rttsMs).toHaveLength(1);
    expect(run.result.lines[0]).toMatch(/^traceroute to web01\.example\.test .* 20 hops max/);
    const short = await m.netTraceroute({ target: { host: "web01.example.test" }, maxHops: 2 });
    expect(short.result.hops).toHaveLength(2);
    expect(short.result.reached).toBe(false);
    const lost = await m.netTraceroute({ target: { host: "unreach.example.test" }, maxHops: 5 });
    expect(lost.result.hops.filter((h) => h.timeouts > 0)).toHaveLength(3);
    expect(lost.result.reached).toBe(false);
    expect(await code(m.netTraceroute({ target: { host: "web01.example.test" }, maxHops: 31 }))).toBe("input.invalid");
    m.netToolsState = { ...m.netToolsState, traceroute: "tracepath" };
    expect((await m.netTraceroute({ target: { host: "web01.example.test" } })).tool).toBe("tracepath");
    m.netToolsState = { ...m.netToolsState, traceroute: null };
    expect(await code(m.netTraceroute({ target: { host: "web01.example.test" } }))).toBe("net.tool_missing");
  });

  it("allows two tool processes at once, the third is net.busy", async () => {
    const m = new MockTransport({ delayMs: 20 });
    const a = m.netPing({ target: { host: "web01.example.test" } });
    const b = m.netTraceroute({ target: { host: "web01.example.test" } });
    await new Promise((r) => setTimeout(r, 0));
    expect(await code(m.netWgShow())).toBe("net.busy");
    await Promise.all([a, b]);
    expect(await code(m.netWgShow())).toBe("ok");
  });

  it("wg show: interfaces and peers with shortened keys; missing tool and denied rights", async () => {
    const m = new MockTransport();
    const wg = await m.netWgShow();
    expect(wg.interfaces[0]).toMatchObject({ name: "wg0", listenPort: 51820 });
    expect(wg.interfaces[0]?.peers).toHaveLength(2);
    for (const p of wg.interfaces[0]?.peers ?? []) expect(p.publicKey).toMatch(/^.{8}….{4}$/);
    expect(JSON.stringify(wg)).not.toMatch(/private|preshared/i);
    expect(m.audit.at(-1)).toMatchObject({ event: "net_wg_status", details: { interfaces: "1" } });
    m.netWgDenied = true;
    expect(await code(m.netWgShow())).toBe("net.permission_denied");
    m.netToolsState = { ...m.netToolsState, wg: false };
    expect(await code(m.netWgShow())).toBe("net.tool_missing");
    expect(await m.netTools()).toEqual({ ping: true, traceroute: "traceroute", wg: false });
  });
});

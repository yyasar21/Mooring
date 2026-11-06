import { useId, useState } from "react";
import { HudLabel } from "@mooring/ui";
import { ipc, NET_LIMITS, type ConnectionSummary, type NetTarget } from "../../lib/ipc";
import { probeHostOf, validHost, validMaxHops, validPort } from "../../lib/validate.net";
import { PingResult, PortResult, TraceResult, WgResult } from "./NetResults";
import { useNet, type NetTool, type RunState } from "./useNet";

export const TOOL_MISSING = "not found on this system";

/** Which connections get the card: those whose host is a network target (ADR-0020 §7). */
export function hasNetworkCard(c: ConnectionSummary): boolean {
  return probeHostOf(c.protocol, c.host, c.port) !== null;
}

function RunLine({ state, children }: { state: RunState<unknown>; children: React.ReactNode }) {
  if (state.status === "idle") return null;
  if (state.status === "running") return <p className="net-line net-running" role="status"><span aria-hidden className="state-dot" data-state="connecting" /> Running…</p>;
  if (state.status === "error") return <p className="net-line" role="alert" data-outcome="closed"><span className="net-outcome">{state.error}</span></p>;
  return <>{children}</>;
}

/**
 * Inspector → Network (ADR-0020): one TCP handshake, the OS ping / traceroute at fixed paths and
 * a read-only WireGuard status. Defaults to the connection's host and port; an "other host" field
 * uses the same validation as Rust. Results are plain text; nothing streams and nothing elevates.
 */
export function NetworkCard({ c }: { c: ConnectionSummary }) {
  const id = useId();
  const probe = probeHostOf(c.protocol, c.host, c.port);
  const { tools, toolsError, runs, run } = useNet();
  const [other, setOther] = useState("");
  const [port, setPort] = useState(probe?.port !== null && probe?.port !== undefined ? String(probe.port) : "");
  const [count, setCount] = useState<number>(NET_LIMITS.ping.count.default);
  const [hops, setHops] = useState(String(NET_LIMITS.traceroute.maxHops.default));

  if (!probe) return null;
  const otherHost = other.trim();
  const otherBad = otherHost !== "" && !validHost(otherHost);
  const portNum = port.trim() === "" ? Number.NaN : Number(port);
  const portBad = !validPort(portNum);
  const hopsNum = hops.trim() === "" ? Number.NaN : Number(hops);
  const hopsBad = !validMaxHops(hopsNum);
  const target = (): NetTarget => (otherHost === "" ? { connectionId: c.id } : { host: otherHost });
  const targetLabel = otherHost === "" ? probe.host : otherHost;
  const running = (t: NetTool) => runs[t].status === "running";
  const missing = (ok: boolean) => (tools !== null && !ok ? TOOL_MISSING : undefined);

  const checkPort = () => void run("port", () => ipc.netPortCheck({ target: otherHost === "" && Number(port) === probe.port ? { connectionId: c.id } : { host: targetLabel, port: portNum } }));
  const ping = () => void run("ping", () => ipc.netPing({ target: target(), count }));
  const trace = () => void run("traceroute", () => ipc.netTraceroute({ target: target(), maxHops: hopsNum }));
  const wg = () => void run("wg", () => ipc.netWgShow());

  return (
    <section className="readout-section net-card" aria-label="Network">
      <HudLabel>Network</HudLabel>
      {toolsError && <p role="alert" className="settings-err">{toolsError}</p>}

      <div className="net-target">
        <label htmlFor={`${id}-host`} className="field-label">Other host <span className="field-opt">optional</span></label>
        <input
          id={`${id}-host`}
          className="field mono"
          value={other}
          placeholder={probe.host}
          spellCheck={false}
          autoComplete="off"
          aria-invalid={otherBad || undefined}
          onChange={(e) => { setOther(e.target.value); }}
        />
        <p className="field-hint">{otherBad ? "A host name (RFC 1123 labels) or an IPv4 / IPv6 address." : `Probes ${targetLabel}. Leave empty for this connection's host.`}</p>
      </div>

      <div className="net-tool">
        <div className="net-tool-row">
          <button type="button" className="btn" disabled={otherBad || portBad || running("port")} onClick={checkPort}>Check port</button>
          <label htmlFor={`${id}-port`} className="net-param">
            <span className="m-micro">port</span>
            <input id={`${id}-port`} className="field net-num" inputMode="numeric" value={port} aria-invalid={portBad || undefined} onChange={(e) => { setPort(e.target.value); }} />
          </label>
          <span className="field-hint ml-auto">one TCP handshake, no data</span>
        </div>
        <RunLine state={runs.port}>{runs.port.status === "done" && <PortResult r={runs.port.result} />}</RunLine>
      </div>

      <div className="net-tool" data-missing={tools !== null && !tools.ping ? true : undefined}>
        <div className="net-tool-row">
          <button type="button" className="btn" disabled={tools === null || !tools.ping || otherBad || running("ping")} title={missing(tools?.ping ?? true)} onClick={ping}>Ping</button>
          <label htmlFor={`${id}-count`} className="net-param">
            <span className="m-micro">count</span>
            <select id={`${id}-count`} className="field net-num" value={count} onChange={(e) => { setCount(Number(e.target.value)); }}>
              {Array.from({ length: NET_LIMITS.ping.count.max }, (_, i) => i + 1).map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          {tools !== null && !tools.ping ? <span className="field-hint ml-auto">ping {TOOL_MISSING}</span> : <span className="field-hint ml-auto">the OS ping, ≤ 30 s</span>}
        </div>
        <RunLine state={runs.ping}>{runs.ping.status === "done" && <PingResult r={runs.ping.result} />}</RunLine>
      </div>

      <div className="net-tool" data-missing={tools !== null && tools.traceroute === null ? true : undefined}>
        <div className="net-tool-row">
          <button type="button" className="btn" disabled={tools === null || tools.traceroute === null || otherBad || hopsBad || running("traceroute")} title={missing(tools?.traceroute !== null)} onClick={trace}>Traceroute</button>
          <label htmlFor={`${id}-hops`} className="net-param">
            <span className="m-micro">max hops</span>
            <input id={`${id}-hops`} className="field net-num" inputMode="numeric" value={hops} aria-invalid={hopsBad || undefined} onChange={(e) => { setHops(e.target.value); }} />
          </label>
          {tools !== null && tools.traceroute === null ? <span className="field-hint ml-auto">traceroute {TOOL_MISSING}</span> : <span className="field-hint ml-auto">{tools?.traceroute ?? "traceroute"}, ≤ 60 s</span>}
        </div>
        <RunLine state={runs.traceroute}>{runs.traceroute.status === "done" && <TraceResult r={runs.traceroute.result} />}</RunLine>
      </div>

      {tools?.wg && (
        <div className="net-tool">
          <div className="net-tool-row">
            <button type="button" className="btn" disabled={running("wg")} onClick={wg}>WireGuard</button>
            <span className="field-hint ml-auto">wg show, read-only, never elevated</span>
          </div>
          <RunLine state={runs.wg}>{runs.wg.status === "done" && <WgResult r={runs.wg.result} />}</RunLine>
        </div>
      )}
      <p className="field-hint">Every run writes an audit entry with the host and the outcome.</p>
    </section>
  );
}

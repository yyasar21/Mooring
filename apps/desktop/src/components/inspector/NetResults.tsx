import type { PingRun, PortCheck, PortOutcome, TraceRun, WgStatus } from "../../lib/ipc";
import { fmtAgo, fmtBytes, fmtMs } from "../../lib/format";

/** Lines shown of a tool's output; Rust already caps at 200 × 512 bytes, this keeps the card short. */
export const MAX_OUTPUT_LINES = 200;

export const PORT_OUTCOME: Record<PortOutcome, string> = {
  open: "Open",
  closed: "Closed — the host refused the connection",
  timeout: "Timed out — nothing answered within the deadline",
  unreachable: "Unreachable — no route to the host",
  dns_failed: "DNS lookup failed",
};

/** Raw tool output, sanitised by Rust, in a scrolling monospace box with the run flags. */
export function OutputLines({ lines, timedOut, truncated, exitCode, label }: { lines: string[]; timedOut: boolean; truncated: boolean; exitCode: number | null; label: string }) {
  const shown = lines.slice(0, MAX_OUTPUT_LINES);
  const flags = [
    timedOut ? "stopped at the deadline; the result is partial" : null,
    truncated ? "output cap reached; the result is partial" : null,
    lines.length > shown.length ? `${String(lines.length - shown.length)} more lines not shown` : null,
    exitCode !== null && exitCode !== 0 ? `exit code ${String(exitCode)}` : null,
  ].filter((f): f is string => f !== null);
  return (
    <details className="net-output-wrap">
      <summary className="net-output-summary">{label}{flags.length > 0 ? ` · ${flags.join(" · ")}` : ""}</summary>
      <pre className="net-output select-text" aria-label={label} tabIndex={0}>{shown.join("\n")}</pre>
    </details>
  );
}

export function PortResult({ r }: { r: PortCheck }) {
  return (
    <p className="net-line" data-outcome={r.outcome}>
      <span className="net-outcome">{PORT_OUTCOME[r.outcome]}</span>
      {r.outcome === "open" && <span className="mono text-text-muted"> {r.addr} in {fmtMs(r.rttMs)}</span>}
    </p>
  );
}

export function PingResult({ r }: { r: PingRun }) {
  const s = r.result;
  const hasRtt = s.minMs !== undefined && s.avgMs !== undefined && s.maxMs !== undefined;
  return (
    <div className="net-result">
      <p className="net-line" data-outcome={s.received === 0 ? "closed" : s.lossPercent > 0 ? "timeout" : "open"}>
        <span className="net-outcome">{s.received === 0 ? "No reply" : s.lossPercent > 0 ? "Partial loss" : "Reachable"}</span>
        <span className="tnum text-text-muted"> {s.sent} sent, {s.received} received, {s.lossPercent}% loss</span>
        {hasRtt && <span className="tnum text-text-muted"> · min/avg/max {fmtMs(s.minMs ?? 0)} / {fmtMs(s.avgMs ?? 0)} / {fmtMs(s.maxMs ?? 0)}</span>}
      </p>
      {s.replies.length > 0 && (
        <table className="net-table" aria-label="Ping replies">
          <thead><tr><th>seq</th><th>ttl</th><th>rtt</th></tr></thead>
          <tbody>
            {s.replies.map((p, i) => (
              <tr key={i}><td>{p.seq ?? "—"}</td><td>{p.ttl ?? "—"}</td><td>{fmtMs(p.rttMs)}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      <OutputLines lines={s.lines} timedOut={r.timedOut} truncated={r.truncated} exitCode={r.exitCode} label="ping output" />
    </div>
  );
}

export function TraceResult({ r }: { r: TraceRun }) {
  const t = r.result;
  return (
    <div className="net-result">
      <p className="net-line" data-outcome={t.reached ? "open" : "timeout"}>
        <span className="net-outcome">{t.reached ? "Reached" : "Not reached"}</span>
        <span className="tnum text-text-muted"> {t.hops.length} hop{t.hops.length === 1 ? "" : "s"} · {r.tool}</span>
      </p>
      {t.hops.length > 0 && (
        <table className="net-table" aria-label="Traceroute hops">
          <thead><tr><th>#</th><th>address</th><th>rtt</th></tr></thead>
          <tbody>
            {t.hops.map((h) => (
              <tr key={h.hop} data-timeout={h.timeouts > 0 && h.rttsMs.length === 0 ? true : undefined}>
                <td>{h.hop}</td>
                <td className="mono">{h.addr ?? "*"}{h.note ? <span className="text-hot"> {h.note}</span> : null}</td>
                <td>{h.rttsMs.length > 0 ? h.rttsMs.map(fmtMs).join(" ") : "*"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <OutputLines lines={t.lines} timedOut={r.timedOut} truncated={r.truncated} exitCode={r.exitCode} label={`${r.tool} output`} />
    </div>
  );
}

export function WgResult({ r }: { r: WgStatus }) {
  if (r.interfaces.length === 0) return <p className="net-line"><span className="net-outcome">No WireGuard interfaces are up.</span></p>;
  return (
    <div className="net-result">
      {r.interfaces.map((i) => (
        <div key={i.name} className="net-wg">
          <p className="net-line" data-outcome="open">
            <span className="net-outcome mono">{i.name}</span>
            <span className="tnum text-text-muted">{i.listenPort !== undefined ? ` listening on ${String(i.listenPort)}` : ""} · {i.peers.length} peer{i.peers.length === 1 ? "" : "s"}</span>
          </p>
          {i.peers.length > 0 && (
            <ul className="net-peers" aria-label={`Peers of ${i.name}`}>
              {i.peers.map((p) => (
                <li key={p.publicKey} className="net-peer">
                  <span className="mono">{p.publicKey}</span>
                  <span className="mono text-text-muted">{p.endpoint ?? "no endpoint"}</span>
                  <span>handshake {p.lastHandshakeSecs !== undefined ? fmtAgo(p.lastHandshakeSecs) : "never"}</span>
                  <span className="tnum text-text-muted">rx {fmtBytes(p.rxBytes) ?? "0 B"} · tx {fmtBytes(p.txBytes) ?? "0 B"}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

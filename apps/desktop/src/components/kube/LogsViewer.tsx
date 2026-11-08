import { useEffect, useId, useMemo, useRef, useState } from "react";
import { KUBE_LIMITS, ipc, type ConnectionSummary } from "../../lib/ipc";
import type { KubeLogsTarget } from "../../stores/kube";
import type { Tab } from "../../stores/sessions";
import { useLogStream } from "./useLogStream";
import { useKubeOptions } from "./useCluster";

/** Lines drawn at once; the rest stay searchable. */
export const RENDER_LINES = 2000;

export function formatBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n % (1024 * 1024) === 0 ? 0 : 1)} MiB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KiB`;
  return `${n} B`;
}

/**
 * A container's log (ADR-0014 §5): not a terminal, plain text that Rust sanitised and capped at
 * the connection's `maxLogBytes`. Follow, tail, timestamps and the container restart the stream.
 */
export function LogsViewer({ tab, target, connection, active }: { tab: Tab; target: KubeLogsTarget; connection: ConnectionSummary | undefined; active: boolean }) {
  const id = useId();
  const options = useKubeOptions(connection);
  const [containers, setContainers] = useState<string[]>([target.container]);
  const [container, setContainer] = useState(target.container);
  const [follow, setFollow] = useState(true);
  const [timestamps, setTimestamps] = useState(false);
  const [tail, setTail] = useState(String(options.logTailLines));
  const [tailLines, setTailLines] = useState<number>(options.logTailLines);
  const [query, setQuery] = useState("");
  const [onlyMatches, setOnlyMatches] = useState(false);
  const [epoch, setEpoch] = useState(0);
  const bottom = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let live = true;
    ipc.kubePods({ sessionId: target.parentSessionId, namespace: target.namespace, labelSelector: null }).then(
      (r) => {
        const p = r.items.find((x) => x.name === target.pod);
        if (live && p) setContainers(p.containers.map((c) => c.name));
      },
      () => undefined,
    );
    return () => { live = false; };
  }, [target.parentSessionId, target.namespace, target.pod]);

  const stream = useLogStream(
    { sessionId: target.parentSessionId, namespace: target.namespace, pod: target.pod, container, follow, tailLines, timestamps },
    epoch,
  );

  const q = query.trim().toLowerCase();
  const matches = useMemo(() => (q ? stream.lines.filter((l) => l.toLowerCase().includes(q)).length : 0), [stream.lines, q]);
  const visible = useMemo(() => {
    const base = q && onlyMatches ? stream.lines.filter((l) => l.toLowerCase().includes(q)) : stream.lines;
    return base.slice(-RENDER_LINES);
  }, [stream.lines, q, onlyMatches]);

  useEffect(() => {
    if (follow && active) bottom.current?.scrollIntoView({ block: "end" });
  }, [visible, follow, active]);

  const tailBad = !/^\d{1,5}$/.test(tail) || Number(tail) < 1 || Number(tail) > KUBE_LIMITS.maxTailLines;
  const applyTail = () => { if (!tailBad) setTailLines(Number(tail)); };

  return (
    <div className="kube-logs" aria-label={`Logs of ${target.pod}/${container}`} role="region">
      <div role="toolbar" aria-label="Log controls" className="session-toolbar kube-logs-bar">
        <span className="m-micro">Logs</span>
        <span className="mono truncate text-text-muted" title={`${target.namespace}/${target.pod}`}>{target.namespace}/{target.pod}</span>
        <label className="sr-only" htmlFor={`${id}-c`}>Container</label>
        <select id={`${id}-c`} className="field mono kube-logs-select" value={container} onChange={(e) => { setContainer(e.target.value); }}>
          {containers.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <label className="kube-check"><input type="checkbox" checked={follow} onChange={(e) => { setFollow(e.target.checked); }} /> Follow</label>
        <label className="kube-check"><input type="checkbox" checked={timestamps} onChange={(e) => { setTimestamps(e.target.checked); }} /> Timestamps</label>
        <label className="kube-check" htmlFor={`${id}-t`}>Tail</label>
        <input id={`${id}-t`} className="field mono kube-logs-tail" inputMode="numeric" aria-label="Tail lines" aria-invalid={tailBad || undefined} value={tail}
          onChange={(e) => { setTail(e.target.value); }} onBlur={applyTail} onKeyDown={(e) => { if (e.key === "Enter") applyTail(); }} />
        <span className="flex-1" />
        <input type="search" className="field kube-logs-search" aria-label="Search logs" placeholder="Search" value={query} onChange={(e) => { setQuery(e.target.value); }} />
        {q && <span className="chip tnum" aria-live="polite">{matches} match{matches === 1 ? "" : "es"}</span>}
        <label className="kube-check"><input type="checkbox" checked={onlyMatches} onChange={(e) => { setOnlyMatches(e.target.checked); }} /> Only matches</label>
        {stream.running ? (
          <button type="button" className="btn btn-ghost" onClick={stream.stop}>Stop</button>
        ) : (
          <button type="button" className="btn btn-ghost" onClick={() => { setEpoch((n) => n + 1); }}>Restart</button>
        )}
      </div>

      {stream.error && <p role="alert" className="tool-error">{stream.error}</p>}
      {stream.ended?.truncated && (
        <p role="status" className="kube-cap">
          Stopped at the {formatBytes(options.maxLogBytes)} log limit of this connection. Lower the tail, or raise “Max log bytes” in the connection options (up to 64 MiB).
        </p>
      )}
      {stream.dropped > 0 && <p className="field-hint px-3">{stream.dropped.toLocaleString("en-US")} older lines were dropped from this view.</p>}

      <div className="kube-log-body term-bezel m-hud" tabIndex={0} aria-label="Log lines">
        {visible.map((l, i) => <LogLine key={i} line={l} q={q} />)}
        <div ref={bottom} />
      </div>

      <div className="kube-logs-foot" role="status">
        <span className="chip" data-tone={stream.running ? "success" : undefined}>{stream.running ? (follow ? "Following" : "Reading") : stream.ended ? "Ended" : "Stopped"}</span>
        <span className="mono tnum">{stream.lines.length.toLocaleString("en-US")} lines · {formatBytes(stream.bytes)} of {formatBytes(options.maxLogBytes)}</span>
        {stream.ended?.reason && <span className="text-text-muted">{stream.ended.reason}</span>}
        {visible.length === RENDER_LINES && <span className="text-text-faint">Showing the last {RENDER_LINES.toLocaleString("en-US")} lines.</span>}
        <span className="flex-1" />
        <span className="text-text-faint">{tab.state === "closed" ? "Cluster session closed" : "Read-only"}</span>
      </div>
    </div>
  );
}

function LogLine({ line, q }: { line: string; q: string }) {
  if (!q) return <div className="kube-log-line">{line || " "}</div>;
  const lower = line.toLowerCase();
  const out: React.ReactNode[] = [];
  let at = 0;
  for (let i = lower.indexOf(q); i >= 0; i = lower.indexOf(q, at)) {
    out.push(line.slice(at, i), <mark key={i}>{line.slice(i, i + q.length)}</mark>);
    at = i + q.length;
  }
  out.push(line.slice(at));
  return <div className="kube-log-line" data-match={at > 0 || undefined}>{out}</div>;
}

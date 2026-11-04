import { useEffect, useRef, useState } from "react";
import { ipc } from "../../lib/ipc";
import { describeError } from "../../stores/errors";

/** Lines kept in memory per viewer; older ones are dropped (and counted). */
export const MAX_LOG_LINES = 50_000;

export interface LogParams {
  sessionId: string;
  namespace: string;
  pod: string;
  container: string;
  follow: boolean;
  tailLines: number | null;
  timestamps: boolean;
}

export interface LogStream {
  lines: string[];
  dropped: number;
  bytes: number;
  running: boolean;
  /** Set when the stream ended: Rust stopped at `maxLogBytes` (truncated) or for a reason. */
  ended: { truncated: boolean; reason: string | null } | null;
  error: string | null;
  stop: () => void;
}

// Rust already replaces controls and bidi overrides (ADR-0014 §5); the UI does it again, keeping `\t`.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
export const sanitizeLogLine = (s: string): string => s.replace(/\r$/, "").replace(UNSAFE, "\ufffd");

/** Streams one container's log with `kube_logs`; a parameter change restarts, unmount stops it. */
export function useLogStream(p: LogParams | null, epoch: number): LogStream {
  const [lines, setLines] = useState<string[]>([]);
  const [dropped, setDropped] = useState(0);
  const [bytes, setBytes] = useState(0);
  const [running, setRunning] = useState(false);
  const [ended, setEnded] = useState<LogStream["ended"]>(null);
  const [error, setError] = useState<string | null>(null);
  const stopRef = useRef<() => void>(() => undefined);
  const key = p ? JSON.stringify(p) : "";

  useEffect(() => {
    setLines([]);
    setDropped(0);
    setBytes(0);
    setEnded(null);
    setError(null);
    if (!key) return;
    const params = JSON.parse(key) as LogParams;
    let live = true;
    let streamId: string | null = null;
    const decoder = new TextDecoder("utf-8", { fatal: false });
    let partial = "";
    const push = (text: string, flush: boolean) => {
      const parts = (partial + text).split("\n");
      partial = flush ? "" : (parts.pop() ?? "");
      const fresh = parts.filter((l, i) => !(flush && i === parts.length - 1 && l === "")).map(sanitizeLogLine);
      if (fresh.length === 0) return;
      setLines((cur) => {
        const next = cur.length + fresh.length > MAX_LOG_LINES ? [...cur, ...fresh].slice(-MAX_LOG_LINES) : [...cur, ...fresh];
        const lost = cur.length + fresh.length - next.length;
        if (lost > 0) setDropped((d) => d + lost);
        return next;
      });
    };
    const stop = () => {
      if (!live) return;
      live = false;
      setRunning(false);
      if (streamId) void ipc.kubeLogsStop({ sessionId: params.sessionId, streamId }).catch(() => undefined);
    };
    stopRef.current = stop;
    setRunning(true);
    ipc.kubeLogs({
      ...params,
      sinceSeconds: null,
      onChunk: (c) => {
        if (!live) return;
        if (c.kind === "data") {
          setBytes((b) => b + c.data.length);
          push(decoder.decode(c.data, { stream: true }), false);
        } else {
          push(decoder.decode(), true);
          live = false;
          setRunning(false);
          setEnded({ truncated: c.truncated, reason: c.reason });
        }
      },
    }).then(
      (r) => {
        streamId = r.streamId;
        if (!live) void ipc.kubeLogsStop({ sessionId: params.sessionId, streamId: r.streamId }).catch(() => undefined);
      },
      (e: unknown) => {
        if (!live) return;
        live = false;
        setRunning(false);
        setError(describeError(e));
      },
    );
    return stop;
  }, [key, epoch]);

  return { lines, dropped, bytes, running, ended, error, stop: () => { stopRef.current(); } };
}

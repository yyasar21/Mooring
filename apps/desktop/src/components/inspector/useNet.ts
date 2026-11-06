import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, type NetTools, type PingRun, type PortCheck, type TraceRun, type WgStatus } from "../../lib/ipc";
import { describeError } from "../../stores/errors";

export type NetTool = "port" | "ping" | "traceroute" | "wg";

interface ResultOf {
  port: PortCheck;
  ping: PingRun;
  traceroute: TraceRun;
  wg: WgStatus;
}

export type RunState<T> =
  | { status: "idle" }
  | { status: "running"; since: number }
  | { status: "done"; result: T; ms: number }
  | { status: "error"; error: string };

export type NetRuns = { [K in NetTool]: RunState<ResultOf[K]> };

const IDLE: NetRuns = { port: { status: "idle" }, ping: { status: "idle" }, traceroute: { status: "idle" }, wg: { status: "idle" } };

/**
 * One run per tool at a time (the backend allows two tool processes; a third is `net.busy`, which
 * the card shows as text). The commands resolve when the tool ends (no streaming or cancel in N1),
 * so a run only shows a running state until the promise settles. Unmounting forgets the results.
 */
export function useNet() {
  const [tools, setTools] = useState<NetTools | null>(null);
  const [toolsError, setToolsError] = useState<string | null>(null);
  const [runs, setRuns] = useState<NetRuns>(IDLE);
  const live = useRef(true);

  useEffect(() => {
    live.current = true;
    ipc.netTools().then(
      (t) => { if (live.current) setTools(t); },
      (e: unknown) => { if (live.current) setToolsError(describeError(e)); },
    );
    return () => { live.current = false; };
  }, []);

  const run = useCallback(async <K extends NetTool>(tool: K, fn: () => Promise<ResultOf[K]>): Promise<void> => {
    const since = Date.now();
    setRuns((r) => ({ ...r, [tool]: { status: "running", since } }));
    try {
      const result = await fn();
      if (live.current) setRuns((r) => ({ ...r, [tool]: { status: "done", result, ms: Date.now() - since } }));
    } catch (e: unknown) {
      if (live.current) setRuns((r) => ({ ...r, [tool]: { status: "error", error: describeError(e) } }));
    }
  }, []);

  const clear = useCallback((tool: NetTool) => { setRuns((r) => ({ ...r, [tool]: { status: "idle" } })); }, []);

  return { tools, toolsError, runs, run, clear };
}

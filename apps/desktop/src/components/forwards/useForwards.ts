import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, isPodTarget, type ForwardInfo, type ForwardOpen, type PodForwardOpen } from "../../lib/ipc";

/** What a form submits: an SSH forward or (on a cluster session) a pod forward, without the session. */
export type ForwardDraft = Omit<ForwardOpen, "sessionId"> | Omit<PodForwardOpen, "sessionId">;
import { describeError } from "../../stores/errors";
import { useForwardCounts } from "../../stores/forwardCounts";

/** How often the list refreshes while the panel is open (connection counts change). */
export const FORWARD_POLL_MS = 5000;

export interface ForwardsState {
  items: ForwardInfo[];
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  /** Resolves to the new forward, or null when the backend refused (error is set). */
  open: (f: ForwardDraft) => Promise<ForwardInfo | null>;
  close: (forwardId: string) => Promise<void>;
  clearError: () => void;
}

/** Forwards of one SSH or cluster session. `sessionId` null = not connected; nothing is requested. */
export function useForwards(sessionId: string | null): ForwardsState {
  const [items, setItems] = useState<ForwardInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = useRef(sessionId);
  current.current = sessionId;

  // The header's "Forwards" count follows this list as soon as it changes.
  useEffect(() => {
    if (sessionId && !loading) useForwardCounts.getState().setCount(sessionId, items.length);
  }, [sessionId, items, loading]);

  const refresh = useCallback(async () => {
    if (!sessionId) return;
    try {
      const list = await ipc.forwardList({ sessionId });
      if (current.current === sessionId) setItems(list);
    } catch (e: unknown) {
      if (current.current === sessionId) setError(describeError(e));
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    setItems([]);
    setError(null);
    if (!sessionId) return;
    setLoading(true);
    void refresh();
    const timer = setInterval(() => void refresh(), FORWARD_POLL_MS);
    return () => { clearInterval(timer); };
  }, [sessionId, refresh]);

  const open = useCallback(
    async (f: ForwardDraft) => {
      if (!sessionId) return null;
      try {
        const info = await ipc.forwardOpen({ sessionId, ...f });
        setItems((cur) => [...cur, info]);
        setError(null);
        return info;
      } catch (e: unknown) {
        setError(describeError(e));
        return null;
      }
    },
    [sessionId],
  );

  const close = useCallback(
    async (forwardId: string) => {
      if (!sessionId) return;
      try {
        await ipc.forwardClose({ sessionId, forwardId });
        setItems((cur) => cur.filter((x) => x.id !== forwardId));
        setError(null);
      } catch (e: unknown) {
        setError(describeError(e));
        void refresh();
      }
    },
    [sessionId, refresh],
  );

  const clearError = useCallback(() => { setError(null); }, []);

  return { items, loading, error, refresh, open, close, clearError };
}

/** `host:port`, with IPv6 literals in brackets. */
export function formatHostPort(hp: { host: string; port: number }): string {
  return hp.host.includes(":") ? `[${hp.host}]:${hp.port}` : `${hp.host}:${hp.port}`;
}

/** A forward target for display: `host:port`, or `namespace/pod:port` for pod forwards. */
export function formatTarget(t: ForwardInfo["target"]): string {
  if (t === null) return "SOCKS5";
  return isPodTarget(t) ? `${t.namespace}/${t.pod}:${t.port}` : formatHostPort(t);
}

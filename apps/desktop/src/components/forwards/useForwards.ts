import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, type ForwardInfo, type ForwardOpen } from "../../lib/ipc";
import { describeError } from "../../stores/errors";

/** How often the list refreshes while the panel is open (connection counts change). */
export const FORWARD_POLL_MS = 5000;

export interface ForwardsState {
  items: ForwardInfo[];
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  /** Resolves to the new forward, or null when the backend refused (error is set). */
  open: (f: Omit<ForwardOpen, "sessionId">) => Promise<ForwardInfo | null>;
  close: (forwardId: string) => Promise<void>;
  clearError: () => void;
}

/** Forwards of one SSH session. `sessionId` null = not connected; nothing is requested. */
export function useForwards(sessionId: string | null): ForwardsState {
  const [items, setItems] = useState<ForwardInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = useRef(sessionId);
  current.current = sessionId;

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
    async (f: Omit<ForwardOpen, "sessionId">) => {
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

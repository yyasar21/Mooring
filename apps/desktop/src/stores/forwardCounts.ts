// The number of open port forwards per SSH session, for the count on the session header's
// "Forwards" view switch. The forwards panel writes it whenever its list changes; the header
// reads `forward_list` (passive) while its tab is shown, so the count is right before the panel
// was ever opened.
import { useEffect } from "react";
import { create } from "zustand";
import { ipc } from "../lib/ipc";

interface ForwardCounts {
  counts: Record<string, number>;
  setCount: (sessionId: string, n: number) => void;
}

export const useForwardCounts = create<ForwardCounts>((set) => ({
  counts: {},
  setCount: (sessionId, n) => { set((s) => (s.counts[sessionId] === n ? s : { counts: { ...s.counts, [sessionId]: n } })); },
}));

/** How often the header re-reads the list while its tab is shown. */
export const COUNT_POLL_MS = 10_000;

/** The open forwards of a session (0 while unknown or not connected). Polls only while `watch`. */
export function useForwardCount(sessionId: string | null, watch: boolean): number {
  const n = useForwardCounts((s) => (sessionId ? (s.counts[sessionId] ?? 0) : 0));
  useEffect(() => {
    if (!sessionId || !watch) return;
    let live = true;
    const read = () => {
      ipc.forwardList({ sessionId }).then(
        (list) => { if (live) useForwardCounts.getState().setCount(sessionId, list.length); },
        () => undefined,
      );
    };
    read();
    const timer = setInterval(read, COUNT_POLL_MS);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [sessionId, watch]);
  return n;
}

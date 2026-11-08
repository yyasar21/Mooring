// How long each tab has been connected, for the session header's status pill. Kept beside the
// store rather than in `Tab`: every path that connects a tab (session events, attach, adopt after
// unlock, kube, web) goes through `useSessions`, so one subscription stamps them all.
import type { DotTone } from "@mooring/ui";
import { useSessions, type Tab } from "./sessions";

const since = new Map<string, number>();

/** A session counts as up while it is connected here or shown in its own window. */
const up = (t: Pick<Tab, "state">) => t.state === "connected" || t.state === "detached";

/** Bring the stamps in line with the tabs: a tab that came up gets `now`, one that went down loses it. */
export function syncClock(tabs: readonly Pick<Tab, "id" | "state">[], now = Date.now()): void {
  const ids = new Set<string>();
  for (const t of tabs) {
    ids.add(t.id);
    if (up(t)) {
      if (!since.has(t.id)) since.set(t.id, now);
    } else {
      since.delete(t.id);
    }
  }
  for (const id of since.keys()) if (!ids.has(id)) since.delete(id);
}

/** `Date.now()` when the tab last came up, or null while it is not up. */
export function connectedSince(tabId: string): number | null {
  return since.get(tabId) ?? null;
}

syncClock(useSessions.getState().tabs);
useSessions.subscribe((s) => { syncClock(s.tabs); });

/** "00:12:31" (hours keep growing past 99). */
export function fmtDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return [h, m, s].map((n) => String(n).padStart(2, "0")).join(":");
}

export type StatusTone = "success" | "warning" | "danger" | "info" | "neutral";

/**
 * The header pill of a tab (design review §4.3): Connected · Connecting · Waiting for you ·
 * Reconnecting · In its own window · Closed · Disconnected. Colour always comes with this label.
 */
export function sessionStatus(tab: Pick<Tab, "state" | "prompt" | "closeCode" | "touch">): { tone: StatusTone; dot: DotTone; label: string } {
  if (tab.prompt || (tab.touch && !tab.touch.timedOut)) return { tone: "warning", dot: "wait", label: "Waiting for you" };
  switch (tab.state) {
    case "connected":
      return { tone: "success", dot: "ok", label: "Connected" };
    case "detached":
      return { tone: "success", dot: "ok", label: "In its own window" };
    case "connecting":
      return { tone: "info", dot: "busy", label: "Connecting" };
    case "reconnecting":
      return { tone: "warning", dot: "busy", label: "Reconnecting" };
    case "closed":
      return tab.closeCode === "user" || tab.closeCode === "server_ended"
        ? { tone: "neutral", dot: "neutral", label: "Closed" }
        : { tone: "danger", dot: "err", label: "Disconnected" };
  }
}

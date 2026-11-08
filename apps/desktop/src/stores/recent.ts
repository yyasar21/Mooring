// L3: connections opened in this unlocked run, most recent first, for the palette's Recent group.
// Ids only, in memory only: nothing about which hosts were opened is written to disk, and the list
// is dropped when the vault locks.
import { useApp } from "./app";
import { useSessions, type Tab } from "./sessions";

export const RECENT_MAX = 6;
let recent: string[] = [];
let seen = new Set<string>();

/** Tabs that appeared since the last call move their connection to the front. */
export function trackTabs(tabs: readonly Pick<Tab, "id" | "connectionId">[]): void {
  const ids = new Set<string>();
  for (const t of tabs) {
    ids.add(t.id);
    if (!seen.has(t.id)) recent = [t.connectionId, ...recent.filter((c) => c !== t.connectionId)].slice(0, RECENT_MAX);
  }
  seen = ids;
}

/** Recent connection ids, most recent first. */
export function recentConnections(): readonly string[] {
  return recent;
}

export function clearRecent(): void {
  recent = [];
  seen = new Set();
}

trackTabs(useSessions.getState().tabs);
useSessions.subscribe((s) => { trackTabs(s.tabs); });
useApp.subscribe((s, prev) => { if (s.vault !== "unlocked" && prev.vault === "unlocked") clearRecent(); });

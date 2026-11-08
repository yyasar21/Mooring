import { ipc } from "../lib/ipc";
import { useSessions } from "./sessions";
import type { Tab } from "./sessions.types";

/** States in which the header's Disconnect has something to end. */
export const canDisconnect = (t: Pick<Tab, "state" | "sessionId">): boolean =>
  t.sessionId !== null && (t.state === "connected" || t.state === "connecting" || t.state === "reconnecting");

/**
 * The session header's "Disconnect" (design review §4.2): end the session but keep the tab, closed
 * with code `user`, so its scrollback stays and Reconnect is one click away. A plain
 * `session_close`, like "Cancel reconnect"; Rust's own `closed` event may follow and only refreshes
 * the reason.
 */
export async function disconnect(tabId: string): Promise<void> {
  const tab = useSessions.getState().tabs.find((t) => t.id === tabId);
  if (!tab || !canDisconnect(tab)) return;
  const sid = tab.sessionId;
  useSessions.setState({
    tabs: useSessions.getState().tabs.map((t) =>
      t.id === tabId ? { ...t, state: "closed", reason: "Disconnected by you.", closeCode: "user", reconnect: null, sessionId: null, prompt: null } : t,
    ),
  });
  if (!sid) return;
  try {
    await ipc.sessionClose({ sessionId: sid });
  } catch {
    // already gone on the backend
  }
}

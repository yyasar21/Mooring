import { ipc } from "../lib/ipc";
import { useSessions } from "./sessions";

/**
 * "Cancel reconnect": the Tauri layer owns the retry loop (ADR-0011), so cancelling it is a plain
 * `session_close`. The tab stays, closed with code `user`, so Reconnect is one click away. Rust's
 * own `closed` event may follow and only refreshes the reason.
 */
export async function cancelReconnect(tabId: string): Promise<void> {
  const tab = useSessions.getState().tabs.find((t) => t.id === tabId);
  if (tab?.state !== "reconnecting") return;
  const sid = tab.sessionId;
  useSessions.setState({
    tabs: useSessions.getState().tabs.map((t) =>
      t.id === tabId ? { ...t, state: "closed", reason: "Reconnect cancelled.", closeCode: "user", reconnect: null, sessionId: null, prompt: null } : t,
    ),
  });
  if (!sid) return;
  try {
    await ipc.sessionClose({ sessionId: sid });
  } catch {
    // already gone on the backend
  }
}

// Detach / attach in `main` (ADR-0013). `window_detach` opens `detached-<sessionId>`; that window's
// `session_attach` makes Rust send `detached` here and the tab shows a placeholder. "Bring back"
// is `window_attach`: Rust closes the window and sends `attached`, and the sessions store attaches
// this view again with fresh channels.
import { ipc } from "../lib/ipc";
import { describeError } from "./errors";
import { useSessions } from "./sessions";

/**
 * Sessions currently shown in their own window. Ids only (no vault data), so it is kept across a
 * lock: after unlock the adopted tab stays a placeholder instead of pulling the session back.
 */
export const detachedSessions = new Set<string>();

/** "Bring back": returns the error text to show, or null. */
export async function bringBack(tabId: string): Promise<string | null> {
  const sid = useSessions.getState().tabs.find((t) => t.id === tabId)?.sessionId;
  if (!sid) return null;
  try {
    await ipc.windowAttach({ sessionId: sid });
    return null;
  } catch (e: unknown) {
    return describeError(e);
  }
}

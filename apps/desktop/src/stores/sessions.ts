import { create } from "zustand";
import { ipc, type PromptPurpose, type SessionEvent, type Size } from "../lib/ipc";
import { errorText } from "./errors";

export type TabState = "connecting" | "connected" | "closed";

export interface PendingPrompt {
  id: number;
  message: string;
  secret: boolean;
  purpose: PromptPurpose;
}

export interface Tab {
  /** Local tab id (exists before the backend hands out a session id). */
  id: string;
  connectionId: string;
  sessionId: string | null;
  state: TabState;
  peerIdentity: string | null;
  prompt: PendingPrompt | null;
  reason: string | null;
}

type OutputListener = (data: Uint8Array) => void;

/**
 * Terminal output stays out of React state: it is buffered per tab until a terminal mounts,
 * then streamed straight to xterm. The buffer is capped so a hidden tab cannot grow unbounded.
 */
const MAX_BUFFER = 1 << 20;
const outputs = new Map<string, { chunks: Uint8Array[]; size: number; listener: OutputListener | null }>();

function pushOutput(tabId: string, data: Uint8Array): void {
  let o = outputs.get(tabId);
  if (!o) {
    o = { chunks: [], size: 0, listener: null };
    outputs.set(tabId, o);
  }
  if (o.listener) {
    o.listener(data);
    return;
  }
  o.chunks.push(data);
  o.size += data.length;
  while (o.size > MAX_BUFFER && o.chunks.length > 1) o.size -= o.chunks.shift()?.length ?? 0;
}

/** Attach a terminal; buffered output is replayed first. Returns the detach function. */
export function subscribeOutput(tabId: string, listener: OutputListener): () => void {
  const o = outputs.get(tabId) ?? { chunks: [], size: 0, listener: null };
  outputs.set(tabId, o);
  for (const c of o.chunks) listener(c);
  o.chunks = [];
  o.size = 0;
  o.listener = listener;
  return () => {
    if (o.listener === listener) o.listener = null;
  };
}

interface SessionState {
  tabs: Tab[];
  activeTab: string | null;
  error: string | null;

  open: (connectionId: string, opts?: { newTab?: boolean; size?: Size }) => Promise<string>;
  activate: (tabId: string) => void;
  close: (tabId: string) => Promise<void>;
  move: (tabId: string, toIndex: number) => void;
  detach: (tabId: string) => Promise<boolean>;
  send: (tabId: string, data: Uint8Array) => Promise<void>;
  resize: (tabId: string, size: Size) => Promise<void>;
  answer: (tabId: string, text: string) => Promise<boolean>;
  reconnect: (tabId: string) => Promise<void>;
  reset: () => void;
}

let tabSeq = 0;
const enc = new TextEncoder();

export const useSessions = create<SessionState>((set, get) => {
  const patch = (tabId: string, p: Partial<Tab>) => {
    set({ tabs: get().tabs.map((t) => (t.id === tabId ? { ...t, ...p } : t)) });
  };

  const onEvent = (tabId: string) => (ev: SessionEvent) => {
    switch (ev.kind) {
      case "connected":
        patch(tabId, { state: "connected", peerIdentity: ev.peerIdentity, prompt: null });
        break;
      case "bytes":
        pushOutput(tabId, ev.data);
        break;
      case "prompt":
        patch(tabId, { prompt: { id: ev.id, message: ev.message, secret: ev.secret, purpose: ev.purpose } });
        break;
      case "closed":
        patch(tabId, { state: "closed", reason: ev.reason, prompt: null, sessionId: null });
        pushOutput(tabId, enc.encode(`\r\n\x1b[2m[session closed: ${ev.reason}]\x1b[0m\r\n`));
        break;
      case "frame":
        // Graphical protocols render frames in A2; nothing to draw for terminal tabs.
        break;
    }
  };

  const start = async (tabId: string, connectionId: string, size: Size) => {
    try {
      const { sessionId } = await ipc.sessionOpen({ connectionId, size, onEvent: onEvent(tabId) });
      if (get().tabs.some((t) => t.id === tabId)) patch(tabId, { sessionId });
      else await ipc.sessionClose({ sessionId }); // tab closed while connecting
    } catch (e: unknown) {
      patch(tabId, { state: "closed", reason: errorText(e) });
    }
  };

  return {
    tabs: [],
    activeTab: null,
    error: null,

    open: async (connectionId, opts = {}) => {
      const existing = opts.newTab ? undefined : get().tabs.find((t) => t.connectionId === connectionId);
      if (existing) {
        set({ activeTab: existing.id });
        return existing.id;
      }
      tabSeq += 1;
      const id = `tab-${tabSeq}`;
      const tab: Tab = { id, connectionId, sessionId: null, state: "connecting", peerIdentity: null, prompt: null, reason: null };
      set({ tabs: [...get().tabs, tab], activeTab: id });
      await start(id, connectionId, opts.size ?? { width: 80, height: 24 });
      return id;
    },

    activate: (tabId) => { set({ activeTab: tabId }); },

    close: async (tabId) => {
      const { tabs, activeTab } = get();
      const idx = tabs.findIndex((t) => t.id === tabId);
      const tab = tabs[idx];
      if (!tab) return;
      const rest = tabs.filter((t) => t.id !== tabId);
      const nextActive = activeTab === tabId ? (rest[Math.min(idx, rest.length - 1)]?.id ?? null) : activeTab;
      set({ tabs: rest, activeTab: nextActive });
      outputs.delete(tabId);
      if (tab.sessionId) {
        try {
          await ipc.sessionClose({ sessionId: tab.sessionId });
        } catch {
          // already gone on the backend: nothing left to release
        }
      }
    },

    move: (tabId, toIndex) => {
      const tabs = [...get().tabs];
      const from = tabs.findIndex((t) => t.id === tabId);
      const [tab] = from >= 0 ? tabs.splice(from, 1) : [];
      if (!tab) return;
      tabs.splice(Math.max(0, Math.min(toIndex, tabs.length)), 0, tab);
      set({ tabs });
    },

    detach: async (tabId) => {
      const tab = get().tabs.find((t) => t.id === tabId);
      if (!tab?.sessionId) return false;
      try {
        await ipc.windowDetach({ sessionId: tab.sessionId });
      } catch (e: unknown) {
        set({ error: errorText(e) });
        return false;
      }
      // The session keeps running in its own window; this window only drops the tab.
      const rest = get().tabs.filter((t) => t.id !== tabId);
      set({ tabs: rest, activeTab: get().activeTab === tabId ? (rest.at(-1)?.id ?? null) : get().activeTab });
      outputs.delete(tabId);
      return true;
    },

    send: async (tabId, data) => {
      const sid = get().tabs.find((t) => t.id === tabId)?.sessionId;
      if (!sid) return;
      try {
        await ipc.sessionSend({ sessionId: sid, input: { kind: "bytes", data } });
      } catch (e: unknown) {
        set({ error: errorText(e) });
      }
    },

    resize: async (tabId, size) => {
      const sid = get().tabs.find((t) => t.id === tabId)?.sessionId;
      if (!sid) return;
      try {
        await ipc.sessionSend({ sessionId: sid, input: { kind: "resize", size } });
      } catch {
        // a resize racing a close is harmless
      }
    },

    answer: async (tabId, text) => {
      const tab = get().tabs.find((t) => t.id === tabId);
      if (!tab?.sessionId || !tab.prompt) return false;
      const { id } = tab.prompt;
      patch(tabId, { prompt: null });
      try {
        await ipc.sessionSend({ sessionId: tab.sessionId, input: { kind: "answer", id, text } });
        return true;
      } catch (e: unknown) {
        patch(tabId, { state: "closed", reason: errorText(e) });
        return false;
      }
    },

    reconnect: async (tabId) => {
      const tab = get().tabs.find((t) => t.id === tabId);
      if (!tab || tab.state !== "closed") return;
      patch(tabId, { state: "connecting", reason: null, peerIdentity: null });
      await start(tabId, tab.connectionId, { width: 80, height: 24 });
    },

    reset: () => {
      outputs.clear();
      set({ tabs: [], activeTab: null, error: null });
    },
  };
});

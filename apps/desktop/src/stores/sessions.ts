import { create } from "zustand";
import {
  ipc,
  isIpcError,
  type CertificateInfo,
  type CloseCode,
  type PromptAccount,
  type PromptPurpose,
  type Protocol,
  type SessionEvent,
  type SessionInfo,
  type SessionInput,
  type Size,
  type VncConnOptions,
} from "../lib/ipc";
import { optionsOf, useConnOptions } from "./connOptions";
import type { LineState } from "@mooring/ui";
import { describeError, errorText } from "./errors";
import { drainFrames, dropFrames, pushFrame } from "./frames";
import { peekSeq } from "../lib/frame/mfr1";
import { useTree } from "./tree";
import { clearOutput, dropOutput, pushOutput } from "./output";
import { closeWeb, openWeb, resetWeb } from "./web";
import { detachedSessions } from "./sessions.detach";
import { adoptKube, openCluster, useKube, type KubeTab } from "./kube";

export { subscribeOutput } from "./output";

export type TabState = "connecting" | "connected" | "reconnecting" | "detached" | "closed";

export interface PendingPrompt {
  id: number;
  message: string;
  secret: boolean;
  purpose: PromptPurpose;
  /** Only for `purpose: "credential"`: what to ask and the pre-fills. */
  account?: PromptAccount | null;
  /** Only for `purpose: "certificate_trust"`: the leaf to decide on. */
  certificate?: CertificateInfo | null;
}

export interface CredentialAnswer {
  username: string;
  domain: string | null;
  password: string;
}

export interface Reconnect {
  attempt: number;
  delayMs: number;
  /** `Date.now()` when the event arrived; the countdown runs from here. */
  since: number;
}

export interface Tab {
  /** Local tab id (exists before the backend hands out a session id). */
  id: string;
  connectionId: string;
  protocol: Protocol | null;
  sessionId: string | null;
  state: TabState;
  peerIdentity: string | null;
  /** `Connected.security`: "nla", "tls", "vnc-auth", "none", ... */
  security: string | null;
  prompt: PendingPrompt | null;
  reason: string | null;
  closeCode: CloseCode | "unknown" | null;
  reconnect: Reconnect | null;
  /** Remote desktop size after `desktop_resized` (rdp/vnc). */
  desktop: Size | null;
  /** VNC view-only (advisory in the UI; Rust drops the input). */
  viewOnly: boolean;
  /** Bumped each time this view re-attaches after a detach: the terminal resends its size. */
  attachEpoch: number;
  /** Kubernetes tabs only (ADR-0014): cluster browser, exec shell or log viewer. */
  kube?: KubeTab;
}

/** The three-state rail and dot of the design system: a reconnect reads as connecting. */
export function lineState(s: TabState): LineState {
  if (s === "reconnecting") return "connecting";
  if (s === "detached") return "connected";
  return s;
}

/** Protocols whose live session can move to a `detached-<sessionId>` window (ADR-0013). */
export const canDetach = (p: Protocol | null | undefined): boolean => p === "ssh" || p === "rdp" || p === "vnc";
/** rdp/vnc sessions draw MFR1 frames on a canvas instead of a terminal. */
export const isGraphical = (p: Protocol | null | undefined): boolean => p === "rdp" || p === "vnc";
/** Initial desktop request before the canvas has measured itself. */
export const DEFAULT_DESKTOP: Size = { width: 1280, height: 800 };

/**
 * Which local tab a backend session's event channel feeds. Ids only, no vault data, so it is kept
 * across a lock: after unlock `adopt` gives a surviving session its old tab id back and the
 * channel opened by `session_open` drives that tab again (M-10).
 */
const tabOfSession = new Map<string, string>();
/** Sink generation per tab: events from a channel replaced by `session_attach` are ignored. */
const sinkGen = new Map<string, number>();

function forgetTab(tabId: string): void {
  for (const [sid, tid] of tabOfSession) if (tid === tabId) tabOfSession.delete(sid);
}

function adoptedState(state: string): TabState | null {
  return state === "connected" || state === "connecting" ? state : null;
}

function protocolOf(connectionId: string): Protocol | null {
  return useTree.getState().connections.find((c) => c.id === connectionId)?.protocol ?? null;
}

function viewOnlyOf(connectionId: string): boolean {
  const c = useTree.getState().connections.find((x) => x.id === connectionId);
  return c?.protocol === "vnc" && (optionsOf(connectionId) as Partial<VncConnOptions> | undefined)?.viewOnly === true;
}

export function blankTab(id: string, connectionId: string, protocol: Protocol | null, p: Partial<Tab> = {}): Tab {
  return {
    id, connectionId, protocol, sessionId: null, state: "connecting", peerIdentity: null, security: null, prompt: null,
    reason: null, closeCode: null, reconnect: null, desktop: null, viewOnly: viewOnlyOf(connectionId), attachEpoch: 0, ...p,
  };
}

/** Return one frame credit (ADR-0011). Passive on the backend; failures are harmless. */
export function ackFrame(tabId: string, seq: number): void {
  const sid = useSessions.getState().tabs.find((t) => t.id === tabId)?.sessionId;
  if (sid) ackSession(sid, seq);
}

/** The same by session id: still valid while the tab is being torn down (lock). */
export function ackSession(sessionId: string, seq: number): void {
  ipc.sessionFrameAck({ sessionId, seq }).catch(() => undefined);
}

interface SessionState {
  tabs: Tab[];
  activeTab: string | null;
  error: string | null;

  open: (connectionId: string, opts?: { newTab?: boolean; size?: Size }) => Promise<string>;
  /** A new exec or logs tab under a cluster tab. */
  openKube: (connectionId: string, kube: KubeTab) => Promise<string>;
  activate: (tabId: string) => void;
  close: (tabId: string) => Promise<void>;
  move: (tabId: string, toIndex: number) => void;
  detach: (tabId: string) => Promise<boolean>;
  send: (tabId: string, data: Uint8Array) => Promise<void>;
  /** Any input (pointer, key, wheel, clipboard offer...). Errors are dropped: input races a close. */
  input: (tabId: string, input: SessionInput) => Promise<void>;
  resize: (tabId: string, size: Size) => Promise<void>;
  answer: (tabId: string, text: string) => Promise<boolean>;
  /** Answer a `credential` prompt. The caller drops its copy of the password once this settles. */
  answerCredential: (tabId: string, a: CredentialAnswer) => Promise<boolean>;
  reconnect: (tabId: string) => Promise<void>;
  setViewOnly: (tabId: string, viewOnly: boolean) => Promise<boolean>;
  /** Rust copies the framebuffer to the OS clipboard; returns its size, or null on failure. */
  screenshot: (tabId: string) => Promise<Size | null>;
  /** After an unlock: show the backend's live sessions (`session_list`) as tabs again. */
  adopt: (live: SessionInfo[]) => void;
  /** Drop every tab and buffered output (lock). Live backend sessions are re-adopted on unlock. */
  reset: () => void;
}

/** A `session_open` refusal that is a trust decision keeps its close code, so the banner can say why (6b: `trust_conflict` too). */
const OPEN_FAILURE_CODES: Readonly<Record<string, CloseCode>> = { "session.trust_mismatch": "trust_mismatch", "session.trust_rejected": "trust_rejected", "http.trust_conflict": "trust_conflict" };
function openFailureCode(e: unknown): CloseCode | null {
  return (isIpcError(e) && OPEN_FAILURE_CODES[e.code]) || null;
}

let tabSeq = 0;
/** A fresh local tab id. */
export function nextTabId(): string {
  tabSeq += 1;
  return `tab-${String(tabSeq)}`;
}
const enc = new TextEncoder();

export const useSessions = create<SessionState>((set, get) => {
  const patch = (tabId: string, p: Partial<Tab>) => {
    set({ tabs: get().tabs.map((t) => (t.id === tabId ? { ...t, ...p } : t)) });
  };
  const tabOf = (tabId: string) => get().tabs.find((t) => t.id === tabId);
  const nextGen = (tabId: string) => {
    const g = (sinkGen.get(tabId) ?? 0) + 1;
    sinkGen.set(tabId, g);
    return g;
  };

  const onEvent = (tabId: string, gen: number) => (ev: SessionEvent) => {
    if (sinkGen.get(tabId) !== gen) return;
    // While the vault is locked the tab is gone: nothing that arrives then is kept.
    if (!tabOf(tabId)) {
      if (ev.kind === "closed") forgetTab(tabId);
      return;
    }
    switch (ev.kind) {
      case "connected":
        patch(tabId, { state: "connected", peerIdentity: ev.peerIdentity, security: ev.security, prompt: null, reconnect: null });
        break;
      case "bytes":
        pushOutput(tabId, ev.data);
        break;
      case "prompt":
        patch(tabId, {
          prompt: { id: ev.id, message: ev.message, secret: ev.secret, purpose: ev.purpose, account: ev.account, certificate: ev.certificate },
        });
        break;
      case "desktop_resized":
        patch(tabId, { desktop: { width: ev.width, height: ev.height } });
        break;
      case "reconnecting":
        patch(tabId, { state: "reconnecting", reconnect: { attempt: ev.attempt, delayMs: ev.delayMs, since: Date.now() }, prompt: null });
        break;
      case "detached":
        if (tabOf(tabId)?.sessionId) detachedSessions.add(tabOf(tabId)?.sessionId ?? "");
        patch(tabId, { state: "detached", prompt: null });
        break;
      case "attached":
        void attachHere(tabId);
        break;
      case "closed":
        detachedSessions.delete(tabOf(tabId)?.sessionId ?? "");
        forgetTab(tabId);
        patch(tabId, { state: "closed", reason: ev.reason, closeCode: ev.code, prompt: null, sessionId: null, reconnect: null });
        if (!isGraphical(tabOf(tabId)?.protocol)) pushOutput(tabId, enc.encode(`\r\n\x1b[2m[session closed: ${ev.reason}]\x1b[0m\r\n`));
        break;
    }
  };

  /** MFR1 messages for a tab; while the tab is gone (locked) they are acked and dropped. */
  const onFrame = (tabId: string, gen: number) => (message: ArrayBuffer) => {
    if (sinkGen.get(tabId) !== gen) return;
    const ack = (seq: number) => { ackFrame(tabId, seq); };
    if (tabOf(tabId)) pushFrame(tabId, message, ack);
    else {
      const sid = [...tabOfSession].find(([, t]) => t === tabId)?.[0];
      const seq = peekSeq(message);
      if (sid && seq !== null) ackSession(sid, seq);
    }
  };

  /** Send an answer to the pending prompt; the prompt is dropped first so it cannot be sent twice. */
  const reply = async (tabId: string, build: (id: number) => SessionInput): Promise<boolean> => {
    const tab = tabOf(tabId);
    if (!tab?.sessionId || !tab.prompt) return false;
    const input = build(tab.prompt.id);
    patch(tabId, { prompt: null });
    try {
      await ipc.sessionSend({ sessionId: tab.sessionId, input });
      return true;
    } catch (e: unknown) {
      patch(tabId, { state: "closed", reason: errorText(e) });
      return false;
    }
  };

  /**
   * Take the session's sinks into this view with fresh channels (after `attached`, or after an
   * unlock for a canvas). Credits reset and Rust resends a full frame.
   */
  const attachHere = async (tabId: string) => {
    const t = tabOf(tabId);
    if (!t?.sessionId) return;
    const sid = t.sessionId;
    const gen = nextGen(tabId);
    const graphical = isGraphical(t.protocol);
    dropFrames(tabId);
    detachedSessions.delete(sid);
    try {
      const a = await ipc.sessionAttach({ sessionId: sid, onEvent: onEvent(tabId, gen), ...(graphical ? { onFrame: onFrame(tabId, gen) } : {}) });
      const now = tabOf(tabId);
      if (!now) return;
      const state = adoptedState(a.state) ?? (a.state === "reconnecting" ? "reconnecting" : now.state === "detached" ? "connected" : now.state);
      patch(tabId, { state, attachEpoch: now.attachEpoch + 1, ...(graphical ? { desktop: a.size } : {}) });
      if (!graphical && now.state === "detached") {
        pushOutput(tabId, enc.encode("\r\n\x1b[2m[back from its own window: output shown there is not repeated here]\x1b[0m\r\n"));
      }
    } catch {
      // the session ended meanwhile: its `closed` event updates the tab
    }
  };

  const start = async (tabId: string, connectionId: string, size: Size) => {
    const gen = nextGen(tabId);
    const graphical = isGraphical(tabOf(tabId)?.protocol);
    dropFrames(tabId);
    const k = tabOf(tabId)?.kube;
    try {
      const { sessionId } = await ipc.sessionOpen({
        connectionId,
        size,
        onEvent: onEvent(tabId, gen),
        ...(graphical ? { onFrame: onFrame(tabId, gen) } : {}),
        ...(k?.view === "exec" && k.exec ? { kube: k.exec } : {}),
      });
      if (tabOf(tabId)) {
        tabOfSession.set(sessionId, tabId);
        patch(tabId, { sessionId });
      } else {
        await ipc.sessionClose({ sessionId }); // tab closed while connecting
      }
    } catch (e: unknown) {
      patch(tabId, { state: "closed", reason: describeError(e), closeCode: openFailureCode(e) });
    }
  };

  const sendTo = async (tabId: string, input: SessionInput) => {
    const sid = tabOf(tabId)?.sessionId;
    if (sid) await ipc.sessionSend({ sessionId: sid, input });
  };

  const initialSize = (p: Protocol | null, size?: Size): Size => size ?? (isGraphical(p) ? DEFAULT_DESKTOP : { width: 80, height: 24 });
  /** Web windows, cluster handles and sessions open differently (ADR-0013, ADR-0014). */
  const begin = (tabId: string, connectionId: string, protocol: Protocol | null, size: Size) => {
    if (protocol === "web") return openWeb(tabId, connectionId);
    if (tabOf(tabId)?.kube?.view === "cluster") return openCluster(tabId, connectionId);
    return start(tabId, connectionId, size);
  };

  return {
    tabs: [],
    activeTab: null,
    error: null,

    open: async (connectionId, opts = {}) => {
      const existing = opts.newTab ? undefined : get().tabs.find((t) => t.connectionId === connectionId && (t.kube?.view ?? "cluster") === "cluster");
      if (existing) {
        set({ activeTab: existing.id });
        return existing.id;
      }
      const id = nextTabId();
      const protocol = protocolOf(connectionId);
      if (isGraphical(protocol)) await useConnOptions.getState().load(connectionId); // initial view-only
      const kube: Partial<Tab> = protocol === "kubernetes" ? { kube: { view: "cluster" } } : {};
      set({ tabs: [...get().tabs, blankTab(id, connectionId, protocol, kube)], activeTab: id });
      await begin(id, connectionId, protocol, initialSize(protocol, opts.size));
      return id;
    },

    openKube: async (connectionId, kube) => {
      const id = nextTabId();
      const p: Partial<Tab> = kube.view === "logs" ? { kube, state: "connected" } : { kube };
      set({ tabs: [...get().tabs, blankTab(id, connectionId, "kubernetes", p)], activeTab: id });
      if (kube.view === "exec") await start(id, connectionId, initialSize("kubernetes"));
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
      dropOutput(tabId);
      dropFrames(tabId);
      forgetTab(tabId);
      if (tab.protocol === "web") await closeWeb(tabId, tab.connectionId);
      else if (tab.sessionId) {
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
      const tab = tabOf(tabId);
      if (!tab?.sessionId || !canDetach(tab.protocol)) return false;
      try {
        await ipc.windowDetach({ sessionId: tab.sessionId });
      } catch (e: unknown) {
        set({ error: describeError(e) });
        return false;
      }
      // The tab stays: it turns into the placeholder when the new window's `session_attach`
      // makes Rust send `detached` here (not before), and comes back on `attached`.
      return true;
    },

    send: async (tabId, data) => {
      try {
        await sendTo(tabId, { kind: "bytes", data });
      } catch (e: unknown) {
        set({ error: errorText(e) });
      }
    },

    input: async (tabId, input) => {
      try {
        await sendTo(tabId, input);
      } catch {
        // pointer and key input racing a close or a reconnect is harmless
      }
    },

    resize: async (tabId, size) => {
      try {
        await sendTo(tabId, { kind: "resize", size });
      } catch {
        // a resize racing a close is harmless
      }
    },

    answer: (tabId, text) => reply(tabId, (id) => ({ kind: "answer", id, text })),

    answerCredential: (tabId, a) =>
      reply(tabId, (id) => ({ kind: "credential_answer", id, username: a.username, domain: a.domain, password: a.password })),

    reconnect: async (tabId) => {
      const tab = tabOf(tabId);
      if (!tab || tab.state !== "closed") return;
      patch(tabId, { state: "connecting", reason: null, closeCode: null, peerIdentity: null, security: null });
      await begin(tabId, tab.connectionId, tab.protocol, tab.desktop ?? initialSize(tab.protocol));
    },

    setViewOnly: async (tabId, viewOnly) => {
      const sid = tabOf(tabId)?.sessionId;
      if (!sid) return false;
      try {
        await ipc.sessionSetViewOnly({ sessionId: sid, viewOnly });
        patch(tabId, { viewOnly });
        return true;
      } catch (e: unknown) {
        set({ error: errorText(e) });
        return false;
      }
    },

    screenshot: async (tabId) => {
      const sid = tabOf(tabId)?.sessionId;
      if (!sid) return null;
      try {
        return await ipc.sessionScreenshot({ sessionId: sid });
      } catch (e: unknown) {
        set({ error: errorText(e) });
        return null;
      }
    },

    adopt: (live) => {
      const have = new Set(get().tabs.map((t) => t.sessionId));
      const adopted: Tab[] = [];
      for (const info of live) {
        const state = adoptedState(info.state);
        if (!state || have.has(info.sessionId)) continue;
        const known = tabOfSession.get(info.sessionId);
        const id = known ?? nextTabId();
        tabOfSession.set(info.sessionId, id);
        // A session shown in its own window stays there: this view keeps the placeholder.
        const away = detachedSessions.has(info.sessionId);
        const kube = adoptKube(info);
        adopted.push(blankTab(id, info.connectionId, info.protocol, { sessionId: info.sessionId, state: away ? "detached" : state, ...kube }));
        if (!isGraphical(info.protocol) && kube.kube?.view !== "cluster") {
          // Output from before the lock was wiped with it; say so instead of showing a blank screen.
          pushOutput(id, enc.encode(known
            ? "\x1b[2m[vault unlocked: earlier output was cleared when it locked]\x1b[0m\r\n"
            : "\x1b[2m[this window cannot show the output of this session]\x1b[0m\r\n"));
        }
      }
      if (adopted.length === 0) return;
      set({ tabs: [...get().tabs, ...adopted], activeTab: get().activeTab ?? adopted[0]?.id ?? null });
      // A canvas lost its pixels with the lock: re-attaching this view makes Rust resend a full frame.
      for (const t of adopted) if (isGraphical(t.protocol) && t.state !== "detached") void attachHere(t.id);
    },

    reset: () => {
      clearOutput();
      // Sessions outlive a lock: give back the credits of frames no canvas will draw now.
      for (const t of get().tabs) {
        for (const m of drainFrames(t.id)) {
          const seq = peekSeq(m);
          if (t.sessionId && seq !== null) ackSession(t.sessionId, seq);
        }
      }
      dropFrames();
      resetWeb();
      useKube.getState().reset();
      set({ tabs: [], activeTab: null, error: null });
    },
  };
});

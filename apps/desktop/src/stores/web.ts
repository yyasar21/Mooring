// Web session tabs (ADR-0013). The page lives in its own `web-<connectionId>` window with no IPC
// bridge; the tab in `main` is a control card fed by the `web_open` channel. Everything shown here
// that comes from the page (title) or from a refused navigation (origin) is untrusted text: it is
// sanitised again here, even though Rust already sanitises the title.
import { create } from "zustand";
import { ipc, isIpcError, type WebEvent, type WebWindowInfo } from "../lib/ipc";
import { WEB_ZOOM } from "../lib/ipc.types.remote";
import { blankTab, nextTabId, useSessions, type Tab } from "./sessions";
import { describeError } from "./errors";
import { useTree } from "./tree";

export type WebNoticeKind = "blocked" | "download_blocked";

export interface WebNotice {
  id: number;
  kind: WebNoticeKind;
  /** The refused origin (`scheme://host[:port]` or `scheme:`), never a path. */
  origin: string;
  at: number;
}

export interface WebTab {
  title: string;
  origin: string;
  /** Effective storage (`web_list`): false after the macOS 11–13 fallback. */
  persistent: boolean;
  /** The last factor this UI set; Rust does not report it (a reopened window starts at 1). */
  zoom: number;
  notices: WebNotice[];
  /** ADR-0025 §3: jump hosts the page goes through (SOCKS on the last hop); null = direct. */
  viaHops: number | null;
}

/** At most this many notices are kept per tab, newest first. */
export const MAX_NOTICES = 5;
const MAX_TITLE = 256;
const MAX_ORIGIN = 300;

/** Zoom steps, as in a browser. `web_zoom` accepts 0.25..=5. */
export const ZOOM_STEPS = [0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4, 5] as const;

// C0/C1 controls, bidi embeddings/overrides/isolates and marks, zero-width characters.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;

/** Page-controlled text for display: no controls or bidi tricks, whitespace collapsed, capped. */
export function sanitizeText(raw: string, max: number): string {
  const clean = raw.replace(/\s+/g, " ").replace(UNSAFE, "").replace(/\s+/g, " ").trim();
  const chars = Array.from(clean);
  return chars.length > max ? `${chars.slice(0, max - 1).join("")}…` : clean;
}

export const sanitizeTitle = (raw: string) => sanitizeText(raw, MAX_TITLE);
export const sanitizeOrigin = (raw: string) => sanitizeText(raw, MAX_ORIGIN);

/** The next zoom factor: one step in or out, or 1 to reset. */
export function nextZoom(current: number, dir: -1 | 0 | 1): number {
  if (dir === 0) return 1;
  const steps: readonly number[] = ZOOM_STEPS;
  const next = dir > 0 ? steps.find((z) => z > current + 1e-6) : [...steps].reverse().find((z) => z < current - 1e-6);
  return Math.min(WEB_ZOOM.max, Math.max(WEB_ZOOM.min, next ?? current));
}

interface WebState {
  byTab: Record<string, WebTab>;
  reset: () => void;
}

export const useWebTabs = create<WebState>((set) => ({
  byTab: {},
  reset: () => { set({ byTab: {} }); },
}));

const blank = (): WebTab => ({ title: "", origin: "", persistent: false, zoom: 1, notices: [], viaHops: null });
/** Channel generation per tab: events of a channel replaced by a newer `web_open` are ignored. */
const gens = new Map<string, number>();
let noticeSeq = 0;

function patchWeb(tabId: string, p: Partial<WebTab> | ((w: WebTab) => Partial<WebTab>)): void {
  const cur = useWebTabs.getState().byTab[tabId] ?? blank();
  const next = typeof p === "function" ? p(cur) : p;
  useWebTabs.setState({ byTab: { ...useWebTabs.getState().byTab, [tabId]: { ...cur, ...next } } });
}

function patchTab(tabId: string, p: Partial<Tab>): void {
  useSessions.setState({ tabs: useSessions.getState().tabs.map((t) => (t.id === tabId ? { ...t, ...p } : t)) });
}

const tabOf = (tabId: string) => useSessions.getState().tabs.find((t) => t.id === tabId);

function onWebEvent(tabId: string, gen: number) {
  return (ev: WebEvent) => {
    if (gens.get(tabId) !== gen || !tabOf(tabId)) return;
    switch (ev.kind) {
      case "title":
        patchWeb(tabId, { title: sanitizeTitle(ev.title) });
        break;
      case "navigated":
        patchWeb(tabId, { origin: sanitizeOrigin(ev.origin) });
        break;
      case "blocked":
      case "download_blocked": {
        noticeSeq += 1;
        const n: WebNotice = { id: noticeSeq, kind: ev.kind, origin: sanitizeOrigin(ev.origin), at: Date.now() };
        patchWeb(tabId, (w) => ({ notices: [n, ...w.notices].slice(0, MAX_NOTICES) }));
        break;
      }
      case "closed":
        gens.delete(tabId);
        patchTab(tabId, { state: "closed", reason: "The web window was closed.", closeCode: "user" });
        break;
    }
  };
}

function applyInfo(tabId: string, info: WebWindowInfo | undefined): void {
  if (!info) return;
  patchWeb(tabId, (w) => ({
    persistent: info.persistent,
    viaHops: info.viaHops ?? w.viaHops,
    origin: w.origin || sanitizeOrigin(info.origin),
    title: w.title || sanitizeTitle(info.title),
  }));
}

/** The jump hosts a connection's window will go through, from the tree (0 = direct). */
export function plannedHops(connectionId: string): number {
  return useTree.getState().connections.find((c) => c.id === connectionId)?.via?.length ?? 0;
}

/**
 * R6: a hop failure's Rust message is a fixed, safe sentence that names the hop and what it asked
 * (more useful than the generic plan-time text), so it is shown as is.
 */
function openFailure(e: unknown): string {
  return isIpcError(e) && e.code === "session.hop_failed" && e.message.trim() !== "" ? e.message : describeError(e);
}

/**
 * `web_open` for a tab (also after a lock, when it moves the events to a new channel). Through
 * jump hosts it takes up to 90 s (R6 chain deadline); the tab shows the planned hop count until
 * then. There is no cancel command: a tab closed meanwhile closes the window once it exists.
 */
export async function openWeb(tabId: string, connectionId: string): Promise<void> {
  const gen = (gens.get(tabId) ?? 0) + 1;
  gens.set(tabId, gen);
  if (!useWebTabs.getState().byTab[tabId]) patchWeb(tabId, blank());
  const planned = plannedHops(connectionId);
  patchWeb(tabId, { viaHops: planned > 0 ? planned : null });
  try {
    const opened = await ipc.webOpen({ connectionId, onEvent: onWebEvent(tabId, gen) });
    if (!tabOf(tabId)) {
      if (gens.get(tabId) === undefined) await ipc.webClose({ connectionId }).catch(() => undefined);
      return;
    }
    patchWeb(tabId, { viaHops: opened.viaHops ?? null });
    patchTab(tabId, { state: "connected", reason: null, closeCode: null, openError: null });
    // `web_list` is passive and carries the effective storage mode.
    const list = await ipc.webList().catch(() => [] as WebWindowInfo[]);
    applyInfo(tabId, list.find((w) => w.connectionId === connectionId));
  } catch (e: unknown) {
    gens.delete(tabId);
    patchTab(tabId, { state: "closed", reason: openFailure(e), closeCode: null, openError: isIpcError(e) ? e.code : null });
  }
}

/** Closing the tab closes the window; a window that is already gone is fine. */
export async function closeWeb(tabId: string, connectionId: string): Promise<void> {
  gens.delete(tabId);
  useWebTabs.setState({ byTab: Object.fromEntries(Object.entries(useWebTabs.getState().byTab).filter(([k]) => k !== tabId)) });
  try {
    await ipc.webClose({ connectionId });
  } catch {
    // session.not_found: the user closed the window natively
  }
}

export type WebAction = "focus" | "reload" | "print" | "close" | "clear_data";

/** Run one control; returns the error text to show, or null. */
export async function webAction(tabId: string, action: WebAction): Promise<string | null> {
  const tab = tabOf(tabId);
  if (!tab) return null;
  const a = { connectionId: tab.connectionId };
  try {
    if (action === "focus") await ipc.webFocus(a);
    else if (action === "reload") await ipc.webReload(a);
    else if (action === "print") await ipc.webPrint(a);
    else if (action === "close") await ipc.webClose(a);
    else await ipc.webClearData(a);
    return null;
  } catch (e: unknown) {
    if (isIpcError(e) && e.code === "session.not_found" && action !== "clear_data") {
      patchTab(tabId, { state: "closed", reason: "The web window was closed.", closeCode: "user" });
    }
    return describeError(e);
  }
}

export async function webZoomStep(tabId: string, dir: -1 | 0 | 1): Promise<string | null> {
  const tab = tabOf(tabId);
  if (!tab) return null;
  const before = useWebTabs.getState().byTab[tabId]?.zoom ?? 1;
  const factor = nextZoom(before, dir);
  patchWeb(tabId, { zoom: factor }); // set first, so quick repeated clicks step from here
  try {
    await ipc.webZoom({ connectionId: tab.connectionId, factor });
    return null;
  } catch (e: unknown) {
    patchWeb(tabId, (w) => (w.zoom === factor ? { zoom: before } : {}));
    return describeError(e);
  }
}

export function dismissNotice(tabId: string, id: number): void {
  patchWeb(tabId, (w) => ({ notices: w.notices.filter((n) => n.id !== id) }));
}

/** After an unlock: show the web windows that survived the lock as tabs again. */
export async function adoptWeb(): Promise<void> {
  let list: WebWindowInfo[];
  try {
    list = await ipc.webList();
  } catch {
    return;
  }
  const have = new Set(useSessions.getState().tabs.filter((t) => t.protocol === "web").map((t) => t.connectionId));
  for (const w of list) {
    if (have.has(w.connectionId)) continue;
    const id = nextTabId();
    const s = useSessions.getState();
    useSessions.setState({ tabs: [...s.tabs, blankTab(id, w.connectionId, "web")], activeTab: s.activeTab ?? id });
    patchWeb(id, { ...blank(), origin: sanitizeOrigin(w.origin), title: sanitizeTitle(w.title), persistent: w.persistent, viaHops: w.viaHops ?? null });
    await openWeb(id, w.connectionId);
  }
}

export function resetWeb(): void {
  gens.clear();
  useWebTabs.getState().reset();
}

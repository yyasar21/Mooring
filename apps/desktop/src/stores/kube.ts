// Kubernetes tabs (ADR-0014). A kube connection opens a *cluster* tab: `kube_open` returns a
// cluster session (no terminal) that the browser, log streams and pod forwards hang off. Exec
// shells are ordinary terminal tabs opened with `session_open({ kube })`; log viewers are tabs
// without a backend session whose stream lives as long as the view.
import { create } from "zustand";
import { ipc, type KubeExecTarget, type KubeIdentity, type SessionInfo } from "../lib/ipc";
import { useSessions, type Tab } from "./sessions";
import { describeError } from "./errors";

export interface KubeLogsTarget {
  parentSessionId: string;
  namespace: string;
  pod: string;
  container: string;
}

/** What a kubernetes tab shows. `exec: null` = an exec shell adopted after unlock (target unknown). */
export type KubeTab =
  | { view: "cluster" }
  | { view: "exec"; exec: KubeExecTarget | null }
  | { view: "logs"; logs: KubeLogsTarget };

export interface ClusterMeta {
  identity: KubeIdentity | null;
  server: string;
  contextNamespace: string | null;
}

interface KubeState {
  /** Cluster tab id → what `kube_open` said. Lost on lock (re-adopted tabs show "unknown"). */
  clusters: Record<string, ClusterMeta>;
  reset: () => void;
}

export const useKube = create<KubeState>((set) => ({
  clusters: {},
  reset: () => { set({ clusters: {} }); },
}));

function patchTab(tabId: string, p: Partial<Tab>): void {
  useSessions.setState({ tabs: useSessions.getState().tabs.map((t) => (t.id === tabId ? { ...t, ...p } : t)) });
}
const tabOf = (tabId: string) => useSessions.getState().tabs.find((t) => t.id === tabId);

/** `kube_open` for a cluster tab (first open and Reconnect). */
export async function openCluster(tabId: string, connectionId: string): Promise<void> {
  try {
    const r = await ipc.kubeOpen({ connectionId });
    if (!tabOf(tabId)) {
      await ipc.sessionClose({ sessionId: r.sessionId }).catch(() => undefined); // tab closed while opening
      return;
    }
    useKube.setState({ clusters: { ...useKube.getState().clusters, [tabId]: { identity: r.identity, server: r.server, contextNamespace: r.contextNamespace } } });
    patchTab(tabId, { sessionId: r.sessionId, state: "connected", reason: null });
  } catch (e: unknown) {
    patchTab(tabId, { state: "closed", reason: describeError(e) });
  }
}

/** Adopting a live kubernetes session after unlock: a cluster handle or an exec shell. */
export function adoptKube(info: SessionInfo): Partial<Tab> {
  if (info.protocol !== "kubernetes") return {};
  const parent = info.kube?.parentSessionId ?? null;
  return { kube: parent === null ? { view: "cluster" } : { view: "exec", exec: null } };
}

/** The cluster tab a kube tab belongs to (exec and logs tabs carry the parent session id). */
export function parentSessionOf(tab: Tab): string | null {
  if (!tab.kube) return null;
  if (tab.kube.view === "cluster") return tab.sessionId;
  if (tab.kube.view === "logs") return tab.kube.logs.parentSessionId;
  return tab.kube.exec?.parentSessionId ?? null;
}

/** Tab title suffix for exec and logs tabs (`pod · container`). */
export function kubeTabLabel(tab: Tab): string | null {
  if (tab.kube?.view === "logs") return `logs ${tab.kube.logs.pod}/${tab.kube.logs.container}`;
  if (tab.kube?.view === "exec") return tab.kube.exec ? `${tab.kube.exec.pod}/${tab.kube.exec.container}` : "exec";
  return null;
}

export function openExec(connectionId: string, exec: KubeExecTarget): Promise<string> {
  return useSessions.getState().openKube(connectionId, { view: "exec", exec });
}

export function openLogs(connectionId: string, logs: KubeLogsTarget): Promise<string> {
  return useSessions.getState().openKube(connectionId, { view: "logs", logs });
}

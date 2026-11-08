import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, isIpcError, type ConnectionSummary, type KubeAccess, type KubeConnOptions, type PodSummary } from "../../lib/ipc";
import { normalizeOptions } from "../../lib/validate.options";
import { optionsOf, useConnOptions } from "../../stores/connOptions";
import { describeError } from "../../stores/errors";

/**
 * Pods are re-listed this often while a namespace is open. K4 has no pod watch command
 * (`kube_watch` was never built), so the passive `kube_pods` poll is the only live update.
 */
export const KUBE_POLL_MS = 15_000;

export interface ClusterView {
  namespaces: string[];
  /** `list namespaces` was denied: the list is the context namespace plus `allowedNamespaces`. */
  namespacesFallback: boolean;
  namespacesTruncated: boolean;
  namespace: string | null;
  setNamespace: (ns: string) => void;
  access: KubeAccess | null;
  pods: PodSummary[];
  podsTruncated: boolean;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

/** The connection's KubeConnOptions with defaults filled in (cache, else the tree row); loads them once. */
export function useKubeOptions(connection: ConnectionSummary | undefined): KubeConnOptions {
  const cached = useConnOptions((s) => (connection ? s.byId[connection.id] : undefined));
  useEffect(() => {
    if (connection && !useConnOptions.getState().byId[connection.id]) void useConnOptions.getState().load(connection.id);
  }, [connection]);
  return normalizeOptions("kubernetes", cached ?? (connection ? optionsOf(connection.id) : undefined) ?? {}) as KubeConnOptions;
}

/**
 * Namespaces, RBAC pre-flight and pods of one cluster session. `kube_namespaces`, `kube_access`
 * and `kube_pods` are passive (POLLED_COMMANDS), so the auto-refresh never keeps the vault
 * unlocked.
 */
export function useCluster(sessionId: string | null, preferred: string | null, allowed: string[]): ClusterView {
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [fallback, setFallback] = useState(false);
  const [nsTruncated, setNsTruncated] = useState(false);
  const [namespace, setNamespace] = useState<string | null>(null);
  const [access, setAccess] = useState<KubeAccess | null>(null);
  const [pods, setPods] = useState<PodSummary[]>([]);
  const [podsTruncated, setPodsTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = useRef({ sessionId, namespace });
  current.current = { sessionId, namespace };
  const allowedKey = allowed.join(",");

  useEffect(() => {
    setNamespaces([]);
    setNamespace(null);
    if (!sessionId) return;
    let live = true;
    const pickFrom = (list: string[]) => {
      if (!live) return;
      setNamespaces(list);
      setNamespace((cur) => cur ?? (preferred && list.includes(preferred) ? preferred : (list[0] ?? null)));
    };
    ipc.kubeNamespaces({ sessionId }).then(
      (r) => { setFallback(false); setNsTruncated(r.truncated); pickFrom(r.items); },
      (e: unknown) => {
        if (!live) return;
        if (isIpcError(e) && e.code === "kube.rbac_denied") {
          setFallback(true);
          pickFrom([...new Set([...(preferred ? [preferred] : []), ...allowedKey.split(",").filter(Boolean)])]);
        } else setError(describeError(e));
      },
    );
    return () => { live = false; };
  }, [sessionId, preferred, allowedKey]);

  const listPods = useCallback(async () => {
    const { sessionId: sid, namespace: ns } = current.current;
    if (!sid || !ns) return;
    try {
      const r = await ipc.kubePods({ sessionId: sid, namespace: ns, labelSelector: null });
      if (current.current.sessionId !== sid || current.current.namespace !== ns) return;
      setPods([...r.items].sort((a, b) => a.name.localeCompare(b.name)));
      setPodsTruncated(r.truncated);
      setError(null);
    } catch (e: unknown) {
      if (current.current.namespace === ns) setError(describeError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setPods([]);
    setAccess(null);
    setError(null);
    if (!sessionId || !namespace) return;
    const run = { live: true };
    setLoading(true);
    void (async () => {
      try {
        const granted = await ipc.kubeAccess({ sessionId, namespace });
        if (!run.live) return;
        setAccess(granted);
        if (!granted.listPods) {
          setLoading(false);
          return;
        }
        await listPods();
      } catch (e: unknown) {
        if (run.live) {
          setError(describeError(e));
          setLoading(false);
        }
      }
    })();
    const timer = setInterval(() => void listPods(), KUBE_POLL_MS);
    return () => {
      run.live = false;
      clearInterval(timer);
    };
  }, [sessionId, namespace, listPods]);

  return {
    namespaces, namespacesFallback: fallback, namespacesTruncated: nsTruncated, namespace, setNamespace,
    access, pods, podsTruncated, loading, error, refresh: listPods,
  };
}

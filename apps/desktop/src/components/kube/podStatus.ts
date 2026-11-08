import type { KubeAccess, PodSummary } from "../../lib/ipc";

/** Status vocabulary (design review 2026-11, Q4); undefined is the neutral chip. */
export type Tone = "success" | "warning" | "danger" | undefined;

/**
 * The badge for a pod: phase plus readiness (Running but not ready is not "Running"). Healthy is
 * success; a pod that needs a look (restarting, not ready, unknown) is warning; failed is danger.
 */
export function podStatus(p: PodSummary): { label: string; tone: Tone } {
  const restarts = p.containers.reduce((n, c) => n + c.restarts, 0);
  const ready = p.containers.every((c) => c.ready);
  switch (p.phase) {
    case "Running":
      if (ready) return { label: "Running", tone: "success" };
      return restarts >= 3 ? { label: "Restarting", tone: "warning" } : { label: "Not ready", tone: "warning" };
    case "Failed":
      return { label: "Failed", tone: "danger" };
    case "Succeeded":
      return { label: "Completed", tone: undefined };
    case "Pending":
      return { label: "Pending", tone: undefined };
    default:
      return { label: "Unknown", tone: "warning" };
  }
}

export const readyCount = (p: PodSummary) => `${p.containers.filter((c) => c.ready).length}/${p.containers.length}`;
export const restartCount = (p: PodSummary) => p.containers.reduce((n, c) => n + c.restarts, 0);

/** Search over name, node, container names and images; every whitespace-separated term must match. */
export function matchesPod(p: PodSummary, query: string): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const hay = [p.name, p.node ?? "", p.phase, ...p.containers.flatMap((c) => [c.name, c.image])].join(" ").toLowerCase();
  return terms.every((t) => hay.includes(t));
}

/** "3m", "5h", "2d" since an RFC 3339 time; "" when unknown. */
export function age(createdAt: string, now = Date.now()): string {
  const t = Date.parse(createdAt);
  if (!Number.isFinite(t)) return "";
  const s = Math.max(0, Math.floor((now - t) / 1000));
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))}m`;
  if (s < 86_400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86_400)}d`;
}

export const ACCESS_ROWS: { key: keyof KubeAccess; label: string; verb: string }[] = [
  { key: "listNamespaces", label: "List namespaces", verb: "list namespaces (cluster-wide)" },
  { key: "listPods", label: "List pods", verb: "list pods" },
  { key: "getLogs", label: "Read logs", verb: "get pods/log" },
  { key: "exec", label: "Exec shells", verb: "create pods/exec" },
  { key: "portForward", label: "Port-forward", verb: "create pods/portforward" },
];

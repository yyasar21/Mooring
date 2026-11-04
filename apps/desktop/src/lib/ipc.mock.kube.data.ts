// Fake cluster contents for the Kubernetes mock: namespaces, pods, the RBAC matrix and log lines.
// Names only (no real cluster); images use the reserved `registry.example.test` host.
import type { KubeAccess, PodPhase, PodSummary } from "./ipc.types.kube";
import { T0 } from "./ipc.seed";

const pod = (name: string, phase: PodPhase, node: string | null, containers: [string, string, boolean, number, number[]][]): PodSummary => ({
  name,
  phase,
  node,
  createdAt: T0,
  containers: containers.map(([n, image, ready, restarts, ports]) => ({ name: n, image: `registry.example.test/${image}`, ready, restarts, ports })),
});

export function seedPods(): Record<string, PodSummary[]> {
  return {
    default: [pod("hello-6d4cf56db6-x8k2p", "Running", "node-a", [["hello", "hello:1.4.2", true, 0, [8080]]])],
    payments: [
      pod("api-7f9c8d6b5-2kqzt", "Running", "node-a", [["api", "payments-api:3.2.0", true, 0, [8080, 9090]], ["envoy", "envoy:1.33", true, 0, [15001]]]),
      pod("api-7f9c8d6b5-9wmrx", "Running", "node-b", [["api", "payments-api:3.2.0", true, 1, [8080, 9090]], ["envoy", "envoy:1.33", true, 0, [15001]]]),
      pod("worker-5b8f7c9d4-lq7vn", "Running", "node-c", [["worker", "payments-worker:3.2.0", false, 7, []]]),
      pod("migrate-29c41-4hx8s", "Succeeded", "node-b", [["migrate", "payments-migrate:3.2.0", false, 0, []]]),
      pod("ledger-0", "Pending", null, [["ledger", "ledger:2.0.1", false, 0, [5432]]]),
    ],
    monitoring: [
      pod("prometheus-0", "Running", "node-c", [["prometheus", "prometheus:3.4", true, 0, [9090]], ["config-reloader", "reloader:0.9", true, 0, []]]),
      pod("log-flood-8c7d6-zz1aa", "Running", "node-a", [["flood", "noisy:0.1", true, 2, []]]),
      pod("exporter-x9q2c", "Failed", "node-b", [["exporter", "node-exporter:1.9", false, 12, [9100]]]),
    ],
    "kube-system": [
      pod("coredns-7db6d8ff4d-6kq5h", "Running", "node-a", [["coredns", "coredns:1.12", true, 0, [53, 9153]]]),
      pod("kube-proxy-p7m2c", "Running", "node-b", [["kube-proxy", "kube-proxy:1.33", true, 0, []]]),
    ],
  };
}

const ALL: KubeAccess = { listPods: true, getLogs: true, exec: true, portForward: true, listNamespaces: true };

/** The demo token is over-privileged in its own namespaces and read-mostly elsewhere. */
export const ACCESS: Record<string, KubeAccess> = {
  default: ALL,
  payments: ALL,
  monitoring: { ...ALL, exec: false },
  "kube-system": { ...ALL, getLogs: false, exec: false, portForward: false },
};
export const DENY_ALL: KubeAccess = { listPods: false, getLogs: false, exec: false, portForward: false, listNamespaces: true };

const LEVELS = ["INFO", "INFO", "INFO", "DEBUG", "WARN", "INFO", "ERROR"] as const;
const MESSAGES = [
  "GET /healthz 200 0.4ms",
  "processed batch id=%n size=64",
  "cache hit ratio=0.97",
  "connection pool: 12 idle, 4 busy",
  "retrying upstream payments-ledger.example.test (attempt 2)",
  "POST /v1/charges 201 18ms",
  "upstream timeout after 5000ms",
];

/** Deterministic log line `n` of a container. */
export function logLine(container: string, n: number, timestamps: boolean): string {
  const at = new Date(Date.parse(T0) + n * 1500).toISOString();
  const level = LEVELS[n % LEVELS.length] ?? "INFO";
  const msg = (MESSAGES[n % MESSAGES.length] ?? "").replace("%n", String(1000 + n));
  return `${timestamps ? `${at} ` : ""}${level.padEnd(5)} [${container}] ${msg}\n`;
}

/** The `log-flood` demo pod writes long lines so the byte cap shows quickly. */
export const FLOOD_LINE = `${"x".repeat(900)}\n`;

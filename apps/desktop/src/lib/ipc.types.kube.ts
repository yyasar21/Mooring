// DTOs of the ADR-0014 IPC contract: read-only Kubernetes sessions (cluster handle, RBAC
// pre-flight, pod browsing, exec as a `Session`, log streams, pod port-forward).
// Same conventions as ADR-0008: command args camelCase, `IpcError` on failure, no secret outward.
// Shapes marked ASSUMED are not spelled out in the ADR; see docs/handoff/a3-ui-u1.md.
import type { Exposure, ForwardInfo, HostPort } from "./ipc.types.exit";
import type { SessionEvent } from "./ipc.types";

// ---------- connection options (KubeConnOptions, deny_unknown_fields) ----------

/** Owner decision 3 (ADR-0014): exec runs one of these, never a custom argv. */
export const KUBE_EXEC_COMMANDS = ["/bin/sh", "/bin/bash", "/bin/ash", "sh", "bash"] as const;
export type KubeExecCommand = (typeof KUBE_EXEC_COMMANDS)[number];

export interface KubeConnOptions {
  /** kubeconfig context; null = the kubeconfig's current-context. */
  context: string | null;
  /** `https://` API server. Required for `kube_token`, refused for `kubeconfig`. */
  server: string | null;
  /** Certificate PEM blocks only, ≤ 64 KiB. Required for `kube_token`, refused for `kubeconfig`. */
  caPem: string | null;
  tlsServerName: string | null;
  /** Default namespace; null = the context's namespace. */
  namespace: string | null;
  /** `limitBytes` of every log stream: default 8 MiB, max 64 MiB. */
  maxLogBytes: number;
  /** Offered when `list namespaces` is denied (RFC 1123 labels). */
  allowedNamespaces: string[];
  /** ASSUMED (not in the ADR struct): the default exec command of this connection. */
  execCommand: KubeExecCommand;
  /** ASSUMED: default `tailLines` of a new log view (1..=10 000). */
  logTailLines: number;
  /** ASSUMED: pod port-forward allowed from this connection. */
  portForward: boolean;
}

const MiB = 1024 * 1024;

/** Rust caps (ADR-0014 §3, §5); `minLogBytes`, `maxAllowedNamespaces` and `maxContext` are ASSUMED. */
export const KUBE_LIMITS = {
  minLogBytes: 64 * 1024,
  defaultLogBytes: 8 * MiB,
  maxLogBytes: 64 * MiB,
  maxTailLines: 10_000,
  defaultTailLines: 500,
  maxAllowedNamespaces: 64,
  maxName: 253,
  maxLabel: 63,
  maxContext: 253,
  logStreamsPerCluster: 8,
  listPages: 10,
  pageLimit: 500,
} as const;

export const DEFAULT_KUBE_OPTIONS: KubeConnOptions = {
  context: null,
  server: null,
  caPem: null,
  tlsServerName: null,
  namespace: null,
  maxLogBytes: KUBE_LIMITS.defaultLogBytes,
  allowedNamespaces: [],
  execCommand: "/bin/sh",
  logTailLines: KUBE_LIMITS.defaultTailLines,
  portForward: true,
};

// ---------- cluster session ----------

export interface KubeIdentity {
  user: string;
  groups: string[];
}

/** `kube_open` result (A3 K4): the cluster handle only; what it reached comes as `connected`. */
export interface KubeOpenResult {
  /** The cluster handle: a session (`protocol: kubernetes`, no terminal). */
  sessionId: string;
}

/**
 * `kube_open` channel (A3 K4, ADR-0025): `connected` carries what the cluster tab shows; jump-host
 * and certificate prompts, `hop_status` and `closed` have the session-event shapes and are
 * answered with `session_send` on the cluster session id.
 */
export type ClusterEvent =
  | { kind: "connected"; server: string; identity: KubeIdentity | null; contextNamespace: string | null }
  | Extract<SessionEvent, { kind: "prompt" | "hop_status" | "closed" }>;
export type ClusterEventHandler = (event: ClusterEvent) => void;

/** RBAC pre-flight (five SelfSubjectAccessReviews) for one namespace. */
export interface KubeAccess {
  listPods: boolean;
  getLogs: boolean;
  exec: boolean;
  portForward: boolean;
  listNamespaces: boolean;
}

export interface KubeList<T> {
  items: T[];
  /** More than 10 pages of 500: the list is cut. */
  truncated: boolean;
}

export type PodPhase = "Pending" | "Running" | "Succeeded" | "Failed" | "Unknown";
export const POD_PHASES: readonly PodPhase[] = ["Pending", "Running", "Succeeded", "Failed", "Unknown"];

export interface ContainerSummary {
  name: string;
  image: string;
  ready: boolean;
  restarts: number;
  ports: number[];
}

export interface PodSummary {
  name: string;
  phase: PodPhase;
  node: string | null;
  createdAt: string;
  containers: ContainerSummary[];
}

/** ASSUMED shape of `Channel<PodEvent>`; `resync` = events were dropped (> 50/s), re-list. */
export type PodEvent =
  | { type: "added" | "modified" | "deleted"; pod: PodSummary }
  | { type: "resync" };
export type PodEventHandler = (e: PodEvent) => void;

/** `Channel<LogChunk>`; `data` is decoded from base64 before it reaches the UI. */
export type LogChunk =
  | { kind: "data"; data: Uint8Array }
  | { kind: "end"; truncated: boolean; reason: string | null };
export type LogChunkHandler = (c: LogChunk) => void;

export interface KubeLogsArgs {
  sessionId: string;
  namespace: string;
  pod: string;
  container: string;
  follow: boolean;
  tailLines: number | null;
  sinceSeconds: number | null;
  timestamps: boolean;
  onChunk: LogChunkHandler;
}

/** `session_open({ ..., kube })`: the exec target. `argv` is one of KUBE_EXEC_COMMANDS. */
export interface KubeExecTarget {
  parentSessionId: string;
  namespace: string;
  pod: string;
  container: string;
  argv: string[];
}

// ---------- pod port-forward (ADR-0010 panel, kind "pod") ----------

export interface PodTarget {
  namespace: string;
  pod: string;
  port: number;
}

export interface PodForwardOpen {
  /** The cluster session. */
  sessionId: string;
  kind: "pod";
  bind: HostPort;
  target: PodTarget;
  exposure: Exposure;
}

export const isPodTarget = (t: ForwardInfo["target"]): t is PodTarget => t !== null && "pod" in t;

// ---------- commands ----------

export interface KubeIpc {
  kubeOpen(args: { connectionId: string; onEvent: ClusterEventHandler }): Promise<KubeOpenResult>;
  /** Passive (POLLED_COMMANDS). */
  kubeAccess(args: { sessionId: string; namespace: string }): Promise<KubeAccess>;
  /** Passive (POLLED_COMMANDS). */
  kubeNamespaces(args: { sessionId: string }): Promise<KubeList<string>>;
  /** Passive (POLLED_COMMANDS). */
  kubePods(args: { sessionId: string; namespace: string; labelSelector: string | null }): Promise<KubeList<PodSummary>>;
  kubeWatch(args: { sessionId: string; namespace: string; onEvent: PodEventHandler }): Promise<{ watchId: string }>;
  kubeUnwatch(args: { sessionId: string; watchId: string }): Promise<void>;
  kubeLogs(args: KubeLogsArgs): Promise<{ streamId: string }>;
  kubeLogsStop(args: { sessionId: string; streamId: string }): Promise<void>;
}

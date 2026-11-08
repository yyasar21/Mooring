// Defensive decoders for ADR-0014 payloads. Pod lists, watch events and log chunks carry
// cluster-controlled strings: they are decoded field by field, capped, and anything unknown
// becomes a safe default (a phase we do not know is "Unknown", never "Running").
import { POD_PHASES, type ClusterEvent, type ContainerSummary, type KubeAccess, type KubeList, type LogChunk, type PodEvent, type PodPhase, type PodSummary } from "./ipc.types.kube";
import { base64ToBytes, decodeSessionEvent } from "./ipc.decode.session";

type Wire = Record<string, unknown>;

const rec = (v: unknown): Wire => (typeof v === "object" && v !== null ? (v as Wire) : {});
/** Kubernetes names are ≤ 253 chars; images and node names get the same cap for display. */
const str = (v: unknown, max = 253): string => (typeof v === "string" ? v.slice(0, max) : "");
const nonNeg = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const pick = (w: Wire, camel: string, snake: string): unknown => (camel in w ? w[camel] : w[snake]);

function decodeContainer(raw: unknown): ContainerSummary {
  const w = rec(raw);
  const ports = Array.isArray(w.ports) ? w.ports.filter((p): p is number => Number.isInteger(p) && p >= 1 && p <= 65535) : [];
  return { name: str(w.name), image: str(w.image, 512), ready: w.ready === true, restarts: nonNeg(w.restarts), ports: ports.slice(0, 64) };
}

export function decodePod(raw: unknown): PodSummary {
  const w = rec(raw);
  const phase = POD_PHASES.find((p) => p === w.phase) ?? ("Unknown" satisfies PodPhase);
  const node = pick(w, "node", "node");
  return {
    name: str(w.name),
    phase,
    node: typeof node === "string" ? node.slice(0, 253) : null,
    createdAt: str(pick(w, "createdAt", "created_at"), 64),
    containers: Array.isArray(w.containers) ? w.containers.map(decodeContainer).filter((c) => c.name !== "") : [],
  };
}

export function decodePodList(raw: unknown): KubeList<PodSummary> {
  const w = rec(raw);
  const items = Array.isArray(w.items) ? w.items.map(decodePod).filter((p) => p.name !== "") : [];
  return { items, truncated: w.truncated === true };
}

export function decodeNamespaces(raw: unknown): KubeList<string> {
  const w = rec(raw);
  const items = Array.isArray(w.items) ? w.items.filter((x): x is string => typeof x === "string" && x !== "").map((x) => x.slice(0, 63)) : [];
  return { items, truncated: w.truncated === true };
}

/** Anything not literally `true` is a denial: the UI never shows more than the token may do. */
export function decodeAccess(raw: unknown): KubeAccess {
  const w = rec(raw);
  const b = (camel: string, snake: string) => pick(w, camel, snake) === true;
  return {
    listPods: b("listPods", "list_pods"),
    getLogs: b("getLogs", "get_logs"),
    exec: b("exec", "exec"),
    portForward: b("portForward", "port_forward"),
    listNamespaces: b("listNamespaces", "list_namespaces"),
  };
}

/** Unknown event types become a `resync` (re-list), never a silent drop. */
export function decodePodEvent(raw: unknown): PodEvent {
  const w = rec(raw);
  const t = typeof w.type === "string" ? w.type.toLowerCase() : "";
  if ((t === "added" || t === "modified" || t === "deleted") && typeof w.pod === "object" && w.pod !== null) {
    const pod = decodePod(w.pod);
    if (pod.name !== "") return { type: t, pod };
  }
  return { type: "resync" };
}

/** A chunk that is neither valid data nor an end ends the stream (shape drift is not data). */
export function decodeLogChunk(raw: unknown): LogChunk {
  const w = rec(raw);
  if (w.kind === "data" && typeof w.data === "string") {
    try {
      return { kind: "data", data: base64ToBytes(w.data) };
    } catch {
      return { kind: "end", truncated: false, reason: "unreadable log data" };
    }
  }
  if (w.kind === "end") return { kind: "end", truncated: w.truncated === true, reason: typeof w.reason === "string" ? w.reason.slice(0, 256) : null };
  return { kind: "end", truncated: false, reason: "unrecognised log message" };
}

/**
 * A `kube_open` channel message. `connected` is read field by field (cluster-controlled names are
 * capped); prompts, `hop_status` and `closed` reuse the session decoder (a malformed hop status
 * closes, as on SSH). Any other kind is ignored: the handle has no terminal to close over it.
 */
export function decodeClusterEvent(raw: unknown): ClusterEvent | null {
  const w = rec(raw);
  if (w.kind === "connected") {
    const id = rec(w.identity);
    const groups = Array.isArray(id.groups) ? id.groups.filter((g): g is string => typeof g === "string").map((g) => g.slice(0, 256)).slice(0, 64) : [];
    const identity = typeof id.user === "string" ? { user: id.user.slice(0, 256), groups } : null;
    const ns = pick(w, "contextNamespace", "context_namespace");
    return { kind: "connected", server: str(w.server, 512), identity, contextNamespace: typeof ns === "string" && ns !== "" ? ns.slice(0, 63) : null };
  }
  if (w.kind === "prompt" || w.kind === "hop_status" || w.kind === "closed") {
    const ev = decodeSessionEvent(raw);
    if (ev.kind === "prompt" || ev.kind === "hop_status" || ev.kind === "closed") return ev;
  }
  // eslint-disable-next-line no-console -- dev-only shape-drift warning, no data
  if (import.meta.env.DEV) console.warn("mooring: ignored an unknown cluster event", typeof w.kind === "string" ? w.kind.slice(0, 40) : typeof w.kind);
  return null;
}

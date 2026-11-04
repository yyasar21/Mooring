// Mock ADR-0014 Kubernetes sessions for `vite dev` and vitest: the cluster handle (`kube_open`),
// RBAC pre-flight, namespace/pod lists, watches, log streams with the byte cap, exec shells that
// reuse the line-editor shell, and pod port-forwards on the cluster session. Nothing here talks
// to a cluster; the read-only guard is Rust's, the mock only refuses what the ADR refuses.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type {
  ForwardInfo,
  KubeAccess,
  KubeConnOptions,
  KubeExecTarget,
  KubeIpc,
  LogChunkHandler,
  PodEvent,
  PodEventHandler,
  PodSummary,
  SessionEventHandler,
  SessionInfo,
  SessionInput,
} from "./ipc.types";
import { KUBE_EXEC_COMMANDS, KUBE_LIMITS, isPodTarget } from "./ipc.types.kube";
import { IpcError } from "./ipc.error";
import { MockOptionsBase } from "./ipc.mock.options";
import { ACCESS, DENY_ALL, FLOOD_LINE, logLine, seedPods } from "./ipc.mock.kube.data";
import { echo } from "./ipc.mock.shell";
import { normalizeOptions } from "./validate.options";
import { checkLogsArgs, isDnsLabel } from "./validate.kube";

const enc = new TextEncoder();
const dec = new TextDecoder();

interface MockWatch { namespace: string; emit: PodEventHandler }
interface MockLogStream { timer: ReturnType<typeof setTimeout> | null; emit: LogChunkHandler }

export interface MockCluster {
  info: SessionInfo;
  options: KubeConnOptions;
  watches: Map<string, MockWatch>;
  logs: Map<string, MockLogStream>;
}

export interface MockExec {
  info: SessionInfo;
  target: KubeExecTarget;
  emit: SessionEventHandler;
  line: string;
}

export abstract class MockKubeBase extends MockOptionsBase implements KubeIpc {
  clusters = new Map<string, MockCluster>();
  execs = new Map<string, MockExec>();
  pods: Record<string, PodSummary[]> = seedPods();
  /** Follow streams emit a line this often; tests set 0 and drive time with timers. */
  logFollowMs = 1000;
  /** Set to make `kube_namespaces` refuse (a token without cluster-wide list). */
  denyNamespaceList = false;
  private kubeIds = 0;

  private kubeId(prefix: string): string {
    this.kubeIds += 1;
    return `${prefix}-${this.kubeIds.toString(16).padStart(4, "0")}`;
  }

  protected cluster(sessionId: string): MockCluster {
    const c = this.clusters.get(sessionId);
    if (!c && this.execs.has(sessionId)) throw new IpcError("input.invalid", "invalid sessionId: not a cluster session");
    if (!c) throw new IpcError("session.not_found", "session not found");
    return c;
  }

  access(namespace: string): KubeAccess {
    return { ...(ACCESS[namespace] ?? DENY_ALL), listNamespaces: !this.denyNamespaceList };
  }

  private podsIn(namespace: string): PodSummary[] {
    if (!isDnsLabel(namespace)) throw new IpcError("input.invalid", "invalid namespace");
    const list = this.pods[namespace];
    if (!list) throw new IpcError("kube.not_found", "namespace not found");
    return list;
  }

  private findPod(namespace: string, name: string): PodSummary {
    const p = this.podsIn(namespace).find((x) => x.name === name);
    if (!p) throw new IpcError("kube.not_found", "pod not found");
    return p;
  }

  private allow(namespace: string, what: keyof KubeAccess, verb: string): void {
    if (!this.access(namespace)[what]) throw new IpcError("kube.rbac_denied", `the token may not ${verb} in this namespace`);
  }

  kubeOpen: KubeIpc["kubeOpen"] = async ({ connectionId }) => {
    await this.unlocked();
    const t = this.target(connectionId);
    if (t.protocol !== "kubernetes") throw new IpcError("input.invalid", "invalid connectionId: not a Kubernetes connection");
    const options = normalizeOptions("kubernetes", t.options ?? {}) as KubeConnOptions;
    const sessionId = this.kubeId("k");
    const info: SessionInfo = { sessionId, connectionId, protocol: "kubernetes", state: "connected", openedAt: new Date().toISOString(), kube: { parentSessionId: null } };
    this.clusters.set(sessionId, { info, options, watches: new Map(), logs: new Map() });
    const server = options.server ?? t.host;
    this.record("kube.connected", { connection: connectionId, server, identity: "ops@example.test" });
    return { sessionId, identity: { user: "ops@example.test", groups: ["system:authenticated", "platform-ops"] }, server, contextNamespace: options.namespace ?? "payments" };
  };

  kubeAccess: KubeIpc["kubeAccess"] = async ({ sessionId, namespace }) => {
    this.cluster(sessionId);
    if (!isDnsLabel(namespace)) throw new IpcError("input.invalid", "invalid namespace");
    return this.access(namespace);
  };

  kubeNamespaces: KubeIpc["kubeNamespaces"] = async ({ sessionId }) => {
    this.cluster(sessionId);
    if (this.denyNamespaceList) throw new IpcError("kube.rbac_denied", "the token may not list namespaces");
    return { items: Object.keys(this.pods).sort(), truncated: false };
  };

  kubePods: KubeIpc["kubePods"] = async ({ sessionId, namespace, labelSelector }) => {
    this.cluster(sessionId);
    const list = this.podsIn(namespace);
    this.allow(namespace, "listPods", "list pods");
    const sel = labelSelector?.trim() ?? "";
    // Mock selector: `app=<prefix>` matches pod names starting with the prefix.
    const prefix = /^app=([a-z0-9-]+)$/.exec(sel)?.[1];
    if (sel !== "" && !prefix) throw new IpcError("input.invalid", "invalid labelSelector");
    return { items: structuredClone(prefix ? list.filter((p) => p.name.startsWith(prefix)) : list), truncated: false };
  };

  kubeWatch: KubeIpc["kubeWatch"] = async ({ sessionId, namespace, onEvent }) => {
    const c = this.cluster(sessionId);
    this.podsIn(namespace);
    this.allow(namespace, "listPods", "watch pods");
    const watchId = this.kubeId("w");
    c.watches.set(watchId, { namespace, emit: onEvent });
    return { watchId };
  };

  kubeUnwatch: KubeIpc["kubeUnwatch"] = async ({ sessionId, watchId }) => {
    const c = this.cluster(sessionId);
    if (!c.watches.delete(watchId)) throw new IpcError("kube.not_found", "watch not found");
  };

  /** Test/dev hook: a pod changed; the store is updated and every watch on that namespace hears it. */
  kubeEmit(namespace: string, ev: PodEvent): void {
    if (ev.type !== "resync") {
      const list = (this.pods[namespace] ??= []);
      const i = list.findIndex((p) => p.name === ev.pod.name);
      if (ev.type === "deleted") { if (i >= 0) list.splice(i, 1); } else if (i >= 0) list[i] = ev.pod; else list.push(ev.pod);
    }
    for (const c of this.clusters.values()) for (const w of c.watches.values()) if (w.namespace === namespace) w.emit(structuredClone(ev));
  }

  kubeLogs: KubeIpc["kubeLogs"] = async ({ sessionId, namespace, pod, container, follow, tailLines, sinceSeconds, timestamps, onChunk }) => {
    const c = this.cluster(sessionId);
    const bad = checkLogsArgs({ namespace, pod, container, tailLines, sinceSeconds });
    if (bad) throw new IpcError("input.invalid", bad);
    const p = this.findPod(namespace, pod);
    if (!p.containers.some((x) => x.name === container)) throw new IpcError("kube.not_found", "container not found");
    this.allow(namespace, "getLogs", "read logs");
    if (c.logs.size >= KUBE_LIMITS.logStreamsPerCluster) throw new IpcError("kube.stream_limit", "at most 8 log streams per cluster");
    const streamId = this.kubeId("l");
    const s: MockLogStream = { timer: null, emit: onChunk };
    c.logs.set(streamId, s);
    this.record("kube.logs.open", { connection: c.info.connectionId, namespace, pod, container, follow: String(follow) });
    const flood = pod.startsWith("log-flood");
    const cap = c.options.maxLogBytes;
    let sent = 0;
    let n = 0;
    const end = (truncated: boolean, reason: string | null) => {
      c.logs.delete(streamId);
      onChunk({ kind: "end", truncated, reason });
    };
    /** Sends text up to the cap; false once the cap is reached (and the stream ended). */
    const send = (text: string): boolean => {
      const bytes = enc.encode(text);
      const room = cap - sent;
      const part = bytes.length > room ? bytes.slice(0, room) : bytes;
      sent += part.length;
      if (part.length > 0) onChunk({ kind: "data", data: part });
      if (sent >= cap) { end(true, null); return false; }
      return true;
    };
    const total = Math.min(tailLines ?? 200, flood ? 10_000 : 400);
    const step = () => {
      if (!c.logs.has(streamId)) return;
      n += 1;
      if (send(flood ? FLOOD_LINE.repeat(64) : logLine(container, total + n, timestamps)) && c.logs.has(streamId)) s.timer = setTimeout(step, this.logFollowMs);
    };
    this.later(() => {
      if (!c.logs.has(streamId)) return;
      let head = "";
      for (let i = 0; i < total; i++) head += flood ? FLOOD_LINE : logLine(container, i, timestamps);
      if (!send(head)) return;
      if (follow) s.timer = setTimeout(step, this.logFollowMs);
      else end(false, null);
    });
    return { streamId };
  };

  kubeLogsStop: KubeIpc["kubeLogsStop"] = async ({ sessionId, streamId }) => {
    const c = this.cluster(sessionId);
    const s = c.logs.get(streamId);
    if (!s) throw new IpcError("kube.not_found", "log stream not found");
    if (s.timer) clearTimeout(s.timer);
    c.logs.delete(streamId);
  };

  // ---------- exec (a Session, called from session_open) ----------

  protected openKubeExec(connectionId: string, onEvent: SessionEventHandler, kube: KubeExecTarget | undefined): { sessionId: string } {
    if (!kube) throw new IpcError("input.invalid", "invalid kube: Kubernetes sessions open with kube_open or an exec target");
    const c = this.cluster(kube.parentSessionId);
    if (c.info.connectionId !== connectionId) throw new IpcError("input.invalid", "invalid kube: the cluster session belongs to another connection");
    const [argv0, ...rest] = kube.argv;
    if (rest.length > 0 || !KUBE_EXEC_COMMANDS.includes(argv0 as (typeof KUBE_EXEC_COMMANDS)[number])) {
      throw new IpcError("input.invalid", "invalid argv: choose one of the allowed shells");
    }
    const p = this.findPod(kube.namespace, kube.pod);
    if (!p.containers.some((x) => x.name === kube.container)) throw new IpcError("kube.not_found", "container not found");
    this.allow(kube.namespace, "exec", "exec into pods");
    const sessionId = this.kubeId("x");
    const info: SessionInfo = { sessionId, connectionId, protocol: "kubernetes", state: "connecting", openedAt: new Date().toISOString(), kube: { parentSessionId: kube.parentSessionId } };
    const x: MockExec = { info, target: structuredClone(kube), emit: onEvent, line: "" };
    this.execs.set(sessionId, x);
    this.record("kube.exec.open", { connection: connectionId, namespace: kube.namespace, pod: kube.pod, container: kube.container, argv0: argv0 ?? "" });
    this.later(() => {
      if (!this.execs.has(sessionId)) return;
      info.state = "connected";
      onEvent({ kind: "connected", protocol: "kubernetes", peerIdentity: `${kube.namespace}/${kube.pod}/${kube.container}`, security: null });
      onEvent({ kind: "bytes", data: enc.encode(`Mock ${argv0 ?? "sh"} in ${kube.pod} (${kube.container}). Input is echoed.\r\n# `) });
    });
    return { sessionId };
  }

  protected kubeHandles(sessionId: string): boolean {
    return this.clusters.has(sessionId) || this.execs.has(sessionId);
  }

  protected kubeSend(sessionId: string, input: SessionInput): void {
    const x = this.execs.get(sessionId);
    if (!x) throw new IpcError("input.invalid", "invalid sessionId: a cluster session has no terminal");
    if (input.kind !== "bytes") return;
    const { out, exit } = echo(x, dec.decode(input.data));
    if (exit) this.later(() => { this.endExec(x, "command terminated with exit code 0", "server_ended"); });
    else if (out) this.later(() => { x.emit({ kind: "bytes", data: enc.encode(out.replace(/\$ $/, "# ")) }); });
  }

  private endExec(x: MockExec, reason: string, code: "user" | "server_ended"): void {
    if (!this.execs.delete(x.info.sessionId)) return;
    this.record("kube.exec.close", { connection: x.info.connectionId, namespace: x.target.namespace, pod: x.target.pod, container: x.target.container });
    x.emit({ kind: "closed", reason, code });
  }

  /** `session_close`: a cluster session takes its exec tabs, watches, log streams and forwards with it. */
  protected kubeClose(sessionId: string): void {
    const x = this.execs.get(sessionId);
    if (x) { this.endExec(x, "closed by user", "user"); return; }
    const c = this.cluster(sessionId);
    for (const e of [...this.execs.values()]) if (e.target.parentSessionId === sessionId) this.endExec(e, "the cluster session closed", "user");
    for (const s of c.logs.values()) { if (s.timer) clearTimeout(s.timer); s.emit({ kind: "end", truncated: false, reason: "the cluster session closed" }); }
    c.watches.clear();
    this.dropSession(sessionId);
    this.clusters.delete(sessionId);
    this.record("session_closed", { connection: c.info.connectionId, reason: "closed by user" });
  }

  protected kubeInfos(): SessionInfo[] {
    return [...this.clusters.values(), ...this.execs.values()].map((x) => structuredClone(x.info));
  }

  /** Pod forwards run on the cluster session only, against a pod that exists. */
  protected override forwardCheck(sessionId: string, f: Pick<ForwardInfo, "kind" | "target"> | null): void {
    if (this.execs.has(sessionId)) throw new IpcError("input.invalid", "invalid sessionId: forwards run on the cluster session");
    const c = this.clusters.get(sessionId);
    if (!c) { super.forwardCheck(sessionId, f); return; }
    if (!f) return;
    if (f.kind !== "pod") throw new IpcError("input.invalid", "invalid kind: a Kubernetes session takes pod forwards only");
    if (!c.options.portForward) throw new IpcError("input.invalid", "invalid kind: port-forward is off for this connection");
    if (isPodTarget(f.target) && isDnsLabel(f.target.namespace)) {
      this.findPod(f.target.namespace, f.target.pod);
      this.allow(f.target.namespace, "portForward", "port-forward");
    }
  }
}

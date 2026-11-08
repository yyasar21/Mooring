// Mock ADR-0014 Kubernetes sessions for `vite dev` and vitest: the cluster handle (`kube_open`),
// RBAC pre-flight, namespace/pod lists, watches, log streams with the byte cap, exec shells that
// reuse the line-editor shell, and pod port-forwards on the cluster session. Nothing here talks
// to a cluster; the read-only guard is Rust's, the mock only refuses what the ADR refuses.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type {
  ClusterEventHandler,
  ForwardInfo,
  KubeAccess,
  KubeConnOptions,
  KubeIpc,
  LogChunkHandler,
  PodSummary,
  SessionEventHandler,
  SessionInfo,
  SessionInput,
} from "./ipc.types";
import { KUBE_EXEC_COMMANDS, KUBE_LIMITS, isPodTarget, type KubeExecTarget } from "./ipc.types.kube";
import { IpcError } from "./ipc.error";
import { MockOptionsBase } from "./ipc.mock.options";
import { ACCESS, DENY_ALL, FLOOD_LINE, logLine, seedPods } from "./ipc.mock.kube.data";
import { echo } from "./ipc.mock.shell";
import { normalizeOptions } from "./validate.options";
import { checkLogsArgs, isDnsLabel } from "./validate.kube";
import type { MockHopChain } from "./ipc.mock.hops";

const enc = new TextEncoder();
const dec = new TextDecoder();

interface MockLogStream { timer: ReturnType<typeof setTimeout> | null; emit: LogChunkHandler }

export interface MockCluster {
  info: SessionInfo;
  options: KubeConnOptions;
  /** The `kube_open` channel: `connected`, hop prompts / `hop_status`, `closed`. */
  emit: ClusterEventHandler;
  /** ADR-0025: the jump hosts in front of the API server (null = direct). */
  chain: MockHopChain | null;
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

  kubeOpen: KubeIpc["kubeOpen"] = async ({ connectionId, onEvent }) => {
    await this.unlocked();
    const t = this.target(connectionId);
    if (t.protocol !== "kubernetes") throw new IpcError("input.invalid", "invalid connectionId: not a Kubernetes connection");
    const options = normalizeOptions("kubernetes", t.options ?? {}) as KubeConnOptions;
    const sessionId = this.kubeId("k");
    const info: SessionInfo = { sessionId, connectionId, protocol: "kubernetes", state: "connecting", openedAt: new Date().toISOString(), kind: "cluster" };
    const c: MockCluster = { info, options, emit: onEvent, chain: null, logs: new Map() };
    this.clusters.set(sessionId, c);
    const server = options.server ?? t.host;
    // K4: the handle comes back at once; `connected` follows once the API server answered.
    const reach = () => {
      if (!this.clusters.has(sessionId)) return;
      info.state = "connected";
      this.record("kube.connected", { connection: connectionId, server, identity: "ops@example.test" });
      onEvent({ kind: "connected", server, identity: { user: "ops@example.test", groups: ["system:authenticated", "platform-ops"] }, contextNamespace: options.namespace ?? "payments" });
    };
    // ADR-0025 / R1: with `via`, the API server is dialled through the chain; hop prompts go on this channel.
    const hopSink: SessionEventHandler = (ev) => { if (ev.kind === "prompt" || ev.kind === "hop_status" || ev.kind === "closed") onEvent(ev); };
    c.chain = this.hopChainOf(connectionId, hopSink, reach, (reason) => {
      if (this.clusters.has(sessionId)) this.kubeClose(sessionId, reason, "hop_failed");
    });
    const chain = c.chain;
    this.later(() => { if (chain) chain.start(); else reach(); });
    return { sessionId };
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

  /**
   * Test/dev hook: a pod changed in the "cluster". K4 has no watch command, so nothing is pushed:
   * the browser sees it on its next `kube_pods` poll.
   */
  kubeSetPod(namespace: string, pod: PodSummary, deleted = false): void {
    const list = (this.pods[namespace] ??= []);
    const i = list.findIndex((p) => p.name === pod.name);
    if (deleted) { if (i >= 0) list.splice(i, 1); } else if (i >= 0) list[i] = pod; else list.push(pod);
  }

  kubeLogsOpen: KubeIpc["kubeLogsOpen"] = async ({ sessionId, namespace, pod, container, follow, tailLines, sinceSeconds, timestamps, onChunk }) => {
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

  kubeLogsClose: KubeIpc["kubeLogsClose"] = async ({ sessionId, streamId }) => {
    const c = this.cluster(sessionId);
    const s = c.logs.get(streamId);
    if (!s) throw new IpcError("kube.not_found", "log stream not found");
    if (s.timer) clearTimeout(s.timer);
    c.logs.delete(streamId);
  };

  // ---------- exec (K4 `kube_exec_open`: a terminal session on the cluster handle) ----------

  kubeExecOpen: KubeIpc["kubeExecOpen"] = async ({ sessionId: parent, namespace, pod, container, command, size, onEvent }) => {
    await this.unlocked();
    const c = this.cluster(parent);
    if (c.info.state !== "connected") throw new IpcError("session.not_connected", "the cluster session is not connected yet");
    if (!Number.isInteger(size.width) || !Number.isInteger(size.height) || size.width < 1 || size.height < 1) throw new IpcError("input.invalid", "invalid size");
    if (command !== null && !KUBE_EXEC_COMMANDS.includes(command)) throw new IpcError("input.invalid", "invalid command: must be one of /bin/sh, /bin/bash, /bin/ash, sh, bash");
    const shell = command ?? c.options.execCommand;
    const p = this.findPod(namespace, pod);
    const box = container ?? p.containers[0]?.name ?? "";
    if (!p.containers.some((x) => x.name === box)) throw new IpcError("kube.not_found", "container not found");
    this.allow(namespace, "exec", "exec into pods");
    const connectionId = c.info.connectionId;
    const sessionId = this.kubeId("x");
    const info: SessionInfo = { sessionId, connectionId, protocol: "kubernetes", state: "connecting", openedAt: new Date().toISOString(), kind: "exec", parentSessionId: parent };
    const x: MockExec = { info, target: { parentSessionId: parent, namespace, pod, container: box, command: shell }, emit: onEvent, line: "" };
    this.execs.set(sessionId, x);
    this.record("kube.exec.open", { connection: connectionId, namespace, pod, container: box, argv0: shell });
    this.later(() => {
      if (!this.execs.has(sessionId)) return;
      info.state = "connected";
      onEvent({ kind: "connected", protocol: "kubernetes", peerIdentity: `${namespace}/${pod}/${box}`, security: null });
      onEvent({ kind: "bytes", data: enc.encode(`Mock ${shell} in ${pod} (${box}). Input is echoed.\r\n# `) });
    });
    return { sessionId };
  };

  protected kubeHandles(sessionId: string): boolean {
    return this.clusters.has(sessionId) || this.execs.has(sessionId);
  }

  protected kubeSend(sessionId: string, input: SessionInput): void {
    const c = this.clusters.get(sessionId);
    if (c?.chain?.active && c.chain.answer(input)) return; // a jump host's question
    const x = this.execs.get(sessionId);
    if (!x && (input.kind === "answer" || input.kind === "credential_answer")) throw new IpcError("input.invalid", "no such prompt");
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
  protected kubeClose(sessionId: string, reason = "closed by user", code: "user" | "hop_failed" = "user"): void {
    const x = this.execs.get(sessionId);
    if (x) { this.endExec(x, reason, "user"); return; }
    const c = this.cluster(sessionId);
    for (const e of [...this.execs.values()]) if (e.target.parentSessionId === sessionId) this.endExec(e, "the cluster session closed", "user");
    for (const s of c.logs.values()) { if (s.timer) clearTimeout(s.timer); s.emit({ kind: "end", truncated: false, reason: "the cluster session closed" }); }
    this.dropSession(sessionId);
    this.clusters.delete(sessionId);
    this.record("session_closed", { connection: c.info.connectionId, reason });
    c.emit({ kind: "closed", reason, code });
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

// ADR-0014 mock contract and decoders: the cluster handle, RBAC, lists, watches, log streams with
// the byte cap, exec from the allow-list only, pod forwards on the cluster session, close cascade.
import { IpcError, type LogChunk, type PodEvent, type SessionEvent } from "./ipc";
import { MockTransport } from "./ipc.mock";
import { decodeAccess, decodeLogChunk, decodePodEvent, decodePodList } from "./ipc.decode.kube";
import { decodeForward } from "./ipc.decode.exit";
import { bytesToBase64 } from "./ipc.decode.session";
import { until } from "../test/ssh";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not an IpcError";
  }
};

async function cluster(m = new MockTransport()) {
  m.logFollowMs = 0;
  const r = await m.kubeOpen({ connectionId: "c-k8s" });
  return { m, sid: r.sessionId, r };
}

describe("mock · kube_open / access / lists", () => {
  it("opens a cluster session with identity and audits it", async () => {
    const { m, r } = await cluster();
    expect(r.identity.user).toBe("ops@example.test");
    expect(r.server).toBe("https://k8s.stage.example.test:6443");
    expect(m.audit.at(-1)?.event).toBe("kube.connected");
    expect((await m.sessionList()).find((s) => s.sessionId === r.sessionId)).toMatchObject({ protocol: "kubernetes", kube: { parentSessionId: null } });
    expect(await code(m.kubeOpen({ connectionId: "c-web01" }))).toBe("input.invalid");
  });

  it("refuses while the vault is locked", async () => {
    const m = new MockTransport({ vault: "locked" });
    expect(await code(m.kubeOpen({ connectionId: "c-k8s" }))).toBe("vault.locked");
  });

  it("answers the RBAC pre-flight per namespace and enforces it", async () => {
    const { m, sid } = await cluster();
    expect(await m.kubeAccess({ sessionId: sid, namespace: "payments" })).toEqual({ listPods: true, getLogs: true, exec: true, portForward: true, listNamespaces: true });
    expect(await m.kubeAccess({ sessionId: sid, namespace: "kube-system" })).toMatchObject({ exec: false, getLogs: false, portForward: false });
    expect(await code(m.kubeAccess({ sessionId: sid, namespace: "Bad_NS" }))).toBe("input.invalid");
    expect(await code(m.kubeLogs({ sessionId: sid, namespace: "kube-system", pod: "kube-proxy-p7m2c", container: "kube-proxy", follow: false, tailLines: 10, sinceSeconds: null, timestamps: false, onChunk: () => undefined }))).toBe("kube.rbac_denied");
  });

  it("lists namespaces and pods, refuses unknown ones, and a denied namespace list", async () => {
    const { m, sid } = await cluster();
    expect((await m.kubeNamespaces({ sessionId: sid })).items).toEqual(["default", "kube-system", "monitoring", "payments"]);
    const pods = await m.kubePods({ sessionId: sid, namespace: "payments", labelSelector: null });
    expect(pods.items.map((p) => p.name)).toContain("api-7f9c8d6b5-2kqzt");
    expect((await m.kubePods({ sessionId: sid, namespace: "payments", labelSelector: "app=worker" })).items).toHaveLength(1);
    expect(await code(m.kubePods({ sessionId: sid, namespace: "nope", labelSelector: null }))).toBe("kube.not_found");
    expect(await code(m.kubePods({ sessionId: sid, namespace: "payments", labelSelector: "app in (x)" }))).toBe("input.invalid");
    m.denyNamespaceList = true;
    expect(await code(m.kubeNamespaces({ sessionId: sid }))).toBe("kube.rbac_denied");
    expect(await code(m.kubeNamespaces({ sessionId: "k-none" }))).toBe("session.not_found");
  });

  it("delivers watch events to the namespace's watches until unwatched", async () => {
    const { m, sid } = await cluster();
    const seen: PodEvent[] = [];
    const { watchId } = await m.kubeWatch({ sessionId: sid, namespace: "payments", onEvent: (e) => seen.push(e) });
    const pod = (await m.kubePods({ sessionId: sid, namespace: "payments", labelSelector: null })).items[0];
    if (!pod) throw new Error("seed");
    m.kubeEmit("payments", { type: "modified", pod: { ...pod, phase: "Failed" } });
    m.kubeEmit("monitoring", { type: "resync" });
    expect(seen).toHaveLength(1);
    await m.kubeUnwatch({ sessionId: sid, watchId });
    m.kubeEmit("payments", { type: "resync" });
    expect(seen).toHaveLength(1);
    expect(await code(m.kubeUnwatch({ sessionId: sid, watchId }))).toBe("kube.not_found");
  });
});

describe("mock · kube_logs", () => {
  const args = (sid: string, p: Partial<Parameters<MockTransport["kubeLogs"]>[0]> = {}) => ({
    sessionId: sid, namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", container: "api", follow: false,
    tailLines: 5, sinceSeconds: null, timestamps: true, onChunk: () => undefined, ...p,
  });

  it("sends the tail then ends; follow keeps sending until stopped", async () => {
    const { m, sid } = await cluster();
    const chunks: LogChunk[] = [];
    await m.kubeLogs(args(sid, { onChunk: (c) => chunks.push(c) }));
    await until(() => chunks.some((c) => c.kind === "end"));
    const text = new TextDecoder().decode((chunks[0] as { data: Uint8Array }).data);
    expect(text.split("\n").filter(Boolean)).toHaveLength(5);
    expect(text).toMatch(/^2026-11-01T08:00:00.000Z INFO /);
    expect(chunks.at(-1)).toEqual({ kind: "end", truncated: false, reason: null });

    const live: LogChunk[] = [];
    const { streamId } = await m.kubeLogs(args(sid, { follow: true, onChunk: (c) => live.push(c) }));
    await until(() => live.length >= 3);
    await m.kubeLogsStop({ sessionId: sid, streamId });
    const n = live.length;
    await until(() => false, 5);
    expect(live.length).toBe(n);
    expect(live.every((c) => c.kind === "data")).toBe(true);
    expect(await code(m.kubeLogsStop({ sessionId: sid, streamId }))).toBe("kube.not_found");
  });

  it("stops at maxLogBytes with truncated: true", async () => {
    const m = new MockTransport();
    m.connections = m.connections.map((c) => (c.id === "c-k8s" ? { ...c, options: { maxLogBytes: 65_536 } as never } : c));
    const { sid } = await cluster(m);
    const chunks: LogChunk[] = [];
    await m.kubeLogs(args(sid, { namespace: "monitoring", pod: "log-flood-8c7d6-zz1aa", container: "flood", follow: true, tailLines: 10_000, onChunk: (c) => chunks.push(c) }));
    await until(() => chunks.some((c) => c.kind === "end"));
    const bytes = chunks.reduce((n, c) => n + (c.kind === "data" ? c.data.length : 0), 0);
    expect(bytes).toBe(65_536);
    expect(chunks.at(-1)).toEqual({ kind: "end", truncated: true, reason: null });
  });

  it("validates arguments and caps streams per cluster", async () => {
    const { m, sid } = await cluster();
    expect(await code(m.kubeLogs(args(sid, { tailLines: 10_001 })))).toBe("input.invalid");
    expect(await code(m.kubeLogs(args(sid, { container: "nope" })))).toBe("kube.not_found");
    expect(await code(m.kubeLogs(args(sid, { pod: "../etc" })))).toBe("input.invalid");
    for (let i = 0; i < 8; i++) await m.kubeLogs(args(sid, { follow: true }));
    expect(await code(m.kubeLogs(args(sid)))).toBe("kube.stream_limit");
  });
});

describe("mock · exec and forwards", () => {
  const exec = (sid: string, argv = ["/bin/sh"], p: Record<string, string> = {}) => ({
    parentSessionId: sid, namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", container: "api", argv, ...p,
  });

  it("opens an exec session only for an allow-listed shell the token may run", async () => {
    const { m, sid } = await cluster();
    const events: SessionEvent[] = [];
    const size = { width: 80, height: 24 };
    const { sessionId } = await m.sessionOpen({ connectionId: "c-k8s", size, onEvent: (e) => events.push(e), kube: exec(sid) });
    await until(() => events.some((e) => e.kind === "connected"));
    expect(events[0]).toMatchObject({ kind: "connected", protocol: "kubernetes" });
    expect(m.audit.some((a) => a.event === "kube.exec.open" && a.details.argv0 === "/bin/sh")).toBe(true);
    const open = (k: ReturnType<typeof exec> | undefined) => code(m.sessionOpen({ connectionId: "c-k8s", size, onEvent: () => undefined, ...(k ? { kube: k } : {}) }));
    expect(await open(exec(sid, ["/bin/sh", "-c", "id"]))).toBe("input.invalid");
    expect(await open(exec(sid, ["/usr/bin/python3"]))).toBe("input.invalid");
    expect(await open(undefined)).toBe("input.invalid");
    expect(await open(exec(sid, ["sh"], { namespace: "monitoring", pod: "prometheus-0", container: "prometheus" }))).toBe("kube.rbac_denied");
    // Input echoes; `exit` ends the shell with server_ended.
    await m.sessionSend({ sessionId, input: { kind: "bytes", data: new TextEncoder().encode("exit\r") } });
    await until(() => events.some((e) => e.kind === "closed"));
    expect(events.at(-1)).toMatchObject({ kind: "closed", code: "server_ended" });
  });

  it("closing the cluster session ends its exec shells, log streams and forwards", async () => {
    const { m, sid } = await cluster();
    const events: SessionEvent[] = [];
    await m.sessionOpen({ connectionId: "c-k8s", size: { width: 80, height: 24 }, onEvent: (e) => events.push(e), kube: exec(sid, ["bash"]) });
    const chunks: LogChunk[] = [];
    await m.kubeLogs({ sessionId: sid, namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", container: "api", follow: true, tailLines: 1, sinceSeconds: null, timestamps: false, onChunk: (c) => chunks.push(c) });
    await m.forwardOpen({ sessionId: sid, kind: "pod", bind: { host: "127.0.0.1", port: 18080 }, target: { namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", port: 8080 }, exposure: "loopback" });
    expect(await m.forwardList({ sessionId: sid })).toHaveLength(1);
    await m.sessionClose({ sessionId: sid });
    expect(events.at(-1)).toMatchObject({ kind: "closed", code: "user" });
    expect(chunks.at(-1)).toMatchObject({ kind: "end", reason: "the cluster session closed" });
    expect(m.forwards.has(sid)).toBe(false);
    expect(await m.sessionList()).toHaveLength(0);
  });

  it("pod forwards run on the cluster session only, with the same exposure rules", async () => {
    const { m, sid } = await cluster();
    const pod = { namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", port: 8080 };
    const f = await m.forwardOpen({ sessionId: sid, kind: "pod", bind: { host: "127.0.0.1", port: 0 }, target: pod, exposure: "loopback" });
    expect(f).toMatchObject({ kind: "pod", target: pod, exposure: "loopback" });
    expect(f.bind.port).toBeGreaterThan(0);
    expect(await code(m.forwardOpen({ sessionId: sid, kind: "local", bind: { host: "127.0.0.1", port: 1 }, target: { host: "db.example.test", port: 5432 }, exposure: "loopback" }))).toBe("input.invalid");
    expect(await code(m.forwardOpen({ sessionId: sid, kind: "pod", bind: { host: "0.0.0.0", port: 9 }, target: pod, exposure: "loopback" }))).toBe("input.invalid");
    expect(await code(m.forwardOpen({ sessionId: sid, kind: "pod", bind: { host: "127.0.0.1", port: 9 }, target: { ...pod, pod: "ghost" }, exposure: "loopback" }))).toBe("kube.not_found");
    expect(await code(m.forwardOpen({ sessionId: sid, kind: "pod", bind: { host: "127.0.0.1", port: 9 }, target: { namespace: "kube-system", pod: "coredns-7db6d8ff4d-6kq5h", port: 53 }, exposure: "loopback" }))).toBe("kube.rbac_denied");
    // An SSH session refuses pod forwards.
    m.trustedHosts.add("web01.example.test");
    const ssh = await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: () => undefined });
    await until(() => m.sessions.get(ssh.sessionId)?.info.state === "connected");
    expect(await code(m.forwardOpen({ sessionId: ssh.sessionId, kind: "pod", bind: { host: "127.0.0.1", port: 9 }, target: pod, exposure: "loopback" }))).toBe("input.invalid");
  });
});

describe("kube decoders", () => {
  it("never shows more than the wire says", () => {
    expect(decodeAccess({ listPods: true, getLogs: "yes", exec: 1, port_forward: true })).toEqual({ listPods: true, getLogs: false, exec: false, portForward: true, listNamespaces: false });
    const list = decodePodList({ items: [{ name: "a", phase: "Exploded", containers: [{ name: "c", ready: "true", restarts: -3, ports: [80, 0, 70000, "x"] }] }, { phase: "Running" }], truncated: 1 });
    expect(list).toEqual({ items: [{ name: "a", phase: "Unknown", node: null, createdAt: "", containers: [{ name: "c", image: "", ready: false, restarts: 0, ports: [80] }] }], truncated: false });
  });

  it("turns unknown watch events into a resync and bad log chunks into an end", () => {
    expect(decodePodEvent({ type: "BOOKMARK" })).toEqual({ type: "resync" });
    expect(decodePodEvent({ type: "ADDED", pod: { name: "p", phase: "Running" } })).toMatchObject({ type: "added", pod: { name: "p" } });
    const chunk = decodeLogChunk({ kind: "data", data: bytesToBase64(new TextEncoder().encode("hi\n")) });
    expect(chunk.kind === "data" ? new TextDecoder().decode(chunk.data) : null).toBe("hi\n");
    expect(decodeLogChunk({ kind: "data", data: "%%%" })).toEqual({ kind: "end", truncated: false, reason: "unreadable log data" });
    expect(decodeLogChunk({ kind: "end", truncated: true, reason: null })).toEqual({ kind: "end", truncated: true, reason: null });
    expect(decodeLogChunk({ kind: "chunk" })).toEqual({ kind: "end", truncated: false, reason: "unrecognised log message" });
  });

  it("decodes pod forward targets", () => {
    const f = decodeForward({ id: "fw-1", kind: "pod", bind: { host: "127.0.0.1", port: 1 }, target: { namespace: "ns", pod: "p", port: 80 }, exposure: "loopback" });
    expect(f).toMatchObject({ kind: "pod", target: { namespace: "ns", pod: "p", port: 80 } });
  });
});

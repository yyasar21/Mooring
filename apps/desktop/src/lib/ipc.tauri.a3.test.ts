// The Tauri transport against a fake `invoke`: command names and argument shapes of ADR-0014..0017,
// and the channel decoding of log streams and exec shells (K4).
import { POLLED_COMMANDS, type LogChunk, type SessionEvent } from "./ipc";

const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];
let reply: unknown = undefined;

vi.mock("@tauri-apps/api/core", () => {
  class Channel {
    onmessage: (msg: unknown) => void = () => undefined;
  }
  return {
    Channel,
    invoke: (cmd: string, args?: Record<string, unknown>) => {
      calls.push({ cmd, args });
      return Promise.resolve(reply);
    },
  };
});
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

const { TauriTransport } = await import("./ipc");

beforeEach(() => {
  calls.length = 0;
  reply = undefined;
});

describe("TauriTransport · ADR-0014..0017", () => {
  it("names every A3 command with camelCase arguments", async () => {
    const t = new TauriTransport();
    const sessionId = "k-1";
    reply = { items: [], truncated: false };
    await t.kubeOpen({ connectionId: "c-1", onEvent: () => undefined });
    await t.kubeAccess({ sessionId, namespace: "ns" });
    await t.kubeNamespaces({ sessionId });
    await t.kubePods({ sessionId, namespace: "ns", labelSelector: null });
    await t.kubeLogsClose({ sessionId, streamId: "l-1" });
    await t.vsphereTest({ connectionId: "c-1" });
    await t.vsphereSyncEnable({ connectionId: "c-1", parentFolderId: "f-1" });
    await t.vsphereSyncDisable({ connectionId: "c-1", keep: true });
    await t.vsphereRefresh({ connectionId: "c-1" });
    await t.vsphereStatus({ connectionId: "c-1" });
    await t.vsphereVmPower({ connectionId: "c-2" });
    await t.vsphereVmAction({ connectionId: "c-2", action: "reboot" });
    await t.vsphereVmIdentity({ connectionId: "c-2" });
    await t.vsphereConsole({ connectionId: "c-2", kind: "client" });
    await t.secretSourceList();
    await t.secretSourceGet({ id: "src-1" });
    await t.secretSourceDelete({ id: "src-1" });
    await t.secretSourceTest({ id: "src-1" });
    await t.secretSourceRevoke({ id: "src-1" });
    await t.credentialExternalTest({ credentialId: "cr-1" });
    await t.secretSourceOidcBegin({ id: "src-1" });
    await t.secretSourceOidcStatus({ sessionId: "o-1" });
    await t.syncConfigure({ backend: { kind: "s3", endpoint: "https://s3.example.test", region: "r", bucket: "b", prefix: "", pathStyle: true }, credentialId: "cr-2", intervalMinutes: null });
    await t.syncStatus();
    await t.syncNow();
    await t.syncResolveFork({ keep: "remote" });
    await t.syncDisable({ deleteRemote: false });
    await t.vaultJoin({ backend: { kind: "s3", endpoint: "https://s3.example.test", region: "r", bucket: "b", prefix: "", pathStyle: true }, credentialId: "cr-2", vaultId: "v", password: "p", intervalMinutes: 15 });
    expect(calls.map((c) => c.cmd)).toEqual([
      "kube_open", "kube_access", "kube_namespaces", "kube_pods", "kube_logs_close",
      "vsphere_test", "vsphere_sync_enable", "vsphere_sync_disable", "vsphere_refresh", "vsphere_status", "vsphere_vm_power",
      "vsphere_vm_action", "vsphere_vm_identity", "vsphere_console",
      "secret_source_list", "secret_source_get", "secret_source_delete", "secret_source_test", "secret_source_revoke", "credential_external_test",
      "secret_source_oidc_begin", "secret_source_oidc_status",
      "sync_configure", "sync_status", "sync_now", "sync_resolve_fork", "sync_disable", "vault_join",
    ]);
    expect(calls[3]?.args).toEqual({ sessionId, namespace: "ns", labelSelector: null });
    expect(calls[11]?.args).toEqual({ connectionId: "c-2", action: "reboot" });
    expect(calls[21]?.args).toEqual({ sessionId: "o-1" });
    expect(calls[25]?.args).toEqual({ keep: "remote" });
    expect(calls[27]?.args).toMatchObject({ vaultId: "v", password: "p", intervalMinutes: 15, backend: { kind: "s3" } });
  });

  it("opens a cluster with an event channel and decodes connected and hop events from it (K4, ADR-0025)", async () => {
    const t = new TauriTransport();
    const seen: unknown[] = [];
    reply = { sessionId: "k-1" };
    expect(await t.kubeOpen({ connectionId: "c-1", onEvent: (e) => seen.push(e) })).toEqual({ sessionId: "k-1" });
    expect(Object.keys(calls[0]?.args ?? {}).sort()).toEqual(["connectionId", "onEvent"]);
    const chan = calls[0]?.args?.onEvent as { onmessage: (m: unknown) => void };
    chan.onmessage({ kind: "hop_status", hop: 0, of: 1, state: "connecting", host: "b.example.test:22" });
    chan.onmessage({ kind: "connected", server: "https://k.example.test", identity: { user: "u", groups: [] }, contextNamespace: null, namespace: "default" });
    expect(seen).toEqual([
      { kind: "hop_status", hop: 0, of: 1, state: "connecting", host: "b.example.test:22", peerIdentity: null },
      { kind: "connected", server: "https://k.example.test", identity: { user: "u", groups: [] }, contextNamespace: null },
    ]);
  });

  it("opens exec shells with kube_exec_open and never sends a kube target to session_open (K4)", async () => {
    const t = new TauriTransport();
    reply = { sessionId: "x-1" };
    const seen: SessionEvent[] = [];
    expect(await t.kubeExecOpen({ sessionId: "k-1", namespace: "ns", pod: "p", container: null, command: "/bin/sh", size: { width: 80, height: 24 }, onEvent: (e) => seen.push(e) })).toEqual({ sessionId: "x-1" });
    expect(calls[0]?.cmd).toBe("kube_exec_open");
    expect(Object.keys(calls[0]?.args ?? {}).sort()).toEqual(["command", "container", "namespace", "onEvent", "pod", "sessionId", "size"]);
    expect(calls[0]?.args).toMatchObject({ sessionId: "k-1", container: null, command: "/bin/sh", size: { width: 80, height: 24 } });
    (calls[0]?.args?.onEvent as { onmessage: (m: unknown) => void }).onmessage({ kind: "bytes", data: btoa("# ") });
    expect(seen[0]?.kind).toBe("bytes");
    await t.sessionOpen({ connectionId: "c-1", size: { width: 80, height: 24 }, onEvent: () => undefined });
    expect(Object.keys(calls[1]?.args ?? {}).sort()).toEqual(["connectionId", "onEvent", "size"]);
  });

  it("decodes log channels defensively (kube_logs_open)", async () => {
    const t = new TauriTransport();
    reply = { streamId: "l-1" };
    const chunks: LogChunk[] = [];
    await t.kubeLogsOpen({ sessionId: "k-1", namespace: "ns", pod: "p", container: "c", follow: true, tailLines: 10, sinceSeconds: null, timestamps: false, onChunk: (c) => chunks.push(c) });
    expect(calls[0]?.cmd).toBe("kube_logs_open");
    const args = calls[0]?.args ?? {};
    expect(args).toMatchObject({ sessionId: "k-1", namespace: "ns", pod: "p", container: "c", follow: true, tailLines: 10, sinceSeconds: null, timestamps: false });
    const ch = args.onChunk as { onmessage: (m: unknown) => void };
    ch.onmessage({ kind: "data", data: btoa("line\n") });
    ch.onmessage({ kind: "end", truncated: true, reason: null });
    expect(chunks[0]?.kind).toBe("data");
    expect(chunks[1]).toEqual({ kind: "end", truncated: true, reason: null });
  });

  it("decodes the heterogeneous sync_status.conflicts (6b L-35) and drops drifted entries", async () => {
    const t = new TauriTransport();
    const trust = { kind: "trust", id: "known_rdp_certs", name: "dc01.example.test:3389" };
    reply = { state: "idle", counter: 2, conflicts: [{ kind: "folder", id: "f", name: "ops", resolution: { type: "lastWriterWins" } }, trust, { kind: "trust" }] };
    const s = await t.syncStatus();
    expect(s.counter).toBe(2);
    expect(s.conflicts).toEqual([{ kind: "folder", id: "f", name: "ops", resolution: { type: "lastWriterWins" } }, trust]);
  });

  it("lists the ADR passive commands as polled", () => {
    for (const c of ["kube_access", "kube_namespaces", "kube_pods", "vsphere_status", "vsphere_vm_power", "sync_status", "secret_source_oidc_status"]) expect(POLLED_COMMANDS).toContain(c);
    for (const c of ["kube_open", "kube_logs_open", "kube_exec_open", "vsphere_refresh", "sync_now", "secret_source_oidc_begin", "secret_source_test"]) expect(POLLED_COMMANDS).not.toContain(c);
  });
});

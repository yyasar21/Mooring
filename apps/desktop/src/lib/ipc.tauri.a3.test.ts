// The Tauri transport against a fake `invoke`: command names and argument shapes of ADR-0014..0017,
// and the channel decoding of pod watches and log streams.
import { POLLED_COMMANDS, type LogChunk, type PodEvent } from "./ipc";

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
    await t.kubeOpen({ connectionId: "c-1" });
    await t.kubeAccess({ sessionId, namespace: "ns" });
    await t.kubeNamespaces({ sessionId });
    await t.kubePods({ sessionId, namespace: "ns", labelSelector: null });
    await t.kubeUnwatch({ sessionId, watchId: "w-1" });
    await t.kubeLogsStop({ sessionId, streamId: "l-1" });
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
      "kube_open", "kube_access", "kube_namespaces", "kube_pods", "kube_unwatch", "kube_logs_stop",
      "vsphere_test", "vsphere_sync_enable", "vsphere_sync_disable", "vsphere_refresh", "vsphere_status", "vsphere_vm_power",
      "vsphere_vm_action", "vsphere_vm_identity", "vsphere_console",
      "secret_source_list", "secret_source_get", "secret_source_delete", "secret_source_test", "secret_source_revoke", "credential_external_test",
      "secret_source_oidc_begin", "secret_source_oidc_status",
      "sync_configure", "sync_status", "sync_now", "sync_resolve_fork", "sync_disable", "vault_join",
    ]);
    expect(calls[3]?.args).toEqual({ sessionId, namespace: "ns", labelSelector: null });
    expect(calls[12]?.args).toEqual({ connectionId: "c-2", action: "reboot" });
    expect(calls[22]?.args).toEqual({ sessionId: "o-1" });
    expect(calls[26]?.args).toEqual({ keep: "remote" });
    expect(calls[28]?.args).toMatchObject({ vaultId: "v", password: "p", intervalMinutes: 15, backend: { kind: "s3" } });
  });

  it("passes the exec target on session_open only when given", async () => {
    const t = new TauriTransport();
    reply = { sessionId: "x-1" };
    const kube = { parentSessionId: "k-1", namespace: "ns", pod: "p", container: "c", argv: ["/bin/sh"] };
    await t.sessionOpen({ connectionId: "c-1", size: { width: 80, height: 24 }, onEvent: () => undefined, kube });
    await t.sessionOpen({ connectionId: "c-1", size: { width: 80, height: 24 }, onEvent: () => undefined });
    expect(calls[0]?.args?.kube).toEqual(kube);
    expect(calls[1]?.args && "kube" in calls[1].args).toBe(false);
  });

  it("decodes watch and log channels defensively", async () => {
    const t = new TauriTransport();
    reply = { watchId: "w-1" };
    const events: PodEvent[] = [];
    await t.kubeWatch({ sessionId: "k-1", namespace: "ns", onEvent: (e) => events.push(e) });
    const watch = calls[0]?.args?.onEvent as { onmessage: (m: unknown) => void };
    watch.onmessage({ type: "added", pod: { name: "p", phase: "Running", containers: [] } });
    watch.onmessage({ type: "weird" });
    expect(events.map((e) => e.type)).toEqual(["added", "resync"]);

    reply = { streamId: "l-1" };
    const chunks: LogChunk[] = [];
    await t.kubeLogs({ sessionId: "k-1", namespace: "ns", pod: "p", container: "c", follow: true, tailLines: 10, sinceSeconds: null, timestamps: false, onChunk: (c) => chunks.push(c) });
    const args = calls[1]?.args ?? {};
    expect(args).toMatchObject({ follow: true, tailLines: 10, sinceSeconds: null, timestamps: false });
    const ch = args.onChunk as { onmessage: (m: unknown) => void };
    ch.onmessage({ kind: "data", data: btoa("line\n") });
    ch.onmessage({ kind: "end", truncated: true, reason: null });
    expect(chunks[0]?.kind).toBe("data");
    expect(chunks[1]).toEqual({ kind: "end", truncated: true, reason: null });
  });

  it("lists the ADR passive commands as polled", () => {
    for (const c of ["kube_access", "kube_namespaces", "kube_pods", "vsphere_status", "vsphere_vm_power", "sync_status", "secret_source_oidc_status"]) expect(POLLED_COMMANDS).toContain(c);
    for (const c of ["kube_open", "kube_logs", "kube_watch", "vsphere_refresh", "sync_now", "secret_source_oidc_begin", "secret_source_test"]) expect(POLLED_COMMANDS).not.toContain(c);
  });
});

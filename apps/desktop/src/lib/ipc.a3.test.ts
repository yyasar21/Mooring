// ADR-0015..0017 mock contract: vSphere sync into a read-only subtree, power through the
// "native dialog", secret sources and external_ref tests (names only), vault sync.
import { IpcError, type SecretSourceInput, type VsphereConnOptions } from "./ipc";
import { MockTransport } from "./ipc.mock";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not an IpcError";
  }
};

describe("mock · vSphere (ADR-0015)", () => {
  async function synced() {
    const m = new MockTransport();
    const root = await m.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-staging" });
    const vm = m.connections.find((c) => c.externalId === "vm-app-vm-01");
    if (!vm) throw new Error("no VM");
    return { m, root, vm };
  }

  it("tests the sign-in and imports Datacenter → Cluster → Host → VM as synced rows", async () => {
    const m = new MockTransport();
    expect(await m.vsphereTest({ connectionId: "c-vc" })).toMatchObject({ user: "administrator@vsphere.local" });
    expect(await code(m.vsphereTest({ connectionId: "c-web01" }))).toBe("input.invalid");
    const root = await m.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-staging" });
    expect(root).toMatchObject({ name: "stage-vcenter", syncSource: "c-vc", parentId: "f-staging" });
    const vms = m.connections.filter((c) => c.syncSource === "c-vc");
    expect(vms).toHaveLength(5);
    expect(vms.every((v) => v.protocol === "vsphere-console" && v.syncState === "present")).toBe(true);
    expect(m.folders.find((f) => f.name === "Standalone hosts")?.syncSource).toBe("c-vc");
    // A second refresh adds nothing and is audited.
    expect(await m.vsphereRefresh({ connectionId: "c-vc" })).toMatchObject({ added: 0 });
    expect(m.audit.at(-1)?.event).toBe("vsphere.sync");
    expect((await m.vsphereStatus({ connectionId: "c-vc" })).lastRefresh).not.toBeNull();
    expect((await m.connectionOptionsGet({ connectionId: "c-vc" }))).toMatchObject({ syncFolderId: root.id });
  });

  it("keeps the synced subtree read-only, overlays editable", async () => {
    const { m, root, vm } = await synced();
    expect(await code(m.folderCreate({ parentId: root.id, name: "x" }))).toBe("tree.synced_readonly");
    expect(await code(m.folderRename({ id: root.id, name: "x" }))).toBe("tree.synced_readonly");
    expect(await code(m.folderDelete({ id: root.id }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionDelete({ id: vm.id }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionMove({ id: vm.id, folderId: "f-root" }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionMove({ id: "c-web01", folderId: root.id }))).toBe("tree.synced_readonly");
    const fields = { ...vm, credentialId: "cr-vc", tags: ["linux"] };
    expect(await code(m.connectionUpdate({ ...fields, name: "renamed" }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionUpdate(fields))).toBe("ok");
    expect(m.connections.find((c) => c.id === vm.id)?.tags).toEqual(["linux"]);
    // Outside the subtree nothing changes.
    expect(await code(m.folderRename({ id: "f-web", name: "Web" }))).toBe("ok");
  });

  it("power actions need the opt-in and go through the native confirmation", async () => {
    const { m, vm } = await synced();
    expect(await m.vsphereVmPower({ connectionId: vm.id })).toEqual({ state: "POWERED_ON" });
    expect(await code(m.vsphereVmAction({ connectionId: vm.id, action: "stop" }))).toBe("vsphere.power_disabled");
    const opts = await m.connectionOptionsGet({ connectionId: "c-vc" });
    await m.connectionOptionsSet({ connectionId: "c-vc", options: { ...(opts as VsphereConnOptions), allowPowerActions: true } });
    m.confirmPower = false;
    expect(await m.vsphereVmAction({ connectionId: vm.id, action: "stop" })).toEqual({ outcome: "cancelled" });
    expect((await m.vsphereVmPower({ connectionId: vm.id })).state).toBe("POWERED_ON");
    m.confirmPower = true;
    expect(await m.vsphereVmAction({ connectionId: vm.id, action: "stop" })).toEqual({ outcome: "done" });
    expect((await m.vsphereVmPower({ connectionId: vm.id })).state).toBe("POWERED_OFF");
    expect(m.audit.filter((a) => a.event === "vsphere.power").map((a) => a.details.outcome)).toEqual(["cancelled", "done"]);
    expect(await code(m.vsphereVmPower({ connectionId: "c-web01" }))).toBe("input.invalid");
  });

  it("consoles: the vSphere Client by default, VMRC only when opted in; identity needs Tools", async () => {
    const { m, vm } = await synced();
    expect(await m.vsphereConsole({ connectionId: vm.id, kind: "client" })).toEqual({ windowLabel: "web-c-vc" });
    expect(await code(m.vsphereConsole({ connectionId: vm.id, kind: "vmrc" }))).toBe("input.invalid");
    expect(await m.vsphereVmIdentity({ connectionId: vm.id })).toEqual({ hostName: "app-vm-01.example.test", ip: "192.0.2.21", family: "LINUX" });
    const off = m.connections.find((c) => c.externalId === "vm-build-vm");
    expect(await code(m.vsphereVmIdentity({ connectionId: off?.id ?? "" }))).toBe("vsphere.tools_missing");
  });

  it("disabling sync keeps (detached) or drops the subtree", async () => {
    const a = await synced();
    await a.m.vsphereSyncDisable({ connectionId: "c-vc", keep: true });
    expect(a.m.connections.find((c) => c.id === a.vm.id)?.syncSource).toBeNull();
    expect(await code(a.m.folderRename({ id: a.root.id, name: "kept" }))).toBe("ok");
    const b = await synced();
    await b.m.vsphereSyncDisable({ connectionId: "c-vc", keep: false });
    expect(b.m.connections.some((c) => c.id === b.vm.id)).toBe(false);
    expect(b.m.folders.some((f) => f.id === b.root.id)).toBe(false);
  });
});

describe("mock · secret sources (ADR-0016)", () => {
  const input = (p: Partial<SecretSourceInput> = {}): SecretSourceInput => ({
    name: "ops vault", address: "https://vault.example.test:8200", namespace: null, authMethod: "approle", authMount: "approle",
    credentialId: "cr-ops", oidcRole: null, options: { caPem: null, allowHttp: false, allowedOrigins: [] }, ...p,
  });

  it("creates, tests, updates and deletes sources; nothing secret comes back", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(input());
    expect(s).toMatchObject({ kind: "vault", name: "ops vault" });
    expect(JSON.stringify(await m.secretSourceList())).not.toMatch(/token|secret_id/i);
    expect(await m.secretSourceTest({ id: s.id })).toMatchObject({ ok: true, method: "approle", renewable: true });
    await m.secretSourceUpdate({ id: s.id, ...input({ name: "renamed", address: "https://down.invalid" }) });
    expect(await m.secretSourceTest({ id: s.id })).toMatchObject({ ok: false, error: "network" });
    expect(m.audit.some((a) => a.event === "secret.source_changed" && a.details.changed === "name,address")).toBe(true);
    await m.secretSourceLogout({ id: s.id });
    await m.secretSourceDelete({ id: s.id });
    expect(await code(m.secretSourceTest({ id: s.id }))).toBe("source.not_found");
  });

  it("validates addresses and the method/credential pairing", async () => {
    const m = new MockTransport();
    expect(await code(m.secretSourceCreate(input({ address: "http://vault.example.test" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ address: "http://127.0.0.1:8200", options: { caPem: null, allowHttp: true, allowedOrigins: [] } })))).toBe("ok");
    expect(await code(m.secretSourceCreate(input({ authMethod: "oidc" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ authMethod: "token", credentialId: null })))).toBe("input.invalid");
  });

  it("OIDC: one window per source, status goes waiting → done", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(input({ authMethod: "oidc", authMount: "oidc", credentialId: null, oidcRole: "ops" }));
    expect(await m.secretSourceOidcStatus({ id: s.id })).toEqual({ state: "idle", error: null });
    expect(await m.secretSourceOidcStart({ id: s.id })).toEqual({ windowLabel: `oidc-${s.id}` });
    expect(await code(m.secretSourceOidcStart({ id: s.id }))).toBe("input.invalid");
    await new Promise((r) => setTimeout(r, 0));
    expect((await m.secretSourceOidcStatus({ id: s.id })).state).toBe("done");
  });

  it("external_ref_test returns key names only, and a used source cannot be deleted", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(input());
    // The ADR-0016 `source` field joins the external_ref schema with U3/E2; the row is seeded directly.
    const ref = { id: "cr-ext", name: "db via vault", kind: "external_ref" as const, fields: { provider: "vault", source: s.id, reference: "kv/ops/db", target_kind: "user_password" }, secretNames: [], fingerprint: null, createdAt: "", updatedAt: "" };
    m.creds.items.push(ref);
    expect(await m.externalRefTest({ credentialId: ref.id })).toEqual({ ok: true, version: 3, present: ["username", "password"], missing: [], error: null });
    expect(await code(m.secretSourceDelete({ id: s.id }))).toBe("source.in_use");
    expect(await code(m.externalRefTest({ credentialId: "cr-ops" }))).toBe("input.invalid");
  });
});

describe("mock · vault sync (ADR-0017)", () => {
  const settings = { endpoint: "https://s3.example.test", bucket: "mooring-sync", prefix: "team", region: "eu-west-1", pathStyle: true, credentialId: "cr-ops", options: { caPem: null } };

  it("configures, probes, syncs and disables", async () => {
    const m = new MockTransport();
    expect(await m.syncGet()).toBeNull();
    expect((await m.syncStatus()).state).toBe("disabled");
    expect(await code(m.syncNow())).toBe("sync.not_configured");
    expect(await m.syncSet(settings)).toMatchObject({ bucket: "mooring-sync", deviceId: "dev-0001" });
    expect(await m.syncProbe()).toEqual({ conditionalWrites: true, error: null });
    expect(await m.syncNow()).toMatchObject({ pulled: true, pushed: true, conflicts: [] });
    expect((await m.syncStatus()).counter).toBe(1);
    await m.syncDisable({ deleteRemote: false });
    expect(await m.syncGet()).toBeNull();
  });

  it("refuses backends without conditional writes and bad settings", async () => {
    const m = new MockTransport();
    expect(await code(m.syncSet({ ...settings, bucket: "Bad_Bucket" }))).toBe("input.invalid");
    await m.syncSet({ ...settings, endpoint: "https://s3.invalid" });
    expect((await m.syncProbe()).conditionalWrites).toBe(false);
    expect(await code(m.syncNow())).toBe("sync.unsupported_backend");
  });

  it("vault_join works only on a fresh device", async () => {
    const join = { endpoint: settings.endpoint, bucket: "b-1", prefix: "team", region: "r", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "x", password: "pw" };
    expect(await code(new MockTransport().vaultJoin(join))).toBe("vault.exists");
    const fresh = new MockTransport({ vault: "missing" });
    expect(await code(fresh.vaultJoin({ ...join, prefix: "empty" }))).toBe("sync.not_found");
    expect(await fresh.vaultJoin(join)).toBe("unlocked");
  });
});

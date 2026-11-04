// ADR-0015..0017 mock contract: vSphere sync into a read-only subtree, power through the
// "native dialog". Secret sources and vault sync are in ipc.secrets.test.ts / ipc.sync.test.ts.
import { IpcError, type VsphereConnOptions } from "./ipc";
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


// ADR-0015 mock contract as rust-core V2 ships it: sync into a read-only subtree, the two-miss
// rule, status, power through the "native dialog", consoles, trust prompts.
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

async function synced() {
  const m = new MockTransport();
  const root = await m.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-staging" });
  const vm = m.connections.find((c) => c.externalId === "vm-app-vm-01");
  if (!vm) throw new Error("no VM");
  return { m, root, vm };
}

const allow = async (m: MockTransport, p: Partial<VsphereConnOptions>) => {
  const opts = (await m.connectionOptionsGet({ connectionId: "c-vc" })) as VsphereConnOptions;
  return m.connectionOptionsSet({ connectionId: "c-vc", options: { ...opts, ...p } });
};

describe("mock · vSphere sync (ADR-0015, V2)", () => {
  it("tests the sign-in and imports Datacenter → Cluster → Host → VM as synced rows", async () => {
    const m = new MockTransport();
    expect(await m.vsphereTest({ connectionId: "c-vc" })).toEqual({ version: "8.0.3.00400", build: "24322831", user: "administrator@vsphere.local" });
    expect(await code(m.vsphereTest({ connectionId: "c-web01" }))).toBe("input.invalid");
    expect(await code(m.vsphereRefresh({ connectionId: "c-vc" }))).toBe("vsphere.not_found");
    expect(await code(m.vsphereSyncDisable({ connectionId: "c-vc", keep: true }))).toBe("vsphere.not_found");
    expect(await m.vsphereStatus({ connectionId: "c-vc" })).toEqual({ lastRefresh: null, lastError: null, running: false, lastReport: null, scheduled: false });
    const root = await m.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-staging" });
    expect(root).toMatchObject({ name: "stage-vcenter", syncSource: "c-vc", parentId: "f-staging" });
    expect(root.externalId).toBeNull();
    const vms = m.connections.filter((c) => c.syncSource === "c-vc");
    expect(vms).toHaveLength(5);
    expect(vms.every((v) => v.protocol === "vsphere-console" && v.syncState === "present" && v.externalId?.startsWith("vm-"))).toBe(true);
    expect(m.folders.find((f) => f.name === "Standalone hosts")).toMatchObject({ syncSource: "c-vc", externalId: "cluster-Standalone hosts" });
    expect(m.audit.filter((a) => a.event === "vsphere_sync_started").at(-1)?.details.trigger).toBe("import");
    expect(m.audit.at(-1)).toMatchObject({ event: "vsphere_sync_finished", details: { added: "5", removed: "0" } });
    // Enabling again is idempotent; a second refresh adds nothing.
    expect((await m.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-root" })).id).toBe(root.id);
    expect(await m.vsphereRefresh({ connectionId: "c-vc" })).toMatchObject({ added: 0, changed: 0, missing: 0, deleted: 0 });
    const status = await m.vsphereStatus({ connectionId: "c-vc" });
    expect(status).toMatchObject({ scheduled: true, running: false, lastError: null, lastReport: { added: 0 } });
    expect(status.lastRefresh).not.toBeNull();
    expect(await m.connectionOptionsGet({ connectionId: "c-vc" })).toMatchObject({ syncFolderId: root.id });
  });

  it("keeps syncFolderId derived: options writes cannot change it", async () => {
    const { m, root } = await synced();
    const stored = await allow(m, { syncFolderId: null, refreshMinutes: null });
    expect(stored).toMatchObject({ syncFolderId: root.id, refreshMinutes: null });
    expect((await m.vsphereStatus({ connectionId: "c-vc" })).scheduled).toBe(false);
  });

  it("a failed first import removes the empty root again", async () => {
    const m = new MockTransport();
    m.vsphereDown.add("c-vc");
    expect(await code(m.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-staging" }))).toBe("vsphere.unavailable");
    expect(m.folders.some((f) => f.syncSource === "c-vc")).toBe(false);
    expect(await m.connectionOptionsGet({ connectionId: "c-vc" })).toMatchObject({ syncFolderId: null });
    expect(await code(m.vsphereTest({ connectionId: "c-vc" }))).toBe("vsphere.unavailable");
  });

  it("marks a VM missing on the first miss and deletes it on the second; a return restores it", async () => {
    const { m } = await synced();
    m.vsphereHidden.add("vm-build-vm");
    expect(await m.vsphereRefresh({ connectionId: "c-vc" })).toMatchObject({ missing: 1, deleted: 0 });
    const row = () => m.connections.find((c) => c.externalId === "vm-build-vm");
    expect(row()?.syncState).toBe("missing");
    expect(await code(m.vsphereVmPower({ connectionId: row()?.id ?? "" }))).toBe("vsphere.not_found");
    m.vsphereHidden.clear();
    expect(await m.vsphereRefresh({ connectionId: "c-vc" })).toMatchObject({ changed: 1, missing: 0 });
    expect(row()?.syncState).toBe("present");
    m.vsphereHidden.add("vm-build-vm");
    await m.vsphereRefresh({ connectionId: "c-vc" });
    expect(await m.vsphereRefresh({ connectionId: "c-vc" })).toMatchObject({ missing: 0, deleted: 1 });
    expect(row()).toBeUndefined();
  });

  it("a failed refresh changes nothing and shows on the status", async () => {
    const { m } = await synced();
    const before = m.connections.length;
    m.vsphereDown.add("c-vc");
    expect(await code(m.vsphereRefresh({ connectionId: "c-vc" }))).toBe("vsphere.unavailable");
    expect(m.connections).toHaveLength(before);
    expect((await m.vsphereStatus({ connectionId: "c-vc" })).lastError).toBe("vsphere.unavailable");
    expect(m.audit.at(-1)).toMatchObject({ event: "vsphere_sync_failed", details: { code: "vsphere.unavailable" } });
  });

  it("the scheduler cannot show the TOFU dialog: http.trust_prompt until a manual refresh trusts", async () => {
    const { m } = await synced();
    m.vsphereUntrusted.add("c-vc");
    await m.vsphereScheduledTick("c-vc");
    expect((await m.vsphereStatus({ connectionId: "c-vc" })).lastError).toBe("http.trust_prompt");
    m.confirmTrust = false;
    expect(await code(m.vsphereRefresh({ connectionId: "c-vc" }))).toBe("http.trust_rejected");
    m.confirmTrust = true;
    expect(await code(m.vsphereRefresh({ connectionId: "c-vc" }))).toBe("ok");
    expect(m.audit.some((a) => a.event === "cert_decision" && a.details.protocol === "vsphere")).toBe(true);
    expect((await m.vsphereStatus({ connectionId: "c-vc" })).lastError).toBeNull();
    await m.vsphereScheduledTick("c-vc");
    expect(m.audit.filter((a) => a.event === "vsphere_sync_started").at(-1)?.details.trigger).toBe("schedule");
  });

  it("keeps the synced subtree read-only, overlays editable", async () => {
    const { m, root, vm } = await synced();
    expect(await code(m.folderCreate({ parentId: root.id, name: "x" }))).toBe("tree.synced_readonly");
    expect(await code(m.folderRename({ id: root.id, name: "x" }))).toBe("tree.synced_readonly");
    expect(await code(m.folderMove({ id: root.id, parentId: "f-root" }))).toBe("tree.synced_readonly");
    expect(await code(m.folderMove({ id: "f-web", parentId: root.id }))).toBe("tree.synced_readonly");
    expect(await code(m.folderDelete({ id: root.id }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionCreate({ ...vm, folderId: root.id }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionDelete({ id: vm.id }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionMove({ id: vm.id, folderId: "f-root" }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionMove({ id: "c-web01", folderId: root.id }))).toBe("tree.synced_readonly");
    expect(await code(m.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: root.id }))).toBe("ok"); // idempotent, parent ignored
    const fields = { ...vm, credentialId: "cr-vc", tags: ["linux"] };
    expect(await code(m.connectionUpdate({ ...fields, name: "renamed" }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionUpdate({ ...fields, host: "198.51.100.9" }))).toBe("tree.synced_readonly");
    expect(await code(m.connectionUpdate(fields))).toBe("ok");
    expect(m.connections.find((c) => c.id === vm.id)).toMatchObject({ tags: ["linux"], credentialId: "cr-vc" });
    expect(await code(m.folderSetDefaultCredential({ id: root.id, credentialId: "cr-vc" }))).toBe("ok");
    // Overlays survive a refresh; outside the subtree nothing changes.
    await m.vsphereRefresh({ connectionId: "c-vc" });
    expect(m.connections.find((c) => c.id === vm.id)?.tags).toEqual(["linux"]);
    expect(await code(m.folderRename({ id: "f-web", name: "Web" }))).toBe("ok");
  });

  it("disabling sync keeps (detached) or drops the subtree and clears syncFolderId", async () => {
    const a = await synced();
    await a.m.vsphereSyncDisable({ connectionId: "c-vc", keep: true });
    expect(a.m.connections.find((c) => c.id === a.vm.id)).toMatchObject({ syncSource: null, syncState: null });
    expect(await code(a.m.folderRename({ id: a.root.id, name: "kept" }))).toBe("ok");
    expect(await a.m.connectionOptionsGet({ connectionId: "c-vc" })).toMatchObject({ syncFolderId: null });
    const b = await synced();
    await b.m.vsphereSyncDisable({ connectionId: "c-vc", keep: false });
    expect(b.m.connections.some((c) => c.id === b.vm.id)).toBe(false);
    expect(b.m.folders.some((f) => f.syncSource === "c-vc")).toBe(false);
  });
});

describe("mock · vSphere VM rows (ADR-0015 §3–4)", () => {
  it("power actions need the opt-in and go through the native confirmation; every outcome is audited", async () => {
    const { m, vm } = await synced();
    expect(await m.vsphereVmPower({ connectionId: vm.id })).toEqual({ state: "POWERED_ON" });
    expect(await code(m.vsphereVmAction({ connectionId: vm.id, action: "stop" }))).toBe("vsphere.power_disabled");
    await allow(m, { allowPowerActions: true });
    m.confirmPower = false;
    expect(await m.vsphereVmAction({ connectionId: vm.id, action: "stop" })).toEqual({ outcome: "cancelled" });
    expect((await m.vsphereVmPower({ connectionId: vm.id })).state).toBe("POWERED_ON");
    m.confirmPower = true;
    expect(await m.vsphereVmAction({ connectionId: vm.id, action: "stop" })).toEqual({ outcome: "done" });
    expect((await m.vsphereVmPower({ connectionId: vm.id })).state).toBe("POWERED_OFF");
    expect(await code(m.vsphereVmAction({ connectionId: vm.id, action: "shutdown" }))).toBe("vsphere.wrong_state");
    expect(await m.vsphereVmAction({ connectionId: vm.id, action: "start" })).toEqual({ outcome: "done" });
    expect(await m.vsphereVmAction({ connectionId: vm.id, action: "reboot" })).toEqual({ outcome: "done" });
    expect(m.audit.filter((a) => a.event === "vsphere_power").map((a) => a.details.outcome)).toEqual([
      "power_disabled", "cancelled", "requested", "done", "requested", "vsphere.wrong_state", "requested", "done", "requested", "done",
    ]);
    expect(await code(m.vsphereVmPower({ connectionId: "c-web01" }))).toBe("input.invalid");
    expect(await code(m.vsphereVmPower({ connectionId: "c-vc" }))).toBe("input.invalid");
  });

  it("guest shutdown and reboot need VMware Tools", async () => {
    const { m } = await synced();
    await allow(m, { allowPowerActions: true });
    const noTools = m.connections.find((c) => c.externalId === "vm-build-vm");
    if (!noTools) throw new Error("no VM");
    expect(await m.vsphereVmAction({ connectionId: noTools.id, action: "start" })).toEqual({ outcome: "done" });
    expect(await code(m.vsphereVmAction({ connectionId: noTools.id, action: "shutdown" }))).toBe("vsphere.tools_missing");
    expect(await code(m.vsphereVmAction({ connectionId: noTools.id, action: "reset" }))).toBe("ok");
  });

  it("consoles: the vSphere Client by default, VMRC only when opted in and confirmed; identity needs Tools", async () => {
    const { m, vm } = await synced();
    expect(await m.vsphereConsole({ connectionId: vm.id, kind: "client" })).toEqual({ windowLabel: "web-c-vc" });
    expect(m.audit.at(-1)).toMatchObject({ event: "vsphere_console", details: { vm: "vm-app-vm-01", kind: "client" } });
    expect(await code(m.vsphereConsole({ connectionId: vm.id, kind: "vmrc" }))).toBe("vsphere.vmrc_disabled");
    await allow(m, { allowVmrc: true });
    m.confirmPower = false;
    expect(await code(m.vsphereConsole({ connectionId: vm.id, kind: "vmrc" }))).toBe("vsphere.not_confirmed");
    m.confirmPower = true;
    expect(await m.vsphereConsole({ connectionId: vm.id, kind: "vmrc" })).toEqual({ windowLabel: null });
    expect(JSON.stringify(m.audit)).not.toMatch(/vmrc:\/\//);
    expect(await m.vsphereVmIdentity({ connectionId: vm.id })).toEqual({ hostName: "app-vm-01.example.test", ip: "192.0.2.21", family: "LINUX" });
    const off = m.connections.find((c) => c.externalId === "vm-build-vm");
    expect(await code(m.vsphereVmIdentity({ connectionId: off?.id ?? "" }))).toBe("vsphere.tools_missing");
  });

  it("a locked vault refuses every mutating call; a down vCenter answers unavailable", async () => {
    const { m, vm } = await synced();
    m.vsphereDown.add("c-vc");
    expect(await code(m.vsphereVmPower({ connectionId: vm.id }))).toBe("vsphere.unavailable");
    m.vsphereDown.clear();
    await m.vaultLock("user");
    for (const p of [
      m.vsphereTest({ connectionId: "c-vc" }), m.vsphereRefresh({ connectionId: "c-vc" }), m.vsphereSyncDisable({ connectionId: "c-vc", keep: true }),
      m.vsphereVmAction({ connectionId: vm.id, action: "start" }), m.vsphereConsole({ connectionId: vm.id, kind: "client" }),
    ]) expect(await code(p)).toBe("vault.locked");
    expect((await m.vsphereStatus({ connectionId: "c-vc" })).scheduled).toBe(false);
  });
});

// Mock of the ADR-0015 vSphere commands as rust-core V2 ships them (docs/handoff/a3-rust-core-v2.md):
// sign-in test, inventory sync into a read-only folder subtree (Datacenter → Cluster → Host → VM),
// refresh reports with the two-miss delete rule, status, power state and actions (the Rust-native
// dialogs are simulated by `confirmPower` / `confirmTrust`), guest identity and console hand-off.
// Fake inventory only (`*.example.test`, RFC 5737 addresses); no hypervisor is ever contacted.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { ConnectionSummary, Folder, VmPowerState, VsphereConnOptions, VsphereIpc, VsphereSyncReport } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { MockKubeBase } from "./ipc.mock.kube";
import { normalizeOptions } from "./validate.options";

/** `[datacenter, cluster, host, vms[]]` of the fake vCenter; a VM has Tools iff it has an address. */
const INVENTORY: [string, string, string, [string, VmPowerState, string | null][]][] = [
  ["DC-East", "compute-a", "esx01.example.test", [["app-vm-01", "POWERED_ON", "192.0.2.21"], ["app-vm-02", "POWERED_ON", "192.0.2.22"]]],
  ["DC-East", "compute-a", "esx02.example.test", [["db-vm-01", "POWERED_ON", "192.0.2.31"], ["build-vm", "POWERED_OFF", null]]],
  ["DC-East", "Standalone hosts", "esx-lab.example.test", [["sandbox-vm", "SUSPENDED", "198.51.100.40"]]],
];

type TreeMutator = "folderCreate" | "folderRename" | "folderMove" | "folderDelete" | "connectionCreate" | "connectionUpdate" | "connectionMove" | "connectionDelete";

interface MockVc {
  lastRefresh: string | null;
  lastError: string | null;
  lastReport: VsphereSyncReport | null;
  power: Map<string, VmPowerState>;
}

const READONLY = () => new IpcError("tree.synced_readonly", "this folder is synced from vCenter and is read-only");
const NOT_SYNCED = () => new IpcError("vsphere.not_found", "inventory sync is not enabled for this connection");

export abstract class MockVsphereBase extends MockKubeBase implements VsphereIpc {
  abstract folders: Folder[];
  abstract connections: ConnectionSummary[];
  vcenters = new Map<string, MockVc>();
  /** What the Rust-native power / VMRC confirmation answers (tests flip it). */
  confirmPower = true;
  /** What the Rust-native TOFU certificate dialog answers on a manual refresh. */
  confirmTrust = true;
  /** External ids (`vm-build-vm`) the fake vCenter stops reporting: missing, then deleted. */
  vsphereHidden = new Set<string>();
  /** vCenter ids whose certificate is not pinned: the scheduler stops with `http.trust_prompt`. */
  vsphereUntrusted = new Set<string>();
  /** vCenter ids that refuse every call with `vsphere.unavailable`. */
  vsphereDown = new Set<string>();
  private vsIds = 0;

  private vsId(prefix: string): string {
    this.vsIds += 1;
    return `${prefix}-vs${this.vsIds.toString(16).padStart(3, "0")}`;
  }

  private vcenter(connectionId: string): ConnectionSummary {
    const c = this.connections.find((x) => x.id === connectionId);
    if (!c) throw new IpcError("tree.not_found", "connection not found");
    if (c.protocol !== "vsphere-console" || c.syncSource) throw new IpcError("input.invalid", "invalid connectionId: not a vCenter connection");
    return c;
  }

  private vm(connectionId: string): { vm: ConnectionSummary; vc: MockVc; options: VsphereConnOptions } {
    const vm = this.connections.find((x) => x.id === connectionId);
    if (!vm) throw new IpcError("tree.not_found", "connection not found");
    const vc = vm.syncSource ? this.vcenters.get(vm.syncSource) : undefined;
    const owner = this.connections.find((x) => x.id === vm.syncSource);
    if (!vc || !owner || !vm.externalId?.startsWith("vm-")) throw new IpcError("input.invalid", "invalid connectionId: not a synced VM");
    if (vm.syncState === "missing") throw new IpcError("vsphere.not_found", "vCenter no longer reports this VM");
    if (this.vsphereDown.has(owner.id)) throw new IpcError("vsphere.unavailable", "vCenter did not answer");
    return { vm, vc, options: normalizeOptions("vsphere-console", owner.options ?? {}) as VsphereConnOptions };
  }

  /** Whether a folder lives in a synced subtree (the read-only rule of ADR-0015 §2). */
  private synced(folderId: string | null | undefined): boolean {
    return this.folders.some((f) => f.id === folderId && f.syncSource);
  }

  private rootOf(connectionId: string): Folder | undefined {
    return this.folders.find((f) => f.syncSource === connectionId && !f.externalId);
  }

  /** Wraps the tree mutators of MockTransport with the store's `tree.synced_readonly` rule. */
  protected guardSyncedTree(): void {
    type Args = { id?: string; parentId?: string; folderId?: string } & Partial<ConnectionSummary>;
    const blocked: Record<TreeMutator, (a: Args) => boolean> = {
      folderCreate: (a) => this.synced(a.parentId),
      folderRename: (a) => this.synced(a.id),
      folderMove: (a) => this.synced(a.id) || this.synced(a.parentId),
      folderDelete: (a) => this.synced(a.id),
      connectionCreate: (a) => this.synced(a.folderId),
      connectionMove: (a) => this.synced(this.rowFolder(a.id)) || this.synced(a.folderId),
      connectionDelete: (a) => this.synced(this.rowFolder(a.id)),
      // Overlays (credential, tags, overrides, options) stay editable; identity fields do not.
      connectionUpdate: (a) => {
        const c = this.connections.find((x) => x.id === a.id);
        if (!c?.syncSource) return this.synced(a.folderId);
        return a.name !== c.name || a.host !== c.host || a.port !== c.port || a.protocol !== c.protocol || a.folderId !== c.folderId;
      },
    };
    const self = this as unknown as Record<TreeMutator, (a: Args) => Promise<unknown>>;
    for (const name of Object.keys(blocked) as TreeMutator[]) {
      const inner = self[name];
      self[name] = async (a: Args) => {
        if (blocked[name](a)) throw READONLY();
        return inner(a);
      };
    }
    // `syncFolderId` is derived from the synced root, never stored: writes cannot change it.
    const setOptions = this.connectionOptionsSet;
    this.connectionOptionsSet = async (a) => {
      const stored = await setOptions(a);
      const c = this.connections.find((x) => x.id === a.connectionId);
      if (c?.protocol !== "vsphere-console" || c.syncSource) return stored;
      c.options = { ...(stored as VsphereConnOptions), syncFolderId: this.rootOf(c.id)?.id ?? null };
      return { ...c.options };
    };
  }

  private rowFolder(id: string | undefined): string | undefined {
    return this.connections.find((c) => c.id === id)?.folderId;
  }

  vsphereTest: VsphereIpc["vsphereTest"] = async ({ connectionId }) => {
    await this.unlocked();
    const c = this.vcenter(connectionId);
    if (this.vsphereDown.has(connectionId)) throw new IpcError("vsphere.unavailable", "vCenter did not answer");
    if (!c.effectiveCredentialId && !c.credentialId) throw new IpcError("vsphere.auth_failed", "vCenter refused the sign-in");
    return { version: "8.0.3.00400", build: "24322831", user: "administrator@vsphere.local" };
  };

  vsphereSyncEnable: VsphereIpc["vsphereSyncEnable"] = async ({ connectionId, parentFolderId }) => {
    await this.unlocked();
    const c = this.vcenter(connectionId);
    const existing = this.rootOf(connectionId);
    if (existing) return { ...existing }; // idempotent (store test)
    if (!this.folders.some((f) => f.id === parentFolderId)) throw new IpcError("tree.not_found", "folder not found");
    if (this.synced(parentFolderId)) throw READONLY();
    const root: Folder = { id: this.vsId("f"), parentId: parentFolderId, name: c.name, defaultCredentialId: null, sort: 99, syncSource: connectionId, externalId: null };
    this.folders.push(root);
    this.vcenters.set(connectionId, { lastRefresh: null, lastError: null, lastReport: null, power: new Map() });
    c.options = { ...(normalizeOptions("vsphere-console", c.options ?? {}) as VsphereConnOptions), syncFolderId: root.id };
    try {
      await this.runRefresh(connectionId, "import");
    } catch (e: unknown) {
      // A failed first import removes the empty root again (V2 decision 5).
      this.folders = this.folders.filter((f) => f.id !== root.id);
      this.vcenters.delete(connectionId);
      c.options = { ...c.options, syncFolderId: null };
      throw e;
    }
    return { ...root };
  };

  vsphereSyncDisable: VsphereIpc["vsphereSyncDisable"] = async ({ connectionId, keep }) => {
    await this.unlocked();
    const c = this.vcenter(connectionId);
    if (!this.vcenters.delete(connectionId)) throw NOT_SYNCED();
    const ids = new Set(this.folders.filter((f) => f.syncSource === connectionId).map((f) => f.id));
    if (keep) {
      for (const f of this.folders) if (ids.has(f.id)) Object.assign(f, { syncSource: null, externalId: null });
      for (const x of this.connections) if (x.syncSource === connectionId) Object.assign(x, { syncSource: null, externalId: null, syncState: null });
    } else {
      this.folders = this.folders.filter((f) => !ids.has(f.id));
      this.connections = this.connections.filter((x) => x.syncSource !== connectionId);
    }
    c.options = { ...(normalizeOptions("vsphere-console", c.options ?? {}) as VsphereConnOptions), syncFolderId: null };
  };

  vsphereRefresh: VsphereIpc["vsphereRefresh"] = async ({ connectionId }) => {
    await this.unlocked();
    this.vcenter(connectionId);
    if (!this.vcenters.has(connectionId)) throw NOT_SYNCED();
    if (this.vsphereUntrusted.has(connectionId)) {
      // Manual: the TOFU dialog is shown by Rust; "Trust" pins and the refresh goes on.
      if (!this.confirmTrust) throw new IpcError("http.trust_rejected", "you rejected the vCenter certificate");
      this.vsphereUntrusted.delete(connectionId);
      this.record("cert_decision", { protocol: "vsphere", connection: connectionId, decision: "trust" });
    }
    return this.runRefresh(connectionId, "manual");
  };

  /** What the scheduler does at its interval: a TOFU prompt cannot be shown, so it stops with `http.trust_prompt`. */
  async vsphereScheduledTick(connectionId: string): Promise<void> {
    const vc = this.vcenters.get(connectionId);
    if (!vc) return;
    if (this.vsphereUntrusted.has(connectionId)) {
      vc.lastError = "http.trust_prompt";
      this.record("vsphere_sync_failed", { connection: connectionId, code: "http.trust_prompt" });
      return;
    }
    try {
      await this.runRefresh(connectionId, "schedule");
    } catch {
      // recorded on the status already
    }
  }

  private async runRefresh(connectionId: string, trigger: "manual" | "schedule" | "import"): Promise<VsphereSyncReport> {
    const vc = this.vcenters.get(connectionId);
    const root = this.rootOf(connectionId);
    if (!vc || !root) throw NOT_SYNCED();
    this.record("vsphere_sync_started", { connection: connectionId, trigger });
    if (this.vsphereDown.has(connectionId)) {
      vc.lastError = "vsphere.unavailable";
      this.record("vsphere_sync_failed", { connection: connectionId, code: vc.lastError });
      throw new IpcError("vsphere.unavailable", "vCenter did not answer");
    }
    const report = { added: 0, changed: 0, missing: 0, deleted: 0, at: new Date().toISOString() };
    const seen = new Set<string>();
    const folderFor = (parentId: string, externalId: string, name: string) => {
      let f = this.folders.find((x) => x.syncSource === connectionId && x.externalId === externalId);
      if (!f) {
        f = { id: this.vsId("f"), parentId, name, defaultCredentialId: null, sort: 0, syncSource: connectionId, externalId };
        this.folders.push(f);
      }
      return f.id;
    };
    for (const [dc, cluster, host, vms] of INVENTORY) {
      const hostFolder = folderFor(folderFor(folderFor(root.id, `datacenter-${dc}`, dc), `cluster-${cluster}`, cluster), `host-${host}`, host);
      for (const [name, power, ip] of vms) {
        const externalId = `vm-${name}`;
        if (this.vsphereHidden.has(externalId)) continue;
        seen.add(externalId);
        vc.power.set(externalId, vc.power.get(externalId) ?? power);
        const row = this.connections.find((x) => x.syncSource === connectionId && x.externalId === externalId);
        if (row) {
          if (row.syncState === "missing") { row.syncState = "present"; report.changed += 1; }
          continue;
        }
        report.added += 1;
        const now = report.at;
        this.connections.push({
          id: this.vsId("c"), folderId: hostFolder, name, protocol: "vsphere-console", host: ip ?? `${name}.example.test`, port: null,
          credentialId: null, effectiveCredentialId: null, usernameOverride: null, domainOverride: null, gatewayCredentialId: null,
          becomeCredentialId: null, tags: [], syncSource: connectionId, externalId, syncState: "present", createdAt: now, updatedAt: now,
        });
      }
    }
    // The two-miss rule: first miss marks `missing`, the second deletes the row with its overlays.
    for (const row of this.connections.filter((x) => x.syncSource === connectionId && x.externalId && !seen.has(x.externalId))) {
      if (row.syncState === "present") { row.syncState = "missing"; report.missing += 1; }
      else { this.connections = this.connections.filter((x) => x.id !== row.id); report.deleted += 1; }
    }
    vc.lastRefresh = report.at;
    vc.lastError = null;
    vc.lastReport = report;
    this.record("vsphere_sync_finished", { connection: connectionId, added: String(report.added), changed: String(report.changed), missing: String(report.missing), removed: String(report.deleted), ms: "0" });
    return { ...report };
  }

  vsphereStatus: VsphereIpc["vsphereStatus"] = async ({ connectionId }) => {
    const c = this.vcenter(connectionId);
    const vc = this.vcenters.get(connectionId);
    const options = normalizeOptions("vsphere-console", c.options ?? {}) as VsphereConnOptions;
    return {
      lastRefresh: vc?.lastRefresh ?? null, lastError: vc?.lastError ?? null, running: false, lastReport: vc?.lastReport ?? null,
      scheduled: vc !== undefined && options.refreshMinutes !== null && this.vault === "unlocked",
    };
  };

  vsphereVmPower: VsphereIpc["vsphereVmPower"] = async ({ connectionId }) => {
    const { vm, vc } = this.vm(connectionId);
    return { state: vc.power.get(vm.externalId ?? "") ?? "POWERED_OFF" };
  };

  vsphereVmAction: VsphereIpc["vsphereVmAction"] = async ({ connectionId, action }) => {
    await this.unlocked();
    const { vm, vc, options } = this.vm(connectionId);
    const key = vm.externalId ?? "";
    const audit = (outcome: string) => { this.record("vsphere_power", { connection: vm.syncSource ?? "", vm: key, action, outcome }); };
    if (!options.allowPowerActions) {
      audit("power_disabled");
      throw new IpcError("vsphere.power_disabled", "power actions are off for this vCenter");
    }
    if (!this.confirmPower) {
      audit("cancelled");
      return { outcome: "cancelled" };
    }
    audit("requested");
    const state = vc.power.get(key) ?? "POWERED_OFF";
    const guest = action === "shutdown" || action === "reboot";
    if (guest && state !== "POWERED_ON") { audit("vsphere.wrong_state"); throw new IpcError("vsphere.wrong_state", "the VM is not powered on"); }
    if (guest && !/^\d+\.\d+\.\d+\.\d+$/.test(vm.host)) { audit("vsphere.tools_missing"); throw new IpcError("vsphere.tools_missing", "VMware Tools are not running in this VM"); }
    const wantOn = action === "start" || action === "reboot" || action === "reset";
    const already = (action === "start" && state === "POWERED_ON") || ((action === "stop" || action === "shutdown") && state === "POWERED_OFF");
    vc.power.set(key, wantOn ? "POWERED_ON" : "POWERED_OFF");
    audit(already ? "already" : "done");
    return { outcome: "done" };
  };

  vsphereVmIdentity: VsphereIpc["vsphereVmIdentity"] = async ({ connectionId }) => {
    const { vm, vc } = this.vm(connectionId);
    if (vc.power.get(vm.externalId ?? "") !== "POWERED_ON") throw new IpcError("vsphere.tools_missing", "VMware Tools are not running in this VM");
    const ip = /^\d+\.\d+\.\d+\.\d+$/.test(vm.host) ? vm.host : null;
    return { hostName: `${vm.name}.example.test`, ip, family: "LINUX" };
  };

  vsphereConsole: VsphereIpc["vsphereConsole"] = async ({ connectionId, kind }) => {
    await this.unlocked();
    const { vm, options } = this.vm(connectionId);
    if (kind === "vmrc") {
      if (!options.allowVmrc) throw new IpcError("vsphere.vmrc_disabled", "VMware Remote Console hand-off is off for this vCenter");
      if (!this.confirmPower) throw new IpcError("vsphere.not_confirmed", "you cancelled the hand-off");
    }
    this.record("vsphere_console", { vm: vm.externalId ?? "", kind });
    return { windowLabel: kind === "client" ? `web-${vm.syncSource ?? ""}` : null };
  };
}

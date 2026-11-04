// Mock ADR-0015 vSphere commands: sign-in test, inventory sync into a read-only folder subtree
// (Datacenter → Cluster → Host → VM), refresh reports, power state and actions (the "native
// dialog" is simulated by `confirmPower`), guest identity and console hand-off. Fake inventory
// only (`*.example.test`, RFC 5737 addresses); no hypervisor is ever contacted.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { ConnectionSummary, Folder, VmPowerState, VsphereConnOptions, VsphereIpc } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { MockKubeBase } from "./ipc.mock.kube";
import { normalizeOptions } from "./validate.options";

/** `[datacenter, cluster, host, vms[]]` of the fake vCenter. */
const INVENTORY: [string, string, string, [string, VmPowerState, string | null][]][] = [
  ["DC-East", "compute-a", "esx01.example.test", [["app-vm-01", "POWERED_ON", "192.0.2.21"], ["app-vm-02", "POWERED_ON", "192.0.2.22"]]],
  ["DC-East", "compute-a", "esx02.example.test", [["db-vm-01", "POWERED_ON", "192.0.2.31"], ["build-vm", "POWERED_OFF", null]]],
  ["DC-East", "Standalone hosts", "esx-lab.example.test", [["sandbox-vm", "SUSPENDED", "198.51.100.40"]]],
];

type TreeMutator = "folderCreate" | "folderRename" | "folderMove" | "folderDelete" | "connectionCreate" | "connectionUpdate" | "connectionMove" | "connectionDelete";

interface MockVc {
  lastRefresh: string | null;
  lastError: string | null;
  power: Map<string, VmPowerState>;
}

export abstract class MockVsphereBase extends MockKubeBase implements VsphereIpc {
  abstract folders: Folder[];
  abstract connections: ConnectionSummary[];
  vcenters = new Map<string, MockVc>();
  /** What the Rust-native confirmation dialog answers (tests flip it). */
  confirmPower = true;
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
    return { vm, vc, options: normalizeOptions("vsphere-console", owner.options ?? {}) as VsphereConnOptions };
  }

  /** Whether a folder or connection lives in a synced subtree (the read-only rule of ADR-0015 §2). */
  private synced(folderId: string | null | undefined): boolean {
    return this.folders.some((f) => f.id === folderId && f.syncSource);
  }

  /** Wraps the tree mutators of MockTransport with the store's `tree.synced_readonly` rule. */
  protected guardSyncedTree(): void {
    const refuse = () => { throw new IpcError("tree.synced_readonly", "this folder is synced from vCenter and is read-only"); };
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
        if (blocked[name](a)) refuse();
        return inner(a);
      };
    }
  }

  private rowFolder(id: string | undefined): string | undefined {
    return this.connections.find((c) => c.id === id)?.folderId;
  }

  vsphereTest: VsphereIpc["vsphereTest"] = async ({ connectionId }) => {
    await this.unlocked();
    const c = this.vcenter(connectionId);
    if (!c.effectiveCredentialId && !c.credentialId) throw new IpcError("vsphere.auth_failed", "vCenter refused the sign-in");
    return { version: "8.0.3", build: "24322831", user: "administrator@vsphere.local" };
  };

  vsphereSyncEnable: VsphereIpc["vsphereSyncEnable"] = async ({ connectionId, parentFolderId }) => {
    await this.unlocked();
    const c = this.vcenter(connectionId);
    if (!this.folders.some((f) => f.id === parentFolderId)) throw new IpcError("tree.not_found", "folder not found");
    if (this.synced(parentFolderId)) throw new IpcError("tree.synced_readonly", "this folder is synced from vCenter and is read-only");
    if (this.vcenters.has(connectionId)) throw new IpcError("input.invalid", "invalid connectionId: sync is already on");
    const root: Folder = { id: this.vsId("f"), parentId: parentFolderId, name: c.name, defaultCredentialId: null, sort: 99, syncSource: connectionId, externalId: null };
    this.folders.push(root);
    this.vcenters.set(connectionId, { lastRefresh: null, lastError: null, power: new Map() });
    c.options = { ...(normalizeOptions("vsphere-console", c.options ?? {}) as VsphereConnOptions), syncFolderId: root.id };
    await this.vsphereRefresh({ connectionId });
    return { ...root };
  };

  vsphereSyncDisable: VsphereIpc["vsphereSyncDisable"] = async ({ connectionId, keep }) => {
    await this.unlocked();
    this.vcenter(connectionId);
    if (!this.vcenters.delete(connectionId)) throw new IpcError("input.invalid", "invalid connectionId: sync is off");
    const ids = new Set(this.folders.filter((f) => f.syncSource === connectionId).map((f) => f.id));
    if (keep) {
      for (const f of this.folders) if (ids.has(f.id)) Object.assign(f, { syncSource: null, externalId: null });
      for (const c of this.connections) if (c.syncSource === connectionId) Object.assign(c, { syncSource: null, externalId: null, syncState: null });
    } else {
      this.folders = this.folders.filter((f) => !ids.has(f.id));
      this.connections = this.connections.filter((c) => c.syncSource !== connectionId);
    }
  };

  vsphereRefresh: VsphereIpc["vsphereRefresh"] = async ({ connectionId }) => {
    await this.unlocked();
    this.vcenter(connectionId);
    const vc = this.vcenters.get(connectionId);
    const rootId = this.folders.find((f) => f.syncSource === connectionId && f.externalId === null)?.id;
    if (!vc || !rootId) throw new IpcError("input.invalid", "invalid connectionId: sync is off");
    let added = 0;
    const folderFor = (parentId: string, externalId: string, name: string) => {
      let f = this.folders.find((x) => x.syncSource === connectionId && x.externalId === externalId);
      if (!f) {
        f = { id: this.vsId("f"), parentId, name, defaultCredentialId: null, sort: 0, syncSource: connectionId, externalId };
        this.folders.push(f);
      }
      return f.id;
    };
    for (const [dc, cluster, host, vms] of INVENTORY) {
      const hostFolder = folderFor(folderFor(folderFor(rootId, `datacenter-${dc}`, dc), `cluster-${cluster}`, cluster), `host-${host}`, host);
      for (const [name, power, ip] of vms) {
        const externalId = `vm-${name}`;
        vc.power.set(externalId, vc.power.get(externalId) ?? power);
        if (this.connections.some((c) => c.syncSource === connectionId && c.externalId === externalId)) continue;
        added += 1;
        const now = new Date().toISOString();
        this.connections.push({
          id: this.vsId("c"), folderId: hostFolder, name, protocol: "vsphere-console", host: ip ?? `${name}.example.test`, port: null,
          credentialId: null, effectiveCredentialId: null, usernameOverride: null, domainOverride: null, gatewayCredentialId: null,
          becomeCredentialId: null, tags: [], syncSource: connectionId, externalId, syncState: "present", createdAt: now, updatedAt: now,
        });
      }
    }
    vc.lastRefresh = new Date().toISOString();
    vc.lastError = null;
    this.record("vsphere.sync", { connection: connectionId, added: String(added), changed: "0", missing: "0", deleted: "0" });
    return { added, changed: 0, missing: 0, deleted: 0, at: vc.lastRefresh };
  };

  vsphereStatus: VsphereIpc["vsphereStatus"] = async ({ connectionId }) => {
    this.vcenter(connectionId);
    const vc = this.vcenters.get(connectionId);
    return { lastRefresh: vc?.lastRefresh ?? null, lastError: vc?.lastError ?? null, running: false };
  };

  vsphereVmPower: VsphereIpc["vsphereVmPower"] = async ({ connectionId }) => {
    const { vm, vc } = this.vm(connectionId);
    return { state: vc.power.get(vm.externalId ?? "") ?? "POWERED_OFF" };
  };

  vsphereVmAction: VsphereIpc["vsphereVmAction"] = async ({ connectionId, action }) => {
    await this.unlocked();
    const { vm, vc, options } = this.vm(connectionId);
    if (!options.allowPowerActions) throw new IpcError("vsphere.power_disabled", "power actions are off for this vCenter");
    const key = vm.externalId ?? "";
    const state = vc.power.get(key) ?? "POWERED_OFF";
    if ((action === "shutdown" || action === "reboot") && state === "POWERED_ON" && vm.host.endsWith(".example.test")) {
      throw new IpcError("vsphere.tools_missing", "VMware Tools are not running in this VM");
    }
    const outcome = this.confirmPower ? "done" : "cancelled";
    this.record("vsphere.power", { connection: vm.syncSource ?? "", vm: key, action, outcome });
    if (outcome === "done") vc.power.set(key, action === "start" || action === "reboot" || action === "reset" ? "POWERED_ON" : "POWERED_OFF");
    return { outcome };
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
    if (kind === "vmrc" && !options.allowVmrc) throw new IpcError("input.invalid", "invalid kind: VMRC hand-off is off for this vCenter");
    this.record("vsphere.console", { vm: vm.externalId ?? "", kind });
    return { windowLabel: kind === "client" ? `web-${vm.syncSource ?? ""}` : null };
  };
}

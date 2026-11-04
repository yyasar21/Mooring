// DTOs of the ADR-0015 IPC contract as rust-core V2 ships it (docs/handoff/a3-rust-core-v2.md):
// vSphere inventory sync into a read-only folder subtree, power state and actions (confirmed in a
// Rust-native dialog: the UI only requests), guest identity and consoles.
import type { Folder } from "./ipc.types";

export interface VsphereConnOptions {
  /** Derived from the synced root by Rust; ignored on write, read-only in the form. */
  syncFolderId: string | null;
  /** 15..=1440, default 60; null = manual refresh only. */
  refreshMinutes: number | null;
  /** Off by default; enabling it is audited at warning severity (weakened). */
  allowPowerActions: boolean;
  /** Owner decision 7: VMRC hand-off opt-in per connection; enabling it is audited too. */
  allowVmrc: boolean;
  /** VMCA root, certificates only. */
  caPem: string | null;
}

export const VSPHERE_LIMITS = { minRefresh: 15, maxRefresh: 1440, defaultRefresh: 60 } as const;

export const DEFAULT_VSPHERE_OPTIONS: VsphereConnOptions = {
  syncFolderId: null,
  refreshMinutes: VSPHERE_LIMITS.defaultRefresh,
  allowPowerActions: false,
  allowVmrc: false,
  caPem: null,
};

/**
 * Tree rows inside a synced subtree carry these (migration 0006). Absent keys = an ordinary row.
 * `syncSource` is also set on the synced root; `externalId` is absent on the root.
 */
export interface SyncedRowFlags {
  /** Connection id of the vCenter; null/absent = a normal row. */
  syncSource?: string | null;
  /** `datacenter-1`, `domain-c1`, `standalone-datacenter-1`, `host-7`, `vm-42`. */
  externalId?: string | null;
}
/** `missing` = vCenter no longer reports the VM; a second miss deletes the row. */
export type SyncState = "present" | "missing";

export interface VsphereTestResult {
  version: string;
  build: string;
  user: string;
}

export interface VsphereSyncReport {
  added: number;
  changed: number;
  missing: number;
  deleted: number;
  at: string;
}

export interface VsphereStatus {
  lastRefresh: string | null;
  /** An error code (`vsphere.rate_limited`, `http.trust_prompt`, …), not a message. */
  lastError: string | null;
  running: boolean;
  lastReport: VsphereSyncReport | null;
  /** A scheduler task exists (sync on, `refreshMinutes` set, vault unlocked). */
  scheduled: boolean;
}

export type VmPowerState = "POWERED_ON" | "POWERED_OFF" | "SUSPENDED";
export const VM_POWER_STATES: readonly VmPowerState[] = ["POWERED_ON", "POWERED_OFF", "SUSPENDED"];

/** Owner decision 6: all five, each behind the opt-in and the native dialog. */
export type VmAction = "start" | "shutdown" | "reboot" | "stop" | "reset";
export const VM_ACTIONS: readonly VmAction[] = ["start", "shutdown", "reboot", "stop", "reset"];
/** Hard power off / reset: "like pulling the plug", the dialog adds the data-loss warning. */
export const DESTRUCTIVE_VM_ACTIONS: readonly VmAction[] = ["stop", "reset"];

export interface VmIdentity {
  hostName: string | null;
  ip: string | null;
  /** `LINUX`, `WINDOWS`, … as vCenter reports it. */
  family: string | null;
}

export type VsphereConsoleKind = "client" | "vmrc";

export interface VsphereIpc {
  /** Login + logout only. */
  vsphereTest(args: { connectionId: string }): Promise<VsphereTestResult>;
  /** Creates the root named after the connection under `parentFolderId` and runs the import; a failed import removes the root again. */
  vsphereSyncEnable(args: { connectionId: string; parentFolderId: string }): Promise<Folder>;
  /** `keep: true` detaches the subtree into normal folders and connections. */
  vsphereSyncDisable(args: { connectionId: string; keep: boolean }): Promise<void>;
  vsphereRefresh(args: { connectionId: string }): Promise<VsphereSyncReport>;
  /** Passive (POLLED_COMMANDS). */
  vsphereStatus(args: { connectionId: string }): Promise<VsphereStatus>;
  /** Passive (POLLED_COMMANDS). `connectionId` is the VM row; Rust caches the answer 10 s. */
  vsphereVmPower(args: { connectionId: string }): Promise<{ state: VmPowerState }>;
  /** Rust shows the native confirmation; `cancelled` = the user said no there. */
  vsphereVmAction(args: { connectionId: string; action: VmAction }): Promise<{ outcome: "done" | "cancelled" }>;
  vsphereVmIdentity(args: { connectionId: string }): Promise<VmIdentity>;
  /** `client` opens (or re-navigates) the `web-<vCenterId>` window; `vmrc` is handed to the OS by Rust and returns null. */
  vsphereConsole(args: { connectionId: string; kind: VsphereConsoleKind }): Promise<{ windowLabel: string | null }>;
}

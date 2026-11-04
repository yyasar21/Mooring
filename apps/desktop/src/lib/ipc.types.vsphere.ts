// DTOs of the ADR-0015 IPC contract: vSphere inventory sync into a read-only folder subtree,
// power state and actions (confirmed in a Rust-native dialog: the UI only requests), consoles.
// Shapes marked ASSUMED are not spelled out in the ADR; see docs/handoff/a3-ui-u1.md.
import type { Folder } from "./ipc.types";

export interface VsphereConnOptions {
  /** Set by `vsphere_sync_enable`; read-only in the form. */
  syncFolderId: string | null;
  /** 15..=1440, default 60; null = manual refresh only. */
  refreshMinutes: number | null;
  /** Off by default; enabling it is audited at warning severity. */
  allowPowerActions: boolean;
  /** ASSUMED field name for owner decision 7 (VMRC hand-off opt-in per connection). */
  allowVmrc: boolean;
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

/** ASSUMED: tree rows inside a synced subtree carry these (migration 0006 columns). */
export interface SyncedRowFlags {
  /** Connection id of the vCenter; null/absent = a normal row. */
  syncSource?: string | null;
  /** `vm-42`, `host-7`, … */
  externalId?: string | null;
}
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
  lastError: string | null;
  running: boolean;
}

export type VmPowerState = "POWERED_ON" | "POWERED_OFF" | "SUSPENDED";
export const VM_POWER_STATES: readonly VmPowerState[] = ["POWERED_ON", "POWERED_OFF", "SUSPENDED"];

/** Owner decision 6: all five, each behind the opt-in and the native dialog. */
export type VmAction = "start" | "shutdown" | "reboot" | "stop" | "reset";
export const VM_ACTIONS: readonly VmAction[] = ["start", "shutdown", "reboot", "stop", "reset"];

export interface VmIdentity {
  hostName: string | null;
  ip: string | null;
  family: string | null;
}

export type VsphereConsoleKind = "client" | "vmrc";

export interface VsphereIpc {
  vsphereTest(args: { connectionId: string }): Promise<VsphereTestResult>;
  vsphereSyncEnable(args: { connectionId: string; parentFolderId: string }): Promise<Folder>;
  /** `keep: true` detaches the subtree into normal folders. */
  vsphereSyncDisable(args: { connectionId: string; keep: boolean }): Promise<void>;
  vsphereRefresh(args: { connectionId: string }): Promise<VsphereSyncReport>;
  /** Passive (POLLED_COMMANDS). */
  vsphereStatus(args: { connectionId: string }): Promise<VsphereStatus>;
  /** Passive (POLLED_COMMANDS). `connectionId` is the VM's connection. */
  vsphereVmPower(args: { connectionId: string }): Promise<{ state: VmPowerState }>;
  /** Rust shows the native confirmation; `cancelled` = the user said no there. */
  vsphereVmAction(args: { connectionId: string; action: VmAction }): Promise<{ outcome: "done" | "cancelled" }>;
  vsphereVmIdentity(args: { connectionId: string }): Promise<VmIdentity>;
  vsphereConsole(args: { connectionId: string; kind: VsphereConsoleKind }): Promise<{ windowLabel: string | null }>;
}

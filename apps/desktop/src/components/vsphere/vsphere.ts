// Pure helpers for the vSphere UI (ADR-0015): which rows are synced, what the user may still
// change there, power-action wording and the schedule arithmetic of the status panel.
import type { ConnectionSummary, Folder, VmAction, VmPowerState, VsphereConnOptions } from "../../lib/ipc";
import { DESTRUCTIVE_VM_ACTIONS } from "../../lib/ipc";

/** A vCenter connection: the `vsphere-console` row that is not itself inside a synced subtree. */
export const isVcenter = (c: ConnectionSummary | undefined): boolean => c?.protocol === "vsphere-console" && !c.syncSource;
/** A VM row imported by a vCenter. */
export const isSyncedVm = (c: ConnectionSummary | undefined): boolean => !!c?.syncSource && c.protocol === "vsphere-console";
export const isSyncedFolder = (f: Folder | undefined): boolean => !!f?.syncSource;
/** The synced root: `syncSource` set, no `externalId`. */
export const isSyncedRoot = (f: Folder | undefined): boolean => !!f?.syncSource && !f.externalId;

export const syncedRootOf = (folders: Folder[], vcenterId: string): Folder | undefined => folders.find((f) => f.syncSource === vcenterId && !f.externalId);

/** Why a row cannot be renamed, moved, deleted or given children. */
export const READONLY_REASON = "Synced from vCenter: this item is read-only. Change it in vCenter, then refresh.";

export const POWER_LABEL: Record<VmPowerState, string> = { POWERED_ON: "Powered on", POWERED_OFF: "Powered off", SUSPENDED: "Suspended" };

export interface ActionMeta {
  action: VmAction;
  label: string;
  /** What the native dialog will say, in short. */
  hint: string;
  destructive: boolean;
  /** Needs VMware Tools in the guest. */
  guest: boolean;
}

export const ACTIONS: readonly ActionMeta[] = [
  { action: "start", label: "Power on", hint: "Starts the VM.", destructive: false, guest: false },
  { action: "shutdown", label: "Shut down guest", hint: "Asks the guest OS to shut down (VMware Tools).", destructive: false, guest: true },
  { action: "reboot", label: "Reboot guest", hint: "Asks the guest OS to restart (VMware Tools).", destructive: false, guest: true },
  { action: "stop", label: "Power off", hint: "Like pulling the plug: unsaved data in the guest may be lost.", destructive: true, guest: false },
  { action: "reset", label: "Reset", hint: "Like pressing the reset button: unsaved data in the guest may be lost.", destructive: true, guest: false },
];

export const isDestructive = (a: VmAction): boolean => DESTRUCTIVE_VM_ACTIONS.includes(a);

/** Which actions make sense for a power state; the others are offered disabled with the reason. */
export function actionFit(action: VmAction, state: VmPowerState | null): string | null {
  if (state === null) return null;
  if (action === "start" && state === "POWERED_ON") return "Already powered on.";
  if ((action === "stop" || action === "shutdown") && state === "POWERED_OFF") return "Already powered off.";
  if ((action === "shutdown" || action === "reboot") && state !== "POWERED_ON") return "The guest OS is not running.";
  return null;
}

/** Why the power menu is unavailable, or null when it may open. */
export function powerBlocked(options: VsphereConnOptions | undefined, vcenterName: string): string | null {
  if (!options) return "Loading the vCenter options…";
  if (!options.allowPowerActions) return `Power actions are off for ${vcenterName}. Turn them on in its connection options.`;
  return null;
}

export function vmrcBlocked(options: VsphereConnOptions | undefined, vcenterName: string): string | null {
  if (!options) return "Loading the vCenter options…";
  if (!options.allowVmrc) return `VMware Remote Console is off for ${vcenterName}. Turn it on in its connection options.`;
  return null;
}

/** `lastRefresh + refreshMinutes` (the scheduler adds ±10 % jitter, so "about"). */
export function nextScheduled(lastRefresh: string | null, refreshMinutes: number | null, scheduled: boolean): Date | null {
  if (!scheduled || refreshMinutes === null) return null;
  const last = lastRefresh ? Date.parse(lastRefresh) : NaN;
  if (Number.isNaN(last)) return null;
  return new Date(last + refreshMinutes * 60_000);
}

/** "just now", "4 min ago", "in 2 h", or the clock time for anything further away. */
export function relativeTime(iso: string | Date | null, now = Date.now()): string {
  if (iso === null) return "never";
  const t = typeof iso === "string" ? Date.parse(iso) : iso.getTime();
  if (Number.isNaN(t)) return "unknown";
  const diff = t - now;
  const abs = Math.abs(diff);
  const past = diff < 0;
  const word = (n: number, unit: string) => (past ? `${String(n)} ${unit} ago` : `in ${String(n)} ${unit}`);
  if (abs < 45_000) return past ? "just now" : "any moment";
  if (abs < 3_600_000) return word(Math.round(abs / 60_000), "min");
  if (abs < 86_400_000) return word(Math.round(abs / 3_600_000), "h");
  return new Date(t).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** The vCenter name for a synced row, for badges and reasons. */
export function sourceName(connections: ConnectionSummary[], syncSource: string | null | undefined): string {
  return connections.find((c) => c.id === syncSource)?.name ?? "vCenter";
}

// Polling hooks for the vSphere inspector panels. Both polled commands are passive on the backend
// (`vsphere_status`, `vsphere_vm_power` in POLLED_COMMANDS), so the idle lock still fires; they
// run only while the panel that owns them is mounted, at most every POLL_MS. Each hook keeps its
// own `setInterval` that names its `ipc.*` call so the M-8 tracer (`polled.test.ts`) can see it.
import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { ipc, type VmIdentity, type VmPowerState, type VsphereStatus } from "../../lib/ipc";
import { describeError } from "../../stores/errors";

/** ADR-0015 §3: Rust caches the power state 10 s, so asking more often would not change anything. */
export const POLL_MS = 10_000;

export interface Polled<T> {
  value: T | null;
  error: string | null;
  /** Ask again now (after an action, or on "Refresh"). */
  reload: () => Promise<void>;
}

type Slot<T> = { value: T | null; error: string | null };
const EMPTY = { value: null, error: null };

/** Run one fetch; answers that arrive after `gen` moved on (unmount, new id) are dropped. */
async function settle<T>(fn: () => Promise<T>, gen: { current: number }, set: Dispatch<SetStateAction<Slot<T>>>): Promise<void> {
  const g = gen.current;
  try {
    const value = await fn();
    if (g === gen.current) set({ value, error: null });
  } catch (e: unknown) {
    if (g === gen.current) set((s) => ({ value: s.value, error: describeError(e) }));
  }
}

/** `vsphere_status` of a vCenter while its panel is visible. */
export function useVsphereStatus(connectionId: string, active = true): Polled<VsphereStatus> {
  const [slot, setSlot] = useState<Slot<VsphereStatus>>(EMPTY);
  const gen = useRef(0);
  const reloadStatus = useCallback(() => settle(() => ipc.vsphereStatus({ connectionId }), gen, setSlot), [connectionId]);
  useEffect(() => {
    gen.current += 1;
    setSlot(EMPTY);
    if (!active) return;
    void reloadStatus();
    const t = setInterval(() => { void reloadStatus(); }, POLL_MS);
    return () => {
      gen.current += 1;
      clearInterval(t);
    };
  }, [active, reloadStatus]);
  return { ...slot, reload: reloadStatus };
}

/** `vsphere_vm_power` of a VM row while its inspector is visible. */
export function useVmPower(vmId: string, active = true): Polled<VmPowerState> {
  const [slot, setSlot] = useState<Slot<VmPowerState>>(EMPTY);
  const gen = useRef(0);
  const reloadPower = useCallback(() => settle(async () => (await ipc.vsphereVmPower({ connectionId: vmId })).state, gen, setSlot), [vmId]);
  useEffect(() => {
    gen.current += 1;
    setSlot(EMPTY);
    if (!active) return;
    void reloadPower();
    const t = setInterval(() => { void reloadPower(); }, POLL_MS);
    return () => {
      gen.current += 1;
      clearInterval(t);
    };
  }, [active, reloadPower]);
  return { ...slot, reload: reloadPower };
}

/** Guest identity, fetched once per VM (ADR-0015 §2: lazily, inspector only) and on demand. */
export function useVmIdentity(vmId: string, active = true): Polled<VmIdentity> & { loading: boolean } {
  const [slot, setSlot] = useState<Slot<VmIdentity>>(EMPTY);
  const [loading, setLoading] = useState(false);
  const gen = useRef(0);
  const reloadIdentity = useCallback(async () => {
    const g = gen.current;
    setLoading(true);
    // An error means "unknown": the identity of an earlier state must not stay on screen.
    await settle(() => ipc.vsphereVmIdentity({ connectionId: vmId }), gen, (s) => { setSlot(typeof s === "function" ? { ...s(EMPTY), value: null } : s); });
    if (g === gen.current) setLoading(false);
  }, [vmId]);
  useEffect(() => {
    gen.current += 1;
    setSlot(EMPTY);
    if (active) void reloadIdentity();
    return () => { gen.current += 1; };
  }, [active, reloadIdentity]);
  return { ...slot, loading, reload: reloadIdentity };
}

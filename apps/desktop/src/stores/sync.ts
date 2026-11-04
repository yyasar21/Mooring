import { create } from "zustand";
import { ipc, type SyncConfig, type SyncOutcome, type SyncStatus } from "../lib/ipc";
import { describeError } from "./errors";

/**
 * ADR-0017 vault sync status. `sync_status` is passive and read once per mount; afterwards the
 * `sync:status` event carries every change (S2). Nothing in the status is secret: config, counters,
 * timestamps, the last error and the conflict names of the last merge.
 */
interface SyncState {
  status: SyncStatus | null;
  error: string | null;
  /** The last manual action's result, for the card's outcome line. */
  notice: string | null;
  busy: boolean;
  /** `alarmKey` of the alarm the user dismissed from the shell banner; cleared on reset (lock). */
  dismissed: string | null;

  load: () => Promise<void>;
  /** Subscribe to `sync:status`; returns unsubscribe. */
  watch: () => () => void;
  /** Hide the shell banner for the current alarm; the next alarm (or a changed one) shows again. */
  dismiss: () => void;
  configure: (config: SyncConfig) => Promise<boolean>;
  syncNow: () => Promise<SyncOutcome | null>;
  resolve: (keep: "local" | "remote") => Promise<SyncOutcome | null>;
  disable: (deleteRemote: boolean) => Promise<boolean>;
  reset: () => void;
}

export function describeOutcome(o: SyncOutcome): string {
  switch (o.type) {
    case "pushed":
      return `Pushed generation ${o.counter}.`;
    case "pulled":
      return `Pulled generation ${o.counter}.`;
    case "merged":
      return o.conflicts.length === 0
        ? `Merged both sides into generation ${o.counter}.`
        : `Merged into generation ${o.counter} with ${o.conflicts.length} conflict${o.conflicts.length === 1 ? "" : "s"} (listed below).`;
    case "noChange":
      return `Nothing to sync; generation ${o.counter} is current.`;
  }
}

/**
 * What the shell banner reacts to: a fork/rollback alarm first, else a failed background run.
 * The key changes whenever the situation does, so a dismissal never hides the next one.
 */
export function alarmKey(s: SyncStatus | null): string | null {
  if (!s) return null;
  if (s.alarm) return s.alarm.type === "fork" ? `fork:${s.alarm.remote}` : `rollback:${s.alarm.remote}:${s.alarm.last}`;
  if (s.lastError) return `error:${s.lastError.code}:${s.lastRunUnix ?? 0}`;
  return null;
}

export const useSync = create<SyncState>((set, get) => {
  async function attempt<T>(fn: () => Promise<T>, done?: (r: T) => string): Promise<T | null> {
    if (get().busy) return null;
    set({ busy: true, error: null, notice: null });
    try {
      const r = await fn();
      set({ notice: done ? done(r) : null });
      return r;
    } catch (e: unknown) {
      set({ error: describeError(e) });
      return null;
    } finally {
      set({ busy: false });
    }
  }

  return {
    status: null,
    error: null,
    notice: null,
    busy: false,
    dismissed: null,

    load: async () => {
      try {
        set({ status: await ipc.syncStatus() });
      } catch (e: unknown) {
        set({ error: describeError(e) });
      }
    },

    watch: () => ipc.onSyncStatus((status) => { set({ status }); }),

    dismiss: () => { set({ dismissed: alarmKey(get().status) }); },

    configure: async (config) => {
      const r = await attempt(() => ipc.syncConfigure(config), () => "Saved. The storage answered and conditional writes work.");
      if (r) await get().load();
      return r !== null;
    },

    syncNow: async () => {
      const r = await attempt(() => ipc.syncNow(), describeOutcome);
      await get().load();
      return r;
    },

    resolve: async (keep) => {
      const r = await attempt(() => ipc.syncResolveFork({ keep }), (o) => `Resolved, keeping the ${keep} copy. ${describeOutcome(o)}`);
      await get().load();
      return r;
    },

    disable: async (deleteRemote) => {
      const r = await attempt(async () => { await ipc.syncDisable({ deleteRemote }); return true; }, () =>
        deleteRemote ? "Sync is off and the bucket objects were deleted." : "Sync is off. The bucket objects were left in place.");
      await get().load();
      return r === true;
    },

    reset: () => { set({ status: null, error: null, notice: null, busy: false, dismissed: null }); },
  };
});

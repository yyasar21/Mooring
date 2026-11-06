import { create } from "zustand";
import { ipc, isIpcError, type UpdateInfo, type UpdateSettings } from "../lib/ipc";
import { describeError } from "./errors";

/**
 * ADR-0018 §3 updater state (U0). `update_settings_get` is read once per mount (vault-gated, not
 * passive, never polled); a manual check and the opt-in background check both feed `info`. The
 * title-bar badge follows `info.available` from the `update:available` event until the user
 * looks at the card. Nothing here is a URL, a signature or bytes: only versions and plain text.
 */
interface UpdateState {
  /** Last check result (manual or background); null before any check. */
  info: UpdateInfo | null;
  settings: UpdateSettings | null;
  /** `update.unconfigured`: the build has no updater key; every control is disabled. */
  unconfigured: boolean;
  checking: boolean;
  installing: boolean;
  error: string | null;
  notice: string | null;
  /** The background check found this version and the user has not opened the card since. */
  badge: string | null;

  load: () => Promise<void>;
  /** Subscribe to `update:available`; returns unsubscribe. */
  watch: () => () => void;
  check: () => Promise<void>;
  install: (version: string, closeSessions: boolean) => Promise<boolean>;
  setBackground: (on: boolean) => Promise<void>;
  /** The card is in view: the badge has done its job. */
  seen: () => void;
  reset: () => void;
}

const EMPTY = { info: null, settings: null, unconfigured: false, checking: false, installing: false, error: null, notice: null, badge: null };

export const useUpdate = create<UpdateState>((set, get) => ({
  ...EMPTY,

  load: async () => {
    try {
      set({ settings: await ipc.updateSettingsGet(), unconfigured: false });
    } catch (e: unknown) {
      if (isIpcError(e) && e.code === "update.unconfigured") set({ unconfigured: true, settings: null });
      else set({ error: describeError(e) });
    }
  },

  watch: () => ipc.onUpdateAvailable((info) => { set({ info, badge: info.available?.version ?? null }); }),

  check: async () => {
    if (get().checking || get().installing) return;
    set({ checking: true, error: null, notice: null });
    try {
      const info = await ipc.updateCheck();
      set({ info, badge: null, notice: info.available ? null : "Mooring is up to date." });
      // a successful check moved `lastCheck`
      await get().load();
    } catch (e: unknown) {
      if (isIpcError(e) && e.code === "update.unconfigured") set({ unconfigured: true });
      else set({ error: describeError(e) });
    } finally {
      set({ checking: false });
    }
  },

  install: async (version, closeSessions) => {
    if (get().installing || get().checking) return false;
    set({ installing: true, error: null, notice: "Downloading and verifying the update… Mooring restarts when it is installed." });
    try {
      await ipc.updateInstall({ version, closeSessions });
      return true;
    } catch (e: unknown) {
      set({ error: describeError(e), notice: null });
      return false;
    } finally {
      set({ installing: false });
    }
  },

  setBackground: async (on) => {
    const before = get().settings;
    if (before) set({ settings: { ...before, backgroundCheck: on } }); // optimistic; reverted on failure
    try {
      set({ settings: await ipc.updateSettingsSet({ backgroundCheck: on }), error: null });
    } catch (e: unknown) {
      set({ settings: before, error: describeError(e) });
    }
  },

  seen: () => { if (get().badge !== null) set({ badge: null }); },

  reset: () => { set({ ...EMPTY }); },
}));

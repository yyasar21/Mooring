import { create } from "zustand";
import { ipc, type AppInfo, type VaultStatus } from "../lib/ipc";
import { errorText } from "./errors";
import { useTree } from "./tree";
import { useCredentials } from "./credentials";
import { useSessions } from "./sessions";
import { useUi } from "./ui";

interface AppState {
  info: AppInfo | null;
  vault: VaultStatus | "unknown";
  lastError: string | null;

  boot: () => Promise<void>;
  createVault: (password: string) => Promise<void>;
  unlock: (password: string) => Promise<void>;
  lock: () => Promise<void>;
}

/** Load everything the unlocked shell shows. */
async function loadVaultData(): Promise<void> {
  await Promise.all([useTree.getState().load(), useCredentials.getState().load()]);
}

/** Forget every piece of vault-derived state held in this window. */
function wipe(): void {
  useSessions.getState().reset();
  useTree.getState().reset();
  useCredentials.getState().reset();
  useUi.getState().reset();
}

export const useApp = create<AppState>((set) => ({
  info: null,
  vault: "unknown",
  lastError: null,

  boot: async () => {
    try {
      const [info, vault] = await Promise.all([ipc.appInfo(), ipc.vaultStatus()]);
      set({ info, vault, lastError: null });
      if (vault === "unlocked") await loadVaultData();
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  createVault: async (password) => {
    try {
      const vault = await ipc.vaultCreate(password);
      set({ vault, lastError: null });
      if (vault === "unlocked") await loadVaultData();
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  unlock: async (password) => {
    try {
      const vault = await ipc.vaultUnlock(password);
      set({ vault, lastError: null });
      if (vault === "unlocked") await loadVaultData();
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  lock: async () => {
    try {
      const vault = await ipc.vaultLock("user");
      wipe();
      set({ vault, lastError: null });
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },
}));

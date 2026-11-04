import { create } from "zustand";
import { ipc, type AppInfo, type LockReason, type SessionInfo, type VaultStatus } from "../lib/ipc";
import { errorText } from "./errors";
import { useTree } from "./tree";
import { useCredentials } from "./credentials";
import { useSessions } from "./sessions";
import { useUi } from "./ui";
import { useTransfers } from "./transfers";
import { useSync } from "./sync";
import { adoptWeb } from "./web";

interface AppState {
  info: AppInfo | null;
  vault: VaultStatus | "unknown";
  lastError: string | null;
  /** Why the backend locked the vault on its own (ADR-0010 `vault:locked`); null after a user lock. */
  lockReason: LockReason | "unknown" | null;

  boot: () => Promise<void>;
  createVault: (password: string) => Promise<void>;
  unlock: (password: string) => Promise<void>;
  lock: () => Promise<void>;
  adoptJoined: () => Promise<void>;
  /** The backend locked the vault (idle, screen lock, ...): drop everything and show the reason. */
  lockedByBackend: (reason: LockReason | "unknown") => void;
}

/** Load everything the unlocked shell shows. */
async function loadVaultData(): Promise<void> {
  await Promise.all([useTree.getState().load(), useCredentials.getState().load()]);
  await adoptLiveSessions();
  await adoptWeb(); // web windows were hidden by the lock, not closed (ADR-0013)
}

/**
 * Sessions, loopback forwards and transfers outlive a lock on the backend (ADR-0010, M-10): show
 * them again so nothing keeps running without a UI to see or stop it. Forwards are listed by the
 * Forwards panel itself (`forward_list`); transfers are re-keyed by `transferId`.
 */
async function adoptLiveSessions(): Promise<void> {
  let live: SessionInfo[];
  try {
    live = await ipc.sessionList();
  } catch {
    return;
  }
  useSessions.getState().adopt(live);
  const ssh = live.filter((s) => s.protocol === "ssh" && s.state === "connected");
  await Promise.all(ssh.map((s) => useTransfers.getState().adopt(s.sessionId)));
}

/** Forget every piece of vault-derived state held in this window. */
function wipe(): void {
  useSessions.getState().reset();
  useTree.getState().reset();
  useCredentials.getState().reset();
  useUi.getState().reset();
  useTransfers.getState().reset();
  useSync.getState().reset();
}

export const useApp = create<AppState>((set, get) => ({
  info: null,
  vault: "unknown",
  lastError: null,
  lockReason: null,

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
      set({ vault, lastError: null, lockReason: vault === "unlocked" ? null : get().lockReason });
      if (vault === "unlocked") await loadVaultData();
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  /** ADR-0017 join (S2): `vault_join` already replaced the bootstrap vault; the shell loads the synced data. */
  adoptJoined: async () => {
    set({ vault: "unlocked", lastError: null, lockReason: null });
    await loadVaultData();
  },

  lock: async () => {
    try {
      const vault = await ipc.vaultLock("user");
      wipe();
      set({ vault, lastError: null, lockReason: null });
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  lockedByBackend: (reason) => {
    wipe();
    // A user lock also emits the event; it carries no message for the unlock screen.
    set({ vault: "locked", lastError: null, lockReason: reason === "user" ? null : reason });
  },
}));

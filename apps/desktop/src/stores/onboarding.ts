import { create } from "zustand";
import { ipc } from "../lib/ipc";

/**
 * First-run onboarding (ADR-0019 §6): the card shows on an empty tree until the user dismisses it
 * or the tree has a connection. The dismissal is remembered per vault in the same local settings
 * store as the theme (`localStorage`, this device only; nothing about it leaves the machine).
 * The vault id comes from `sync_status` (passive, no secret), so a second vault on the same
 * machine gets its own first run.
 */
const KEY = "mooring.onboarding";

function readDismissed(): string[] {
  try {
    const raw = localStorage.getItem(KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function writeDismissed(ids: string[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(ids));
  } catch {
    // storage blocked: the dismissal still holds for this window
  }
}

interface OnboardingState {
  /** The unlocked vault's id, or null until `load` answered. */
  vaultId: string | null;
  dismissed: string[];
  /** Dismissed in this window (also when no vault id could be read). */
  hidden: boolean;
  /** The import wizard opened from the card; it lives in the workspace so a filled tree does not unmount it mid-flow. */
  importing: boolean;
  load: () => Promise<void>;
  dismiss: () => void;
  setImporting: (on: boolean) => void;
  reset: () => void;
}

export const useOnboarding = create<OnboardingState>((set, get) => ({
  vaultId: null,
  dismissed: readDismissed(),
  hidden: false,
  importing: false,

  load: async () => {
    try {
      const status = await ipc.syncStatus();
      set({ vaultId: status.vaultId });
    } catch {
      set({ vaultId: null }); // no id: the card still shows; a dismissal then holds for this window only
    }
  },

  dismiss: () => {
    const id = get().vaultId;
    const dismissed = id && !get().dismissed.includes(id) ? [...get().dismissed, id] : get().dismissed;
    if (dismissed !== get().dismissed) writeDismissed(dismissed);
    set({ dismissed, hidden: true });
  },

  setImporting: (importing) => { set({ importing }); },
  reset: () => { set({ vaultId: null, hidden: false, importing: false }); },
}));

/** True while the card should show for the current vault. */
export function onboardingPending(s: Pick<OnboardingState, "vaultId" | "dismissed" | "hidden">): boolean {
  if (s.hidden) return false;
  return s.vaultId === null || !s.dismissed.includes(s.vaultId);
}

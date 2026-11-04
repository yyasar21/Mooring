import { create } from "zustand";
import type { Protocol } from "../lib/ipc.types";

export type Theme = "dark" | "light";
export type View = "workspace" | "audit" | "credentials" | "settings";

/** Which editor dialog is open. `id` absent = create. */
export type Dialog =
  | { kind: "folder"; id?: string; parentId: string }
  | { kind: "connection"; id?: string; folderId: string };

/**
 * What the credentials view shows in its right pane: nothing, an existing credential, or the kind
 * picker for a new one (`protocol` greys out kinds that cannot sign in there). Pasted secrets
 * never pass through this store; they stay in the form component.
 */
export type CredentialPane =
  | { mode: "none" }
  | { mode: "edit"; id: string }
  | { mode: "new"; protocol?: Protocol };

export const SIDEBAR = { min: 180, max: 480, initial: 264 };
export const INSPECTOR = { min: 240, max: 520, initial: 312 };

const THEME_KEY = "mooring.theme";

function readTheme(): Theme {
  try {
    return localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(theme: Theme): void {
  if (typeof document !== "undefined") document.documentElement.dataset.theme = theme;
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, Math.round(v)));

interface UiState {
  theme: Theme;
  view: View;
  sidebarWidth: number;
  inspectorWidth: number;
  inspectorOpen: boolean;
  paletteOpen: boolean;
  dialog: Dialog | null;
  credentialPane: CredentialPane;
  /** Row id currently being renamed inline in the tree. */
  renaming: string | null;

  setTheme: (t: Theme) => void;
  toggleTheme: () => void;
  setView: (v: View) => void;
  setSidebarWidth: (w: number) => void;
  setInspectorWidth: (w: number) => void;
  toggleInspector: () => void;
  setPalette: (open: boolean) => void;
  openDialog: (d: Dialog) => void;
  closeDialog: () => void;
  /** Switch to the credentials view with the given pane. */
  showCredentials: (pane?: CredentialPane) => void;
  setRenaming: (id: string | null) => void;
  reset: () => void;
}

export const useUi = create<UiState>((set, get) => ({
  theme: readTheme(),
  view: "workspace",
  sidebarWidth: SIDEBAR.initial,
  inspectorWidth: INSPECTOR.initial,
  inspectorOpen: true,
  paletteOpen: false,
  dialog: null,
  credentialPane: { mode: "none" },
  renaming: null,

  setTheme: (theme) => {
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      // storage blocked: the choice still applies for this window
    }
    applyTheme(theme);
    set({ theme });
  },
  toggleTheme: () => { get().setTheme(get().theme === "dark" ? "light" : "dark"); },
  setView: (view) => { set({ view, paletteOpen: false }); },
  setSidebarWidth: (w) => { set({ sidebarWidth: clamp(w, SIDEBAR.min, SIDEBAR.max) }); },
  setInspectorWidth: (w) => { set({ inspectorWidth: clamp(w, INSPECTOR.min, INSPECTOR.max) }); },
  toggleInspector: () => { set({ inspectorOpen: !get().inspectorOpen }); },
  setPalette: (paletteOpen) => { set({ paletteOpen }); },
  openDialog: (dialog) => { set({ dialog, paletteOpen: false }); },
  closeDialog: () => { set({ dialog: null }); },
  showCredentials: (pane = { mode: "none" }) => {
    set({ view: "credentials", credentialPane: pane, paletteOpen: false, dialog: null });
  },
  setRenaming: (renaming) => { set({ renaming }); },
  reset: () => {
    set({ view: "workspace", paletteOpen: false, dialog: null, credentialPane: { mode: "none" }, renaming: null });
  },
}));

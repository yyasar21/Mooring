import { create } from "zustand";

export type Theme = "dark" | "light";
export type View = "workspace" | "audit";

/** Which editor dialog is open. `id` absent = create. */
export type Dialog =
  | { kind: "folder"; id?: string; parentId: string }
  | { kind: "connection"; id?: string; folderId: string }
  | { kind: "credential"; id?: string }
  | { kind: "credentials" };

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
  setRenaming: (renaming) => { set({ renaming }); },
  reset: () => { set({ view: "workspace", paletteOpen: false, dialog: null, renaming: null }); },
}));

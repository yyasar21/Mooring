import { create } from "zustand";
import type { CredentialRole, Protocol, ProtocolOptions } from "../lib/ipc.types";

/** The theme in effect. */
export type Theme = "dark" | "light";
/** What the user chose in Settings → Appearance; "system" follows the OS. */
export type ThemePref = Theme | "system";
export type View = "workspace" | "audit" | "credentials" | "settings";

/** Which editor dialog is open. `id` absent = create. */
export type Dialog =
  | { kind: "folder"; id?: string; parentId: string }
  | { kind: "connection"; id?: string; folderId: string };

/**
 * The unsaved fields of the connection form, carried across a "New…" credential round trip
 * (U0). Credential ids only; the form never holds a secret.
 */
export interface ConnectionDraft {
  name: string;
  protocol: Protocol;
  host: string;
  port: string;
  folder: string;
  cred: string;
  userOv: string;
  domainOv: string;
  gateway: string;
  become: string;
  /** ADR-0026: the SSH certificate (Vault `ssh_sign`) reference; absent in older drafts. */
  certificate?: string;
  tags: string;
  /** ADR-0025 jump hosts, first hop first (absent in drafts from before A5). */
  via?: string[];
  options: Partial<Record<Protocol, ProtocolOptions>>;
}

/** Where a credential created from a form's "New…" button goes back to. */
export interface CredentialReturn {
  dialog: Extract<Dialog, { kind: "connection" }>;
  /** The picker that asked for the credential; the saved one is preselected there. */
  role: CredentialRole;
  draft: ConnectionDraft;
}

/** Handed to the reopened connection form once, then cleared by it. */
export interface ConnectionResume {
  draft: ConnectionDraft;
  pick: { role: CredentialRole; id: string } | null;
}

/**
 * What the credentials view shows in its right pane: nothing, an existing credential (its detail
 * card, or its editor), or the kind picker for a new one (`protocol` greys out kinds that cannot
 * sign in there; `returnTo` sends the saved credential back to the form that asked for it).
 * Pasted secrets never pass through this store; they stay in the form component.
 */
export type CredentialPane =
  | { mode: "none" }
  | { mode: "view"; id: string }
  | { mode: "edit"; id: string }
  | { mode: "new"; protocol?: Protocol; returnTo?: CredentialReturn };

/** Something a settings card should do when it mounts, set by the screen that sent the user there. */
export type SettingsIntent = { kind: "add-secret-source"; credentialId: string | null; sourceKind?: "vault" | "onepassword" | "bitwarden" };

export const SIDEBAR = { min: 180, max: 480, initial: 264 };
export const INSPECTOR = { min: 240, max: 520, initial: 312 };

const THEME_KEY = "mooring.theme";

function readThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

/** The OS theme; dark where the platform cannot say (the app's historical default). */
export function systemTheme(): Theme {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return "dark";
  if (window.matchMedia("(prefers-color-scheme: light)").matches) return "light";
  return "dark";
}

export function resolveTheme(pref: ThemePref): Theme {
  return pref === "system" ? systemTheme() : pref;
}

export function applyTheme(theme: Theme): void {
  if (typeof document !== "undefined") document.documentElement.dataset.theme = theme;
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, Math.round(v)));

interface UiState {
  /** Resolved theme (what is painted). */
  theme: Theme;
  /** The Appearance setting. */
  themePref: ThemePref;
  view: View;
  sidebarWidth: number;
  inspectorWidth: number;
  inspectorOpen: boolean;
  paletteOpen: boolean;
  dialog: Dialog | null;
  credentialPane: CredentialPane;
  /** Draft + preselection for the connection form reopened after a "New…" round trip. */
  connectionResume: ConnectionResume | null;
  settingsIntent: SettingsIntent | null;
  /** Row id currently being renamed inline in the tree. */
  renaming: string | null;

  /** Settings → Appearance: System, Light or Dark. Persisted on this device only. */
  setThemePref: (p: ThemePref) => void;
  /** An explicit light or dark choice (same as `setThemePref`). */
  setTheme: (t: Theme) => void;
  /** Palette "Switch theme": the opposite of what is painted, as an explicit choice. */
  toggleTheme: () => void;
  /** The OS theme changed; only repaints while the preference is "system". */
  syncSystemTheme: () => void;
  setView: (v: View) => void;
  setSidebarWidth: (w: number) => void;
  setInspectorWidth: (w: number) => void;
  toggleInspector: () => void;
  setPalette: (open: boolean) => void;
  openDialog: (d: Dialog) => void;
  closeDialog: () => void;
  /** Switch to the credentials view with the given pane. */
  showCredentials: (pane?: CredentialPane) => void;
  /** Reopen the connection form a "New…" left, with its draft and (if saved) the new credential picked. */
  resumeConnectionDialog: (ret: CredentialReturn, pickedId: string | null) => void;
  /** The connection form took its resume; nothing else should see it. */
  takeConnectionResume: () => ConnectionResume | null;
  /** Switch to Settings with something for a card to do on mount. */
  showSettings: (intent?: SettingsIntent) => void;
  takeSettingsIntent: () => SettingsIntent | null;
  setRenaming: (id: string | null) => void;
  reset: () => void;
}

export const useUi = create<UiState>((set, get) => ({
  theme: resolveTheme(readThemePref()),
  themePref: readThemePref(),
  view: "workspace",
  sidebarWidth: SIDEBAR.initial,
  inspectorWidth: INSPECTOR.initial,
  inspectorOpen: true,
  paletteOpen: false,
  dialog: null,
  credentialPane: { mode: "none" },
  connectionResume: null,
  settingsIntent: null,
  renaming: null,

  setThemePref: (themePref) => {
    try {
      if (themePref === "system") localStorage.removeItem(THEME_KEY);
      else localStorage.setItem(THEME_KEY, themePref);
    } catch {
      // storage blocked: the choice still applies for this window
    }
    const theme = resolveTheme(themePref);
    applyTheme(theme);
    set({ themePref, theme });
  },
  setTheme: (theme) => { get().setThemePref(theme); },
  toggleTheme: () => { get().setThemePref(get().theme === "dark" ? "light" : "dark"); },
  syncSystemTheme: () => {
    if (get().themePref !== "system") return;
    const theme = systemTheme();
    applyTheme(theme);
    set({ theme });
  },
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
  resumeConnectionDialog: (ret, pickedId) => {
    set({
      view: "workspace",
      dialog: ret.dialog,
      credentialPane: { mode: "none" },
      paletteOpen: false,
      connectionResume: { draft: ret.draft, pick: pickedId === null ? null : { role: ret.role, id: pickedId } },
    });
  },
  takeConnectionResume: () => {
    const r = get().connectionResume;
    if (r) set({ connectionResume: null });
    return r;
  },
  showSettings: (intent) => { set({ view: "settings", paletteOpen: false, dialog: null, settingsIntent: intent ?? null }); },
  takeSettingsIntent: () => {
    const i = get().settingsIntent;
    if (i) set({ settingsIntent: null });
    return i;
  },
  setRenaming: (renaming) => { set({ renaming }); },
  reset: () => {
    set({
      view: "workspace", paletteOpen: false, dialog: null, credentialPane: { mode: "none" },
      connectionResume: null, settingsIntent: null, renaming: null,
    });
  },
}));

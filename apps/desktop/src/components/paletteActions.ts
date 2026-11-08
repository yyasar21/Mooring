// L3: what the command palette offers besides connections: actions (with their shortcut, so a row
// teaches the chord) and the settings pages. Pure data plus the store calls each row runs.
import { canDetach, useSessions } from "../stores/sessions";
import { useApp } from "../stores/app";
import { useOnboarding } from "../stores/onboarding";
import { useTree } from "../stores/tree";
import { useUi } from "../stores/ui";
import { SETTINGS_SECTIONS } from "./settings/settingsSections";
import { goToView } from "./NavRail";
import { openSettingsCard } from "./SyncBanner";

export interface PaletteAction {
  id: string;
  label: string;
  /** The chord as `Kbd` writes it ("mod ⇧ L"), when the action has one. */
  keys?: string;
  /** Extra words the search matches. */
  terms?: string;
  run: () => void;
}

/** The actions available now (Close and Detach only with an active tab). `close` shuts the palette first. */
export function paletteActions(close: () => void): PaletteAction[] {
  const ui = useUi.getState();
  const root = useTree.getState().folders.find((f) => f.parentId === null)?.id ?? "";
  const s = useSessions.getState();
  const tab = s.tabs.find((t) => t.id === s.activeTab);
  const out: PaletteAction[] = [
    { id: "new-conn", label: "New connection", terms: "add host create", run: () => { ui.openDialog({ kind: "connection", folderId: root }); } },
    { id: "new-folder", label: "New folder", terms: "add group", run: () => { ui.openDialog({ kind: "folder", parentId: root }); } },
    { id: "new-cred", label: "New credential", terms: "add password key secret", run: () => { ui.showCredentials({ mode: "new" }); } },
    {
      id: "import", label: "Import connections…", terms: "mremoteng royal rdm csv ldap",
      run: () => { close(); ui.setView("workspace"); useOnboarding.getState().setImporting(true); },
    },
    { id: "go-hosts", label: "Go to Hosts", keys: "mod 1", terms: "tree connections", run: () => { close(); ui.setView("workspace"); } },
    { id: "go-creds", label: "Go to Credentials", keys: "mod 2", terms: "manage", run: () => { close(); goToView("credentials"); } },
    { id: "go-audit", label: "Go to Audit log", keys: "mod 3", terms: "events history", run: () => { close(); goToView("audit"); } },
    { id: "go-settings", label: "Go to Settings", keys: "mod 4", terms: "preferences options", run: () => { close(); goToView("settings"); } },
    { id: "details", label: "Show or hide details", keys: "mod I", terms: "inspector panel", run: () => { close(); ui.toggleInspector(); } },
    { id: "theme", label: "Switch theme", terms: "dark light appearance", run: () => { close(); ui.toggleTheme(); } },
  ];
  if (tab) {
    out.push({ id: "close-tab", label: "Close tab", keys: "mod W", terms: "session", run: () => { close(); void s.close(tab.id); } });
    if (canDetach(tab.protocol) && tab.state === "connected") {
      out.push({ id: "detach", label: "Detach tab to a window", keys: "mod ⇧ D", terms: "window", run: () => { close(); void s.detach(tab.id); } });
    }
  }
  out.push({ id: "lock", label: "Lock vault", keys: "mod ⇧ L", terms: "sign out", run: () => { close(); void useApp.getState().lock(); } });
  return out;
}

/** One row per settings page; running it opens Settings at that card. */
export function settingsPages(close: () => void): PaletteAction[] {
  return SETTINGS_SECTIONS.map((sec) => ({
    id: `settings-${sec.id}`,
    label: sec.title,
    terms: `settings ${sec.group} ${sec.terms}`,
    run: () => { close(); openSettingsCard(sec.id); },
  }));
}

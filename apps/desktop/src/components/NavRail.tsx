import { Icon, type IconName } from "@mooring/ui";
import { useUi, type View } from "../stores/ui";

interface Item {
  view: View;
  icon: IconName;
  /** Visible label under the icon. */
  label: string;
  /** Accessible name, when it says more than the label ("Audit" → "Audit log"). */
  name?: string;
  keys: string;
}

const TOP: Item[] = [
  { view: "workspace", icon: "hosts", label: "Hosts", keys: "1" },
  { view: "credentials", icon: "key", label: "Credentials", keys: "2" },
  { view: "audit", icon: "list", label: "Audit", name: "Audit log", keys: "3" },
];
const BOTTOM: Item[] = [{ view: "settings", icon: "gear", label: "Settings", keys: "4" }];

/** Open a view from the rail or its shortcut. Choosing the open view again goes back to Hosts. */
export function goToView(view: View): void {
  const ui = useUi.getState();
  if (view === "workspace" || ui.view === view) ui.setView("workspace");
  else if (view === "credentials") ui.showCredentials();
  else ui.setView(view);
}

/**
 * Primary navigation (design review 2026-11, M1): Hosts, Credentials and Audit log at the top,
 * Settings at the bottom; mod+1…4 from anywhere. `nav "Views"` and the button names are e2e
 * contracts. The current view is `aria-current="page"`; pressing it again returns to Hosts (the
 * old title-bar buttons toggled, and flows rely on that).
 */
export function NavRail() {
  const view = useUi((s) => s.view);
  const item = (it: Item) => (
    <button
      key={it.view}
      type="button"
      className="rail-item"
      aria-current={view === it.view ? "page" : undefined}
      aria-label={it.name}
      title={`${it.name ?? it.label} (${modLabel()}+${it.keys})`}
      onClick={() => { goToView(it.view); }}
    >
      <Icon name={it.icon} size={20} />
      <span className="rail-label">{it.label}</span>
    </button>
  );
  return (
    <nav aria-label="Views" className="rail">
      {TOP.map(item)}
      <span className="rail-spacer" />
      {BOTTOM.map(item)}
    </nav>
  );
}

function modLabel(): string {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent) ? "⌘" : "Ctrl";
}

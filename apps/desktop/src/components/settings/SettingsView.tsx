import { useState, type ReactNode } from "react";
import { Icon } from "@mooring/ui";
import { useUi } from "../../stores/ui";
import { AutoLockCard } from "./AutoLockCard";
import { SyslogCard } from "./SyslogCard";
import { KnownCertsCard } from "./KnownCertsCard";
import { SecretSourcesCard } from "./SecretSourcesCard";
import { SyncCard } from "./SyncCard";
import { UpdatesCard } from "./UpdatesCard";
import { AboutCard } from "./AboutCard";
import { ImportCard } from "../import/ImportCard";
import { SecurityCard } from "./SecurityCard";
import { BackupCard } from "./BackupCard";
import { SshCard } from "./SshCard";
import { AppearanceCard } from "./AppearanceCard";
import { matchSections, SETTINGS_SECTIONS, type SettingsSection } from "./settingsSections";

const CARDS: Record<string, () => ReactNode> = {
  "autolock-title": () => <AutoLockCard />,
  "security-title": () => <SecurityCard />,
  "backup-title": () => <BackupCard />,
  "sync-title": () => <SyncCard />,
  "sources-title": () => <SecretSourcesCard />,
  "trust-title": () => <KnownCertsCard />,
  "ssh-title": () => <SshCard />,
  "syslog-title": () => <SyslogCard />,
  "appearance-title": () => <AppearanceCard />,
  "settings-import": () => <ImportCard />,
  "updates-title": () => <UpdatesCard />,
  "about-title": () => <AboutCard />,
};

const GROUPS: SettingsSection["group"][] = ["Vault", "Trust and audit", "Application"];

/** Scroll a card's heading into view and give it focus, so its controls are one Tab away. */
function goTo(id: string): void {
  const h = document.getElementById(id);
  if (!h) return;
  h.tabIndex = -1;
  // jsdom has no scrollIntoView
  if ("scrollIntoView" in h) h.scrollIntoView({ block: "start" });
  h.focus();
}

/**
 * Application settings (M6): a section list with search on the left, the cards on the right in
 * the same order. Every card stays mounted (a hidden one keeps its state and heading id), the
 * search only hides the cards it does not match. `openSettingsCard` clears the search first.
 */
export function SettingsView() {
  const query = useUi((s) => s.settingsQuery);
  const setQuery = useUi((s) => s.setSettingsQuery);
  const [current, setCurrent] = useState<string | null>(null);
  const shown = new Set(matchSections(query).map((s) => s.id));

  return (
    <section aria-label="Settings" className="view-page">
      <header className="page-head">
        <h1 className="t-page">Settings</h1>
      </header>
      <div className="settings-layout">
        <nav aria-label="Settings sections" className="settings-nav">
          <div className="settings-search">
            <Icon name="search" size={14} />
            <input
              type="search"
              className="field"
              aria-label="Find a setting"
              placeholder="Find a setting"
              value={query}
              onChange={(e) => { setQuery(e.target.value); }}
              onKeyDown={(e) => {
                if (e.key === "Escape" && query) {
                  e.stopPropagation();
                  setQuery("");
                }
              }}
            />
          </div>
          {GROUPS.map((g) => {
            const items = SETTINGS_SECTIONS.filter((s) => s.group === g && shown.has(s.id));
            if (items.length === 0) return null;
            return (
              <div key={g} className="settings-nav-group">
                <p className="settings-nav-title" id={`settings-group-${g.replace(/\W+/g, "-").toLowerCase()}`}>{g}</p>
                <ul aria-labelledby={`settings-group-${g.replace(/\W+/g, "-").toLowerCase()}`}>
                  {items.map((s) => (
                    <li key={s.id}>
                      <button
                        type="button"
                        className="settings-nav-item"
                        aria-current={current === s.id ? "true" : undefined}
                        onClick={() => {
                          setCurrent(s.id);
                          goTo(s.id);
                        }}
                      >
                        {s.title}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
          {shown.size === 0 && <p className="settings-nav-empty" role="status">No setting matches “{query}”.</p>}
        </nav>
        <div className="settings-scroll">
          {SETTINGS_SECTIONS.map((s) => (
            <div key={s.id} className="settings-slot" data-section={s.id} hidden={!shown.has(s.id)}>
              {CARDS[s.id]?.()}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

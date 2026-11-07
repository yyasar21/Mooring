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

/**
 * Application settings: auto-lock policy and biometric unlock (ADR-0010, ADR-0022), the audit
 * syslog mirror, the trusted certificates (ADR-0011), secret sources (ADR-0016), vault sync
 * (ADR-0017), backups (ADR-0023), importers (ADR-0019), updates (ADR-0018 §3) and About.
 */
export function SettingsView() {
  const setView = useUi((s) => s.setView);
  return (
    <section aria-label="Settings" className="flex h-full min-w-0 flex-col bg-bg">
      <header className="flex h-[52px] flex-none items-center gap-3 border-b border-line bg-bg-sunken px-4">
        <h1 className="m-display whitespace-nowrap text-[length:var(--fs-l)]">Settings</h1>
        <button type="button" className="btn btn-ghost ml-auto" onClick={() => { setView("workspace"); }}>
          Back to sessions
        </button>
      </header>
      <div className="settings-scroll">
        <AutoLockCard />
        <SecurityCard />
        <SyslogCard />
        <KnownCertsCard />
        <SecretSourcesCard />
        <SyncCard />
        <BackupCard />
        <ImportCard />
        <UpdatesCard />
        <AboutCard />
      </div>
    </section>
  );
}

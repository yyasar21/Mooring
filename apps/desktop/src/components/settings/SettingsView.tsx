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

/**
 * Application settings: appearance, auto-lock policy and biometric unlock (ADR-0010, ADR-0022),
 * the audit syslog mirror, the trusted certificates (ADR-0011), secret sources (ADR-0016), vault
 * sync (ADR-0017), SSH security keys (ADR-0024), backups (ADR-0023), importers (ADR-0019),
 * updates (ADR-0018 §3) and About. The view takes the full width; the rail leads back to Hosts.
 */
export function SettingsView() {
  return (
    <section aria-label="Settings" className="view-page">
      <header className="page-head">
        <h1 className="t-page">Settings</h1>
      </header>
      <div className="settings-scroll">
        <AppearanceCard />
        <AutoLockCard />
        <SecurityCard />
        <SshCard />
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

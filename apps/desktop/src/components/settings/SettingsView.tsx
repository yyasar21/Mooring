import { useUi } from "../../stores/ui";
import { AutoLockCard } from "./AutoLockCard";
import { SyslogCard } from "./SyslogCard";
import { KnownCertsCard } from "./KnownCertsCard";

/** Application settings: auto-lock policy, the audit syslog mirror (ADR-0010) and the trusted certificates (ADR-0011). */
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
        <SyslogCard />
        <KnownCertsCard />
      </div>
    </section>
  );
}

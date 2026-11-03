import { lazy, Suspense } from "react";
import { Kbd } from "@mooring/ui";
import { useSessions, type Tab } from "../stores/sessions";
import { useTree } from "../stores/tree";
import { TabStrip } from "./TabStrip";
import { PromptModal } from "./terminal/PromptModal";

// xterm.js is most of the bundle; load it with the first terminal tab, not at startup.
const TerminalView = lazy(() => import("./terminal/TerminalView").then((m) => ({ default: m.TerminalView })));

/** Centre pane: tab strip and the session panels. Every terminal stays mounted; only one shows. */
export function Workspace() {
  const tabs = useSessions((s) => s.tabs);
  const activeTab = useSessions((s) => s.activeTab);

  return (
    <section aria-label="Sessions" className="flex h-full min-w-0 flex-col bg-bg">
      <TabStrip />
      <div className="relative min-h-0 flex-1">
        {tabs.length === 0 && <EmptyState />}
        {tabs.map((t) => (
          <SessionPanel key={t.id} tab={t} active={t.id === activeTab} />
        ))}
      </div>
    </section>
  );
}

function SessionPanel({ tab, active }: { tab: Tab; active: boolean }) {
  const c = useTree((s) => s.connections.find((x) => x.id === tab.connectionId));
  const reconnect = useSessions((s) => s.reconnect);
  const terminal = c?.protocol === "ssh" || c?.protocol === "kubernetes";

  return (
    <div
      role="tabpanel"
      id={`panel-${tab.id}`}
      aria-labelledby={`tab-${tab.id}`}
      hidden={!active}
      className="absolute inset-0"
    >
      {terminal ? (
        <Suspense fallback={<div className="term-host" />}>
          <TerminalView tabId={tab.id} active={active} />
        </Suspense>
      ) : (
        <div className="grid h-full place-items-center p-6 text-center">
          <div className="max-w-sm">
            <p className="text-[length:var(--fs-l)] font-medium">{c?.name}</p>
            <p className="mono mt-1 text-text-muted select-text">{c?.host}</p>
            <p className="mt-4 text-[length:var(--fs-s)] text-text-faint">
              {c?.protocol.toUpperCase()} display arrives with the graphical protocols. The session itself is open and
              audited.
            </p>
          </div>
        </div>
      )}
      {tab.state === "closed" && (
        <div className="absolute bottom-3 left-1/2 z-10 flex -translate-x-1/2 items-center gap-3 rounded-[var(--radius-m)] border border-line-strong bg-surface-raised px-3 py-2 text-[length:var(--fs-s)]">
          <span className="text-text-muted">Disconnected: {tab.reason ?? "session ended"}</span>
          <button type="button" className="btn" onClick={() => void reconnect(tab.id)}>
            Reconnect
          </button>
        </div>
      )}
      {tab.prompt && active && <PromptModal tabId={tab.id} prompt={tab.prompt} host={c?.host ?? ""} />}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="grid h-full place-items-center">
      <div className="text-center">
        <p className="text-[length:var(--fs-l)] font-medium">Nothing open yet</p>
        <p className="mt-2 text-text-muted">
          Press <Kbd>mod K</Kbd> and type a host, a name or a tag.
        </p>
      </div>
    </div>
  );
}

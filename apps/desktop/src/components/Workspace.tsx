import { lazy, Suspense, useState } from "react";
import { Kbd } from "@mooring/ui";
import { isGraphical, useSessions, type Tab } from "../stores/sessions";
import { RemoteSessionTab } from "./remote/RemoteSessionTab";
import { useTree } from "../stores/tree";
import { TabStrip } from "./TabStrip";
import { PromptModal } from "./terminal/PromptModal";
import { SessionToolbar, type SessionTool } from "./SessionToolbar";
import { ForwardsPanel } from "./forwards/ForwardsPanel";
import { SftpPanel } from "./sftp/SftpPanel";

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
  const ssh = c?.protocol === "ssh";
  const graphical = isGraphical(c?.protocol ?? tab.protocol);
  const [tool, setTool] = useState<SessionTool>("terminal");
  const liveSession = tab.state === "connected" ? tab.sessionId : null;

  const bezel = (
    <div className="term-bezel m-hud" data-active={active && tab.state === "connected" && tool === "terminal" ? true : undefined}>
      <Suspense fallback={<div className="term-host" />}>
        <TerminalView tabId={tab.id} active={active && tool === "terminal"} />
      </Suspense>
    </div>
  );

  return (
    <div
      role="tabpanel"
      id={`panel-${tab.id}`}
      aria-labelledby={`tab-${tab.id}`}
      hidden={!active}
      className="absolute inset-0"
    >
      {ssh ? (
        <>
          <SessionToolbar tool={tool} onTool={setTool} />
          <div className="session-body">
            {/* The terminal stays mounted under the tool panels so its scrollback survives. */}
            {bezel}
            {tool === "forwards" && (
              <div className="tool-layer">
                <ForwardsPanel sessionId={liveSession} />
              </div>
            )}
            {tool === "files" && (
              <div className="tool-layer">
                <SftpPanel key={liveSession ?? "offline"} sessionId={liveSession} />
              </div>
            )}
          </div>
        </>
      ) : terminal ? (
        bezel
      ) : graphical ? (
        <RemoteSessionTab tab={tab} active={active} connection={c} />
      ) : (
        <div className="panel-note m-hud">
          <div className="max-w-sm">
            <p className="m-micro">{c?.protocol.toUpperCase()} session</p>
            <p className="m-display mt-2 text-[length:var(--fs-xl)]">{c?.name}</p>
            <p className="readout-host mt-1 select-text">{c?.host}</p>
            <p className="mt-4 text-[length:var(--fs-s)] text-text-faint">
              {c?.protocol.toUpperCase()} display arrives with the graphical protocols. The session itself is open and
              audited.
            </p>
          </div>
        </div>
      )}
      {tab.state === "closed" && !graphical && (
        <div className="dropped m-hud" data-tone="hot">
          <span className="m-micro" style={{ color: "var(--hot)" }}>Link lost</span>
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
    <div className="panel-note">
      <svg className="reticle absolute" width="260" height="260" viewBox="0 0 260 260" fill="none" stroke="currentColor" aria-hidden>
        <circle cx="130" cy="130" r="120" strokeDasharray="2 6" />
        <circle cx="130" cy="130" r="72" />
        <path d="M130 0v40M130 220v40M0 130h40M220 130h40" />
      </svg>
      <div className="relative text-center">
        <p className="m-display text-[length:var(--fs-xl)]">Nothing open yet</p>
        <p className="mt-3 text-text-muted">
          Press <Kbd>mod K</Kbd> and type a host, a name or a tag.
        </p>
      </div>
    </div>
  );
}

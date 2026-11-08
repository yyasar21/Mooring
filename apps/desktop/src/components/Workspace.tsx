import { lazy, Suspense, useCallback, useState } from "react";
import { Icon, Kbd } from "@mooring/ui";
import { canDetach, isGraphical, useSessions, type Tab } from "../stores/sessions";
import type { Size } from "../lib/ipc";
import { RemoteSessionTab } from "./remote/RemoteSessionTab";
import { WebSessionTab } from "./web/WebSessionTab";
import { DetachedPlaceholder } from "./detached/DetachedPlaceholder";
import { useTree } from "../stores/tree";
import { TabStrip } from "./TabStrip";
import { PromptModal } from "./terminal/PromptModal";
import { HopStrip } from "./terminal/HopStrip";
import { SK_CLOSE, TouchBanner } from "./terminal/TouchBanner";
import { CLOSE_TEXT } from "./remote/ConnectionBanner";
import { SessionToolbar, type SessionTool } from "./SessionToolbar";
import { ForwardsPanel } from "./forwards/ForwardsPanel";
import { SftpPanel } from "./sftp/SftpPanel";
import { ClusterBrowser } from "./kube/ClusterBrowser";
import { LogsViewer } from "./kube/LogsViewer";
import { OnboardingCard } from "./onboarding/OnboardingCard";
import { ImportWizard } from "./import/ImportWizard";
import { TabErrorBoundary } from "./TabErrorBoundary";
import { onboardingPending, useOnboarding } from "../stores/onboarding";

// xterm.js is most of the bundle; load it with the first terminal tab, not at startup.
const TerminalView = lazy(() => import("./terminal/TerminalView").then((m) => ({ default: m.TerminalView })));

/** Centre pane: tab strip and the session panels. Every terminal stays mounted; only one shows. */
export function Workspace() {
  const tabs = useSessions((s) => s.tabs);
  const activeTab = useSessions((s) => s.activeTab);
  const importing = useOnboarding((s) => s.importing);

  return (
    <section aria-label="Sessions" className="flex h-full min-w-0 flex-col bg-bg">
      <TabStrip />
      <div className="relative min-h-0 flex-1">
        {tabs.length === 0 && <EmptyState />}
        {tabs.map((t) => (
          <SessionPanel key={t.id} tab={t} active={t.id === activeTab} />
        ))}
      </div>
      {importing && <ImportWizard format={null} onClose={() => { useOnboarding.getState().setImporting(false); }} />}
    </section>
  );
}

function SessionPanel({ tab, active }: { tab: Tab; active: boolean }) {
  const c = useTree((s) => s.connections.find((x) => x.id === tab.connectionId));
  const reconnect = useSessions((s) => s.reconnect);
  // Kubernetes (ADR-0014): the cluster tab is a browser, logs a viewer, exec a terminal.
  const kube = tab.kube;
  const terminal = c?.protocol === "ssh" || kube?.view === "exec";
  const ssh = c?.protocol === "ssh";
  const graphical = isGraphical(c?.protocol ?? tab.protocol);
  const web = (c?.protocol ?? tab.protocol) === "web";
  const [tool, setTool] = useState<SessionTool>("terminal");
  const liveSession = tab.state === "connected" ? tab.sessionId : null;
  const detached = tab.state === "detached";
  const onData = useCallback((d: Uint8Array) => void useSessions.getState().send(tab.id, d), [tab.id]);
  const onResize = useCallback((size: Size) => void useSessions.getState().resize(tab.id, size), [tab.id]);
  // ADR-0024: a security-key pre-flight refusal gets its own title and next step.
  const sk = tab.openError ? SK_CLOSE[tab.openError] : undefined;

  const bezel = (
    <div className="term-bezel m-hud" data-active={active && tab.state === "connected" && tool === "terminal" ? true : undefined}>
      <TabErrorBoundary what="the terminal" onClose={() => void useSessions.getState().close(tab.id)}>
      <Suspense fallback={<div className="term-host" />}>
        <TerminalView
          tabId={tab.id}
          active={active && tool === "terminal" && !detached}
          blocked={tab.prompt !== null}
          onData={onData}
          onResize={onResize}
          resyncKey={tab.attachEpoch}
        />
      </Suspense>
      </TabErrorBoundary>
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
          <SessionToolbar tool={tool} onTool={setTool} onDetach={canDetach(tab.protocol) && liveSession ? () => void useSessions.getState().detach(tab.id) : null} />
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
      ) : kube?.view === "cluster" ? (
        <TabErrorBoundary what="the cluster browser" onClose={() => void useSessions.getState().close(tab.id)}><ClusterBrowser tab={tab} connection={c} /></TabErrorBoundary>
      ) : kube?.view === "logs" ? (
        <TabErrorBoundary what="the log viewer" onClose={() => void useSessions.getState().close(tab.id)}><LogsViewer tab={tab} target={kube.logs} connection={c} active={active} /></TabErrorBoundary>
      ) : terminal ? (
        bezel
      ) : graphical ? (
        <TabErrorBoundary what="the remote desktop" onClose={() => void useSessions.getState().close(tab.id)}><RemoteSessionTab tab={tab} active={active && !detached} connection={c} /></TabErrorBoundary>
      ) : web ? (
        <TabErrorBoundary what="the web session" onClose={() => void useSessions.getState().close(tab.id)}><WebSessionTab tab={tab} connection={c} /></TabErrorBoundary>
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
      {tab.state === "closed" && !graphical && !web && kube?.view !== "cluster" && kube?.view !== "logs" && !tab.touch?.timedOut && (
        <div className="dropped m-hud" data-tone="hot">
          {sk ? <span className="dropped-title">{sk.title}</span> : <span className="m-micro" style={{ color: "var(--hot)" }}>Link lost</span>}
          <span className="dropped-text">
            <span className="text-text-muted">{sk ? tab.reason : `Disconnected: ${tab.reason ?? "session ended"}`}</span>
            {(tab.closeCode === "hop_failed" || tab.closeCode === "hop_lost") && <span className="dropped-hint">{CLOSE_TEXT[tab.closeCode].hint}</span>}
            {sk && <span className="dropped-hint">{sk.hint}</span>}
          </span>
          <button type="button" className="btn" onClick={() => void reconnect(tab.id)}>
            Reconnect
          </button>
        </div>
      )}
      {/* ADR-0025: cluster tabs get the hop strip too (R1 sends `hop_status` on the kube_open channel). */}
      {!web && kube?.view !== "logs" && <HopStrip tab={tab} />}
      {!web && !graphical && <TouchBanner tab={tab} onRetry={() => void reconnect(tab.id)} />}
      {detached && <DetachedPlaceholder tabId={tab.id} name={c?.name ?? "This session"} />}
      {tab.prompt && active && <PromptModal tabId={tab.id} prompt={tab.prompt} host={c?.host ?? ""} />}
    </div>
  );
}

function EmptyState() {
  // ADR-0019 §6: an empty tree after unlock gets the first-run card until it is dismissed or filled.
  const empty = useTree((s) => s.loaded && s.connections.length === 0);
  const pending = useOnboarding(onboardingPending);
  if (empty && pending) {
    return (
      <div className="panel-note">
        <OnboardingCard />
      </div>
    );
  }
  return (
    <div className="panel-note">
      <div className="empty-state">
        <span className="empty-icon" aria-hidden><Icon name="hosts" size={24} /></span>
        <p className="empty-title">Nothing open yet</p>
        <p className="empty-text">
          Double-click a connection in the tree, or press <Kbd>mod K</Kbd> and type a host, a name or a tag.
        </p>
      </div>
    </div>
  );
}

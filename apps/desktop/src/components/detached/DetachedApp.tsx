import { lazy, Suspense, useCallback, useState } from "react";
import { TabErrorBoundary } from "../TabErrorBoundary";
import { ProtocolPip } from "@mooring/ui";
import type { Size } from "../../lib/ipc";
import { RemoteCanvas } from "../remote/RemoteCanvas";
import { useDetachedSession } from "./useDetachedSession";

const TerminalView = lazy(() => import("../terminal/TerminalView").then((m) => ({ default: m.TerminalView })));

const BANNER: Record<"attaching" | "away" | "closed" | "failed", { title: string; text: string }> = {
  attaching: { title: "Attaching", text: "Taking the session over from the main window…" },
  away: { title: "Back in the main window", text: "The session moved back to the main window. This window closes." },
  closed: { title: "Session ended", text: "The session is closed. You can close this window." },
  failed: { title: "Could not attach", text: "Bring the session back to the main window, or close this window." },
};

/**
 * The `detached-<sessionId>` window (route `#/detached/<sessionId>`): one session and a slim bar.
 * It mounts instead of `App`, so none of the main window's boot (vault status, tree, `listen`)
 * runs here; `useDetachedSession` calls only the six commands this window's capability grants.
 */
export function DetachedApp({ sessionId }: { sessionId: string }) {
  const { st, key, input, ack, bringBack, requestDesktop, error } = useDetachedSession(sessionId);
  const [stats, setStats] = useState(false);
  const live = st.phase === "live";
  const connected = live && st.state === "connected";
  const graphical = st.protocol === "rdp" || st.protocol === "vnc";
  const onData = useCallback((d: Uint8Array) => { input({ kind: "bytes", data: d }); }, [input]);
  const onResize = useCallback((size: Size) => { input({ kind: "resize", size }); }, [input]);
  const banner = st.phase === "live" ? null : BANNER[st.phase];
  const label = st.protocol ? st.protocol.toUpperCase() : "Session";

  return (
    <main className="detached-root" aria-label={`${label} session in a separate window`}>
      <div role="toolbar" aria-label="Detached session" className="detached-bar">
        {st.protocol && <ProtocolPip protocol={st.protocol} live={connected} />}
        <span className="m-micro">{label} · separate window</span>
        <span className="chip" data-tone={connected ? "ok" : st.state === "reconnecting" ? "hot" : undefined}>
          {live ? st.state : st.phase}
        </span>
        <span className="spacer" />
        {error && (
          <span role="alert" className="remote-note" style={{ color: "var(--hot)" }}>
            {error}
          </span>
        )}
        {graphical && (
          <button type="button" className="btn btn-ghost" aria-pressed={stats} onClick={() => { setStats((v) => !v); }}>
            Stats
          </button>
        )}
        <button type="button" className="btn" disabled={st.phase === "closed" || st.phase === "away"} onClick={bringBack}>
          Bring back
        </button>
      </div>
      <div className="session-body remote-body">
        <div className="term-bezel m-hud" data-active={connected ? true : undefined}>
          {live && st.protocol === "ssh" && (
            <TabErrorBoundary what="the terminal">
              <Suspense fallback={<div className="term-host" />}>
                <TerminalView tabId={key} active={!st.prompt} blocked={st.prompt} onData={onData} onResize={onResize} />
              </Suspense>
            </TabErrorBoundary>
          )}
          {live && graphical && (
            <RemoteCanvas
              tabId={key}
              label={`${label} desktop`}
              active={!st.prompt}
              // View-only and the clipboard policy live in main (their commands are not granted
              // here); Rust enforces both, so this view sends input and never offers the clipboard.
              inputEnabled={connected && !st.prompt}
              showStats={stats}
              onInput={input}
              onAck={ack}
              onDesktopRequest={requestDesktop}
              offerClipboardOnFocus={false}
            />
          )}
        </div>
        {(banner ?? st.prompt) && (
          <div className="link-banner m-hud" role={st.phase === "failed" || st.phase === "closed" ? "alert" : "status"}>
            <span className="m-micro">{banner ? banner.title : "Waiting for you"}</span>
            <span className="text-text-muted">
              {banner ? (st.reason && st.phase !== "away" ? `${st.reason}. ${banner.text}` : banner.text) : "The session asks a question. Bring it back to the main window to answer it."}
            </span>
          </div>
        )}
      </div>
    </main>
  );
}

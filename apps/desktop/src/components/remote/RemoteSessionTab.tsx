import { useCallback, useEffect, useState } from "react";
import type { ClipboardPolicy, ConnectionSummary, RdpConnOptions, SessionInput, Size, VncConnOptions } from "../../lib/ipc";
import { ackSession, useSessions, type Tab } from "../../stores/sessions";
import { ConnectionBanner } from "./ConnectionBanner";
import { RemoteCanvas } from "./RemoteCanvas";

/** `Connected.security` → badge text and whether it is a plaintext warning (ADR-0012 owner decision 4). */
export function securityBadge(security: string | null): { text: string; hot: boolean } | null {
  switch (security) {
    case null:
      return null;
    case "nla":
      return { text: "NLA", hot: false };
    case "tls":
      return { text: "TLS without NLA", hot: true };
    case "vnc-auth":
    case "none":
      return { text: "Unencrypted", hot: true };
    default:
      return { text: security.toUpperCase().slice(0, 24), hot: false };
  }
}

function clipboardPolicy(c: ConnectionSummary | undefined): ClipboardPolicy {
  const o = c?.options as Partial<RdpConnOptions & VncConnOptions> | undefined;
  return o?.clipboard ?? "both";
}

/**
 * An RDP or VNC tab: toolbar (security, view-only, clipboard, screenshot, stats), the canvas in
 * the bezel, and the connection banner. Every pixel and input goes through `RemoteCanvas`.
 */
export function RemoteSessionTab({ tab, active, connection }: { tab: Tab; active: boolean; connection: ConnectionSummary | undefined }) {
  const input = useSessions((s) => s.input);
  const resize = useSessions((s) => s.resize);
  const reconnect = useSessions((s) => s.reconnect);
  const close = useSessions((s) => s.close);
  const setViewOnly = useSessions((s) => s.setViewOnly);
  const screenshot = useSessions((s) => s.screenshot);
  const [stats, setStats] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const vnc = tab.protocol === "vnc";
  const connected = tab.state === "connected";
  const policy = clipboardPolicy(connection);
  const toRemote = policy === "both" || policy === "to_remote";
  const viewOnly = vnc && tab.viewOnly;
  const inputEnabled = connected && !viewOnly && tab.prompt === null;
  const badge = securityBadge(connected ? tab.security : null);
  const name = connection?.name ?? "remote desktop";

  useEffect(() => {
    if (note === null) return;
    const t = window.setTimeout(() => { setNote(null); }, 3000);
    return () => { window.clearTimeout(t); };
  }, [note]);

  const onInput = useCallback((i: SessionInput) => { void input(tab.id, i); }, [input, tab.id]);
  const sid = tab.sessionId;
  const onAck = useCallback((seq: number) => { if (sid) ackSession(sid, seq); }, [sid]);
  const onDesktopRequest = useCallback(
    (size: Size) => {
      const d = useSessions.getState().tabs.find((t) => t.id === tab.id);
      if (d?.state !== "connected" || (d.desktop?.width === size.width && d.desktop.height === size.height)) return;
      void resize(tab.id, size);
    },
    [resize, tab.id],
  );

  return (
    <>
      <div role="toolbar" aria-label="Remote desktop tools" className="session-toolbar remote-toolbar">
        <span className="m-micro">{vnc ? "VNC" : "RDP"}</span>
        {badge && (
          <span className="chip" data-tone={badge.hot ? "hot" : "ok"} title="Negotiated security">
            {badge.text}
          </span>
        )}
        {vnc && (
          <span className="chip" data-tone={viewOnly ? "hot" : undefined} aria-live="polite">
            {viewOnly ? "View only" : "Input on"}
          </span>
        )}
        <span className="spacer" />
        {note && (
          <span role="status" className="remote-note">
            {note}
          </span>
        )}
        {vnc && (
          <button type="button" className="btn btn-ghost" disabled={!connected} aria-pressed={viewOnly} onClick={() => void setViewOnly(tab.id, !tab.viewOnly)}>
            View only
          </button>
        )}
        <button
          type="button"
          className="btn btn-ghost"
          disabled={!connected || !toRemote || viewOnly}
          title={toRemote ? "Mooring reads your clipboard and offers its text to the remote" : "The clipboard policy of this connection does not send to the remote"}
          onClick={() => {
            void input(tab.id, { kind: "clipboard_offer" });
            setNote("Clipboard text offered to the remote");
          }}
        >
          Send clipboard
        </button>
        <span className="remote-note" title="Remote copies land on this computer's clipboard; the text never passes through this window">
          {policy === "both" || policy === "from_remote" ? "Remote copies: automatic" : "Remote copies: off"}
        </span>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={!connected}
          onClick={() => {
            void screenshot(tab.id).then((s) => { if (s) setNote(`Screenshot ${String(s.width)}×${String(s.height)} copied`); });
          }}
        >
          Screenshot
        </button>
        <button type="button" className="btn btn-ghost" aria-pressed={stats} onClick={() => { setStats((v) => !v); }}>
          Stats
        </button>
      </div>
      <div className="session-body remote-body">
        <div className="term-bezel m-hud" data-active={active && connected ? true : undefined}>
          <RemoteCanvas
            tabId={tab.id}
            label={`${name} desktop`}
            active={active && tab.prompt === null}
            inputEnabled={inputEnabled}
            showStats={stats}
            onInput={onInput}
            onAck={onAck}
            onDesktopRequest={onDesktopRequest}
            offerClipboardOnFocus={toRemote && !viewOnly}
          />
        </div>
        <ConnectionBanner
          tab={tab}
          host={connection?.host ?? ""}
          onReconnect={() => void reconnect(tab.id)}
          onClose={() => void close(tab.id)}
        />
      </div>
    </>
  );
}

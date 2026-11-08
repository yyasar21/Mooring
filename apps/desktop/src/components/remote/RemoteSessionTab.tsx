import { useCallback, useEffect, useRef, useState } from "react";
import type { ClipboardPolicy, ConnectionSummary, ProtocolOptions, RdpConnOptions, SessionInput, Size, VncConnOptions } from "../../lib/ipc";
import { ackSession, useSessions, type Tab } from "../../stores/sessions";
import { ConnectionBanner } from "./ConnectionBanner";
import { RemoteCanvas } from "./RemoteCanvas";
import { cancelReconnect } from "../../stores/sessions.reconnect";
import { useConnOptions } from "../../stores/connOptions";
import { SessionHeader } from "../SessionHeader";
import { DetachButton, DisconnectButton } from "../SessionToolbar";

/** `Connected.security` → badge text and whether it is a plaintext warning (ADR-0012 owner decision 4). */
export function securityBadge(security: string | null): { text: string; hot: boolean } | null {
  switch (security) {
    case null:
      return null;
    case "nla":
      return { text: "NLA", hot: false };
    case "tls":
      return { text: "TLS without NLA", hot: true };
    // ADR-0027: the same, through an RD Gateway (the gateway chip names it).
    case "nla+rdg":
      return { text: "NLA", hot: false };
    case "tls+rdg":
      return { text: "TLS without NLA", hot: true };
    case "vnc-auth":
    case "none":
      return { text: "Unencrypted", hot: true };
    default:
      return { text: security.toUpperCase().slice(0, 24), hot: false };
  }
}

/** ADR-0027: "via RD Gateway gw01" while the gateway tunnel is up; the default port is not repeated. */
export function gatewayChip(tab: Pick<Tab, "gateway">): string | null {
  const g = tab.gateway;
  if (g?.state !== "up") return null;
  return `via RD Gateway ${g.host.replace(/:443$/, "")}`;
}

function clipboardPolicy(o: ProtocolOptions | undefined): ClipboardPolicy {
  return (o as Partial<RdpConnOptions & VncConnOptions> | undefined)?.clipboard ?? "both";
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
  const detach = useSessions((s) => s.detach);
  const [stats, setStats] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const vnc = tab.protocol === "vnc";
  const connected = tab.state === "connected";
  const cached = useConnOptions((s) => (connection ? s.byId[connection.id] : undefined));
  const policy = clipboardPolicy(cached ?? connection?.options);
  const toRemote = policy === "both" || policy === "to_remote";
  const viewOnly = vnc && tab.viewOnly;
  const inputEnabled = connected && !viewOnly && tab.prompt === null;
  const badge = securityBadge(connected ? tab.security : null);
  const name = connection?.name ?? "remote desktop";
  const viaGateway = tab.state === "closed" ? null : gatewayChip(tab);

  useEffect(() => {
    if (note === null) return;
    const t = window.setTimeout(() => { setNote(null); }, 3000);
    return () => { window.clearTimeout(t); };
  }, [note]);

  const onInput = useCallback((i: SessionInput) => { void input(tab.id, i); }, [input, tab.id]);
  const sid = tab.sessionId;
  const onAck = useCallback((seq: number) => { if (sid) ackSession(sid, seq); }, [sid]);
  // The size the canvas wants; sent when connected, and again once a (re)connect completes.
  const wanted = useRef<Size | null>(null);
  const requestDesktop = useCallback(() => {
    const d = useSessions.getState().tabs.find((t) => t.id === tab.id);
    const size = wanted.current;
    if (!size || d?.state !== "connected" || (d.desktop?.width === size.width && d.desktop.height === size.height)) return;
    void resize(tab.id, size);
  }, [resize, tab.id]);
  const onDesktopRequest = useCallback(
    (size: Size) => {
      wanted.current = size;
      requestDesktop();
    },
    [requestDesktop],
  );
  useEffect(() => {
    if (connected) requestDesktop();
  }, [connected, requestDesktop]);

  return (
    <div className="session-frame">
      <SessionHeader tab={tab} connection={connection}>
      <div role="toolbar" aria-label="Remote desktop tools" className="remote-toolbar">
        {badge && (
          <span className="chip" data-tone={badge.hot ? "danger" : "success"} title="Negotiated security">
            {badge.text}
          </span>
        )}
        {viaGateway && (
          <span className="chip" title={tab.gateway?.peerIdentity ? `RD Gateway certificate ${tab.gateway.peerIdentity}` : "RD Gateway"}>
            {viaGateway}
          </span>
        )}
        {vnc && (
          <span className="chip" data-tone={viewOnly ? "warning" : undefined} aria-live="polite">
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
        <DetachButton onDetach={connected && tab.sessionId ? () => void detach(tab.id) : null} />
      </div>
      <DisconnectButton tab={tab} />
      </SessionHeader>
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
          onCancelReconnect={() => void cancelReconnect(tab.id)}
        />
      </div>
    </div>
  );
}

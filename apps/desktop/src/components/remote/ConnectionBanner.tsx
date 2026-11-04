import { useEffect, useState } from "react";
import type { CloseCode } from "../../lib/ipc";
import { RECONNECT_MAX_ATTEMPTS } from "../../lib/ipc.types.remote";
import type { Tab } from "../../stores/sessions";

/** Heading and tone per close code (ADR-0011 `CloseCode`). */
export const CLOSE_TEXT: Record<CloseCode | "unknown", { title: string; hint: string | null; hot: boolean }> = {
  user: { title: "Session closed", hint: null, hot: false },
  network: { title: "Network lost", hint: "Mooring retried and gave up. Check the route to the host.", hot: true },
  auth_failed: { title: "Sign-in failed", hint: "Check the credential of this connection.", hot: true },
  trust_rejected: { title: "Certificate rejected", hint: "You declined the server certificate. Nothing was pinned.", hot: false },
  trust_mismatch: {
    title: "Certificate changed",
    hint: "The pinned certificate no longer matches. Remove the pin under Known certificates only after the server owner confirms the change.",
    hot: true,
  },
  server_ended: { title: "Remote ended the session", hint: null, hot: false },
  protocol_error: { title: "Protocol error", hint: "The server sent data Mooring refuses to parse. The session was stopped.", hot: true },
  vault_locked: { title: "Vault locked", hint: "Unlock the vault to reconnect.", hot: false },
  unknown: { title: "Disconnected", hint: null, hot: true },
};

/** Whole seconds until the next attempt, ticking while the banner is shown. */
function useCountdown(until: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (until === null) return;
    setNow(Date.now());
    const id = window.setInterval(() => { setNow(Date.now()); }, 250);
    return () => { window.clearInterval(id); };
  }, [until]);
  return until === null ? 0 : Math.max(0, Math.ceil((until - now) / 1000));
}

/**
 * The connection state over a remote canvas: connecting, reconnecting with the backoff countdown
 * (the Tauri layer retries; the UI only shows it), detached to another window, or closed with
 * the reason and a Reconnect button.
 */
export function ConnectionBanner({ tab, host, onReconnect, onClose }: { tab: Tab; host: string; onReconnect: () => void; onClose: () => void }) {
  const until = tab.state === "reconnecting" && tab.reconnect ? tab.reconnect.since + tab.reconnect.delayMs : null;
  const secs = useCountdown(until);

  if (tab.state === "connecting" && !tab.prompt) {
    return (
      <div className="link-banner m-hud" role="status" aria-live="polite">
        <span className="m-micro">Connecting</span>
        <span className="text-text-muted">Opening a session to {host}…</span>
      </div>
    );
  }

  if (tab.state === "reconnecting" && tab.reconnect) {
    const r = tab.reconnect;
    return (
      <div className="link-banner m-hud" data-tone="hot" role="status" aria-live="polite">
        <span className="m-micro" style={{ color: "var(--hot)" }}>Link lost · reconnecting</span>
        <span className="link-countdown" aria-label={`Next attempt in ${String(secs)} seconds`}>
          {secs > 0 ? `${String(secs)} s` : "now"}
        </span>
        <span className="text-text-muted">
          Attempt {r.attempt} of {RECONNECT_MAX_ATTEMPTS}. Mooring signs in again with the stored credential.
        </span>
        <div className="actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Stop and close
          </button>
        </div>
      </div>
    );
  }

  if (tab.state === "detached") {
    return (
      <div className="link-banner m-hud" role="status">
        <span className="m-micro">Detached</span>
        <span className="text-text-muted">This session is shown in its own window.</span>
      </div>
    );
  }

  if (tab.state === "closed") {
    const t = CLOSE_TEXT[tab.closeCode ?? "unknown"];
    return (
      <div className="link-banner m-hud" data-tone={t.hot ? "hot" : undefined} role="alert">
        <span className="m-micro" style={t.hot ? { color: "var(--hot)" } : undefined}>{t.title}</span>
        <span className="text-text">{tab.reason ?? "The session ended."}</span>
        {t.hint && <span className="text-[length:var(--fs-xs)] text-text-muted">{t.hint}</span>}
        <div className="actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Close tab
          </button>
          <button type="button" className="btn" onClick={onReconnect}>
            Reconnect
          </button>
        </div>
      </div>
    );
  }

  return null;
}

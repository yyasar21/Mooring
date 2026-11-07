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
    hint: "The stored certificate no longer matches. If the server was reinstalled, confirm the new fingerprint with its owner, then remove the stored certificate in Settings → Trust.",
    hot: true,
  },
  trust_conflict: {
    title: "Conflicting certificates",
    hint: "This host has two different trusted certificates (synced from another device). Mooring does not reconnect on its own: remove one in Settings → Trust, then connect again.",
    hot: true,
  },
  server_ended: { title: "Remote ended the session", hint: null, hot: false },
  protocol_error: { title: "Protocol error", hint: "The server sent data Mooring refuses to parse. The session was stopped.", hot: true },
  vault_locked: { title: "Vault locked", hint: "Unlock the vault to reconnect.", hot: false },
  // ADR-0025: jump hosts. The reason names the hop; the hint says what it means for the target.
  hop_failed: {
    title: "Jump host failed",
    hint: "A jump host did not come up, so Mooring never contacted the target. Check that jump host's host key and credential.",
    hot: true,
  },
  hop_lost: {
    title: "Jump host connection lost",
    hint: "The link through a jump host dropped. Remote desktops reconnect and rebuild the whole chain; a terminal needs Reconnect.",
    hot: true,
  },
  unknown: { title: "Disconnected", hint: null, hot: true },
};

/** `Date.now()`, ticking every 250 ms while `on`. */
function useNow(on: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!on) return;
    setNow(Date.now());
    const id = window.setInterval(() => { setNow(Date.now()); }, 250);
    return () => { window.clearInterval(id); };
  }, [on]);
  return now;
}

/** Seconds left and the elapsed fraction (0..1) of one backoff wait. */
export function backoffProgress(r: { delayMs: number; since: number }, now: number): { secs: number; fraction: number } {
  const left = Math.max(0, r.since + r.delayMs - now);
  const fraction = r.delayMs > 0 ? Math.min(1, Math.max(0, 1 - left / r.delayMs)) : 1;
  return { secs: Math.ceil(left / 1000), fraction };
}

/**
 * The connection state over a remote canvas: connecting, reconnecting with the backoff countdown
 * (the Tauri layer retries; the UI only shows it), or closed with the reason and a Reconnect
 * button. A detached session shows `DetachedPlaceholder` instead (Workspace).
 */
export function ConnectionBanner({ tab, host, onReconnect, onClose, onCancelReconnect }: {
  tab: Tab;
  host: string;
  onReconnect: () => void;
  onClose: () => void;
  onCancelReconnect: () => void;
}) {
  const now = useNow(tab.state === "reconnecting" && tab.reconnect !== null);

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
    const { secs, fraction } = backoffProgress(r, now);
    const attempt = Math.min(Math.max(1, r.attempt), RECONNECT_MAX_ATTEMPTS);
    return (
      <div className="link-banner m-hud" data-tone="hot" role="status" aria-live="polite" aria-label="Reconnecting">
        <span className="m-micro" style={{ color: "var(--hot)" }}>Link lost · reconnecting to {host}</span>
        <div className="flex items-end justify-between gap-3">
          <span className="link-countdown" aria-label={`Next attempt in ${String(secs)} seconds`}>
            {secs > 0 ? `${String(secs)} s` : "now"}
          </span>
          <ol className="link-attempts" aria-label={`Attempt ${String(attempt)} of ${String(RECONNECT_MAX_ATTEMPTS)}`}>
            {Array.from({ length: RECONNECT_MAX_ATTEMPTS }, (_, i) => (
              <li key={i} data-state={i + 1 < attempt ? "spent" : i + 1 === attempt ? "now" : undefined} />
            ))}
          </ol>
        </div>
        <div className="link-progress" aria-hidden>
          <span style={{ transform: `scaleX(${fraction.toFixed(3)})` }} />
        </div>
        <span className="text-text-muted">
          Attempt {attempt} of {RECONNECT_MAX_ATTEMPTS}. Mooring signs in again with the stored credential; it never retries after a
          sign-in or certificate failure.
        </span>
        <div className="actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Close tab
          </button>
          <button type="button" className="btn btn-danger" onClick={onCancelReconnect}>
            Cancel reconnect
          </button>
        </div>
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

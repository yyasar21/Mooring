import { useEffect, useState } from "react";
import type { Tab } from "../../stores/sessions";
import { shortFingerprint } from "../../lib/credentials.sk";

/** `Date.now()`, ticking once a second while `on`. */
function useSecondTick(on: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!on) return;
    setNow(Date.now());
    const id = window.setInterval(() => { setNow(Date.now()); }, 1000);
    return () => { window.clearInterval(id); };
  }, [on]);
  return now;
}

/** Seconds left before Rust gives up waiting for the touch. */
export function touchSecondsLeft(t: { since: number; timeoutSeconds: number }, now: number): number {
  return Math.max(0, Math.ceil((t.since + t.timeoutSeconds * 1000 - now) / 1000));
}

/**
 * ADR-0024: "Touch your security key" over the terminal while a FIDO2 key signs. Non-modal: it
 * takes no answer and no focus (the agent talks to the key). After `touch_timeout` it says so and
 * offers Retry once the session has closed.
 */
export function TouchBanner({ tab, onRetry }: { tab: Tab; onRetry: () => void }) {
  const t = tab.touch;
  const now = useSecondTick(t !== null && t !== undefined && !t.timedOut);
  if (!t) return null;
  const hop = t.hop !== null ? `Hop ${String(t.hop + 1)}: ` : "";
  const below = (tab.hops?.length ?? 0) > 0 || undefined;
  const key = t.fingerprint ? shortFingerprint(t.fingerprint) : "";

  if (t.timedOut) {
    return (
      <div className="touch-banner" data-tone="hot" data-below-hops={below} role="alert" aria-label="Security key not touched">
        <div className="touch-text">
          <p className="touch-title">{hop}No touch within {t.timeoutSeconds} seconds</p>
          <p className="touch-sub">
            Mooring stopped signing in{key && <> with <span className="mono" title={t.fingerprint}>{key}</span></>} and did not try a password.
          </p>
        </div>
        {tab.state === "closed" && <button type="button" className="btn" onClick={onRetry}>Retry</button>}
      </div>
    );
  }

  const secs = touchSecondsLeft(t, now);
  return (
    <div className="touch-banner" data-below-hops={below}>
      <span className="touch-indicator" aria-hidden><span /></span>
      <div className="touch-text">
        <p className="touch-title" role="status">{hop}Touch your security key to continue</p>
        <p className="touch-sub">
          {key && <>Key <span className="mono" title={t.fingerprint}>{key}</span> · </>}
          <span className="tnum" aria-label={`${String(secs)} seconds left`}>{secs} s left</span>
        </p>
      </div>
    </div>
  );
}

/** Pre-flight refusals of ADR-0024 (`session_open` errors): a readable title and what to do next. */
export const SK_CLOSE: Readonly<Record<string, { title: string; hint: string }>> = {
  "ssh.sk_key_not_in_agent": { title: "Security key not in ssh-agent", hint: "ssh-add -K loads a resident key from the security key; ssh-add <handle file> loads the others. Then press Reconnect." },
  "ssh.sk_helper_disabled": { title: "Direct security-key signing is off", hint: "Edit the credential and choose Through your ssh-agent, then press Reconnect." },
  "ssh.sk_helper_missing": { title: "ssh-sk-helper not found", hint: "Edit the credential and choose Through your ssh-agent, then press Reconnect." },
};

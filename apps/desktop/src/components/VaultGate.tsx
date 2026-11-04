import { useState } from "react";
import type { LockReason } from "../lib/ipc";
import { useApp } from "../stores/app";
import { VaultJoin } from "./VaultJoin";

const LOCK_TEXT: Record<Exclude<LockReason, "user"> | "unknown", string> = {
  idle: "Locked after a period of inactivity.",
  screen_lock: "Locked because the screen was locked.",
  sleep: "Locked because the computer went to sleep.",
  window_hidden: "Locked because the Mooring window was hidden.",
  unknown: "Locked by Mooring.",
};

/** Message for the unlock screen after an automatic lock; null after a user lock. */
export function lockReasonText(reason: LockReason | "unknown" | null): string | null {
  return reason === null || reason === "user" ? null : LOCK_TEXT[reason];
}

/**
 * The airlock: onboarding (no vault yet) and unlock (vault locked). Both are one field, the master
 * password. Visual drama lives in CSS (`airlock.css`): one sweep on arrival, a pressure bar while
 * the key is derived, nothing looping at rest.
 */
export function VaultGate({ mode }: { mode: "create" | "unlock" }) {
  const createVault = useApp((s) => s.createVault);
  const unlock = useApp((s) => s.unlock);
  const lastError = useApp((s) => s.lastError);
  const reason = lockReasonText(useApp((s) => s.lockReason));
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  // ADR-0017: a fresh device may pull an existing synced vault instead of creating one.
  const [join, setJoin] = useState(false);
  if (join) return <VaultJoin onBack={() => { setJoin(false); }} />;

  const mismatch = mode === "create" && confirm.length > 0 && confirm !== password;
  const tooShort = mode === "create" && password.length > 0 && password.length < 12;
  const canSubmit = password.length > 0 && !mismatch && !tooShort && !busy;

  async function submit() {
    if (!canSubmit) return;
    setBusy(true);
    await (mode === "create" ? createVault(password) : unlock(password));
    setPassword("");
    setConfirm("");
    setBusy(false);
  }

  return (
    <main className="airlock">
      <Rings />
      <div aria-hidden className="airlock-sweep" />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
        className="airlock-hatch m-hud"
        data-active
      >
        <div className="airlock-kicker">
          <span className="m-micro">Mooring vault</span>
          <span className="m-micro">{mode === "create" ? "Not initialised" : "Sealed"}</span>
        </div>
        {mode === "unlock" && reason && (
          <p role="status" className="airlock-reason">
            <span aria-hidden className="airlock-reason-mark" />
            <span>
              {reason} Sessions, forwards and transfers were closed.
            </span>
          </p>
        )}
        <h1 className="airlock-title">{mode === "create" ? "Create your vault" : "Unlock Mooring"}</h1>
        <p className="airlock-copy">
          {mode === "create"
            ? "Everything you save is encrypted with this password. It is never stored and cannot be recovered."
            : "Your connections and credentials stay encrypted until you unlock."}
        </p>

        <div className="airlock-field">
          <label className="field-label" htmlFor="pw">
            Master password
          </label>
          <input
            id="pw"
            type="password"
            autoFocus
            autoComplete={mode === "create" ? "new-password" : "current-password"}
            value={password}
            onChange={(e) => { setPassword(e.target.value); }}
            className="airlock-input"
          />
        </div>
        {mode === "create" && (
          <div className="airlock-field" style={{ marginTop: 14 }}>
            <label className="field-label" htmlFor="pw2">
              Repeat password
            </label>
            <input
              id="pw2"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => { setConfirm(e.target.value); }}
              className="airlock-input"
            />
          </div>
        )}

        <p className="airlock-error" role="alert">
          {tooShort && "Use at least 12 characters. Length matters more than symbols."}
          {mismatch && "The two passwords differ."}
          {!tooShort && !mismatch && lastError}
        </p>

        <button type="submit" disabled={!canSubmit} className="airlock-submit" data-busy={busy || undefined}>
          {busy ? "Deriving key…" : mode === "create" ? "Create vault" : "Unlock"}
        </button>

        <div className="airlock-foot">
          <span className="m-micro">Argon2id · XChaCha20-Poly1305</span>
          {mode === "create" ? (
            <button type="button" className="airlock-link" onClick={() => { setJoin(true); }}>Join a synced vault instead</button>
          ) : (
            <span className="m-micro">Local only</span>
          )}
        </div>
      </form>
    </main>
  );
}

/** Static range rings and bearing ticks behind the hatch. Drawn once; never animated. */
function Rings() {
  const ticks = Array.from({ length: 72 }, (_, i) => i * 5);
  return (
    <svg className="airlock-rings" viewBox="-410 -410 820 820" aria-hidden fill="none" stroke="currentColor">
      <circle r="400" strokeWidth="1" />
      <circle r="330" strokeWidth="1" strokeDasharray="2 6" />
      <circle r="260" strokeWidth="1" />
      {ticks.map((a) => (
        <line
          key={a}
          className={a % 45 === 0 ? "tick" : undefined}
          x1="0"
          y1={a % 45 === 0 ? -372 : -388}
          x2="0"
          y2="-400"
          strokeWidth={a % 45 === 0 ? 2 : 1}
          transform={`rotate(${a})`}
        />
      ))}
      <path d="M-410 0h140M270 0h140M0 -410v140M0 270v140" strokeWidth="1" strokeDasharray="1 4" />
    </svg>
  );
}

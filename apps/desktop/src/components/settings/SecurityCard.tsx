import { useEffect, useRef, useState } from "react";
import { biometricName, suspendedText, unavailableText, useBiometric } from "../../stores/biometric";
import { SettingsCard, Toggle } from "./Toggle";

/**
 * Settings → Security (ADR-0022): "Unlock with Touch ID / Windows Hello". Turning it on or off
 * asks for the master password first (Rust checks it); the OS prompt only appears after that
 * click. Unavailable and suspended states explain themselves under the switch.
 */
export function SecurityCard() {
  const status = useBiometric((s) => s.status);
  const busy = useBiometric((s) => s.busy);
  const error = useBiometric((s) => s.error);
  const notice = useBiometric((s) => s.notice);
  const [asking, setAsking] = useState<"enroll" | "disable" | null>(null);

  useEffect(() => {
    const b = useBiometric.getState();
    b.clearMessages();
    void b.load();
  }, []);

  const name = biometricName(status);
  const unavailable = status ? unavailableText(status) : null;
  const suspended = status ? suspendedText(status) : null;
  const on = status?.enabled ?? false;

  const hint = unavailable
    ?? (on
      ? "On. The unlock screen offers it; the master password always works too. Mooring never starts the system prompt without a click."
      : `Off. Turn it on to unlock with ${name} instead of typing the master password. The master password stays the way back in.`);

  return (
    <SettingsCard title="Security" labelledBy="security-title">
      <div className="settings-body">
        <Toggle
          checked={on}
          disabled={status === null || busy || (!status.available && !on)}
          onChange={(next) => {
            useBiometric.getState().clearMessages();
            setAsking(next ? "enroll" : "disable");
          }}
          label={`Unlock with ${name}`}
          hint={hint}
        />
        {suspended && <p role="status" className="settings-warn" data-testid="biometric-suspended">{suspended}</p>}
        {asking && (
          <PasswordStep
            action={asking}
            name={name}
            busy={busy}
            onCancel={() => { setAsking(null); }}
            onSubmit={async (password) => {
              const b = useBiometric.getState();
              const ok = asking === "enroll" ? await b.enroll(password) : await b.disable(password);
              if (ok) setAsking(null);
            }}
          />
        )}
        {error && <p role="alert" className="settings-err">{error}</p>}
        {notice && <p role="status" className="settings-ok">{notice}</p>}
      </div>
    </SettingsCard>
  );
}

/** The master password for enrol / disable. Uncontrolled: read once on submit, then cleared. */
function PasswordStep({ action, name, busy, onCancel, onSubmit }: {
  action: "enroll" | "disable";
  name: string;
  busy: boolean;
  onCancel: () => void;
  onSubmit: (password: string) => Promise<void>;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const [empty, setEmpty] = useState(false);
  useEffect(() => { ref.current?.focus(); }, [action]);
  return (
    <form
      className="sec-form"
      aria-label={action === "enroll" ? `Turn on ${name} unlock` : `Turn off ${name} unlock`}
      onSubmit={(e) => {
        e.preventDefault();
        const password = ref.current?.value ?? "";
        if (ref.current) ref.current.value = "";
        if (!password) {
          setEmpty(true);
          return;
        }
        setEmpty(false);
        void onSubmit(password);
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onCancel();
        }
      }}
    >
      <label className="field-label" htmlFor="bio-pw">Master password</label>
      <input ref={ref} id="bio-pw" type="password" className="field" autoComplete="current-password" aria-invalid={empty || undefined} />
      <p className="field-hint">
        {action === "enroll"
          ? `Mooring checks the password, then ${name} asks you to confirm. The key it stores opens only this vault on this computer.`
          : `Mooring removes its key from ${name}. You unlock with the master password from then on.`}
      </p>
      {empty && <p role="alert" className="settings-err">Enter the master password.</p>}
      <div className="sec-actions">
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Waiting for the system…" : action === "enroll" ? `Turn on ${name}` : `Turn off ${name}`}
        </button>
      </div>
    </form>
  );
}

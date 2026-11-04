import { useEffect, useState } from "react";
import { ipc, IDLE_MINUTES, type AutoLockPolicy } from "../../lib/ipc";
import { validateIdleMinutes } from "../../lib/validate.exit";
import { describeError } from "../../stores/errors";
import { SettingsCard, Toggle } from "./Toggle";

const DEFAULT_IDLE = 15;

/** ADR-0006 / ADR-0010 auto-lock policy: idle minutes (or never) and the OS triggers. */
export function AutoLockCard() {
  const [saved, setSaved] = useState<AutoLockPolicy | null>(null);
  const [idleOn, setIdleOn] = useState(true);
  const [minutes, setMinutes] = useState(String(DEFAULT_IDLE));
  const [flags, setFlags] = useState({ onScreenLock: true, onSleep: true, onWindowHidden: true });
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const adopt = (p: AutoLockPolicy) => {
    setSaved(p);
    setIdleOn(p.idleMinutes !== null);
    setMinutes(String(p.idleMinutes ?? DEFAULT_IDLE));
    setFlags({ onScreenLock: p.onScreenLock, onSleep: p.onSleep, onWindowHidden: p.onWindowHidden });
  };

  useEffect(() => {
    let live = true;
    ipc.autolockGet().then((p) => { if (live) adopt(p); }, (e: unknown) => { if (live) setError(describeError(e)); });
    return () => { live = false; };
  }, []);

  const idleMinutes = idleOn ? (minutes.trim() === "" ? Number.NaN : Number(minutes)) : null;
  const idleError = validateIdleMinutes(idleMinutes);
  const draft: AutoLockPolicy = { idleMinutes, ...flags };
  const dirty = saved !== null && JSON.stringify(draft) !== JSON.stringify(saved);
  const neverLocks = !idleOn && !flags.onScreenLock && !flags.onSleep && !flags.onWindowHidden;

  const save = async () => {
    if (idleError || busy) return;
    setBusy(true);
    try {
      adopt(await ipc.autolockSet(draft));
      setError(null);
      setStatus("Saved.");
    } catch (e: unknown) {
      setError(describeError(e));
      setStatus(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsCard title="Auto-lock" kicker="Vault" labelledBy="autolock-title">
      <form
        className="settings-body"
        onSubmit={(e) => { e.preventDefault(); void save(); }}
        onChange={() => { setStatus(null); }}
      >
        <div className="settings-idle">
          <Toggle checked={idleOn} onChange={setIdleOn} label="Lock when idle" hint="No keyboard or mouse activity in Mooring." />
          <div className="settings-minutes">
            <label className="field-label" htmlFor="idle-min">Minutes</label>
            <input
              id="idle-min"
              className="field mono tnum"
              inputMode="numeric"
              disabled={!idleOn}
              value={idleOn ? minutes : ""}
              placeholder={idleOn ? undefined : "never"}
              aria-invalid={idleOn && idleError ? true : undefined}
              aria-describedby="idle-hint"
              onChange={(e) => { setMinutes(e.target.value); }}
            />
          </div>
        </div>
        <p id="idle-hint" className={idleError ? "settings-err" : "field-hint"} role={idleError ? "alert" : undefined}>
          {idleError ?? `${IDLE_MINUTES.min} to ${IDLE_MINUTES.max} minutes.`}
        </p>

        <div className="settings-toggles">
          <Toggle checked={flags.onScreenLock} onChange={(v) => { setFlags({ ...flags, onScreenLock: v }); }} label="When the screen locks" />
          <Toggle checked={flags.onSleep} onChange={(v) => { setFlags({ ...flags, onSleep: v }); }} label="When the computer sleeps" />
          <Toggle checked={flags.onWindowHidden} onChange={(v) => { setFlags({ ...flags, onWindowHidden: v }); }} label="When the Mooring window is hidden" hint="Minimised, or another app is in front." />
        </div>
        <p className="field-hint">Where the operating system does not report screen lock or sleep, the idle timer covers it.</p>
        {neverLocks && <p className="settings-warn">With every trigger off, the vault stays open until you lock it.</p>}

        <div className="settings-foot">
          <p role="alert" className="settings-err flex-1">{error}</p>
          {status && <p role="status" className="settings-ok">{status}</p>}
          <button type="submit" className="btn btn-primary" disabled={!dirty || idleError !== null || busy}>Save</button>
        </div>
      </form>
    </SettingsCard>
  );
}

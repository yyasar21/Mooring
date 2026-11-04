import { useEffect, useState } from "react";
import {
  ipc,
  SYSLOG_DEFAULT_PORT,
  SYSLOG_FACILITIES,
  type SyslogConfig,
  type SyslogFacility,
  type SyslogTestResult,
  type SyslogTransport,
} from "../../lib/ipc";
import { hasErrors, validateSyslog } from "../../lib/validate.exit";
import { describeError } from "../../stores/errors";
import { SettingsCard, Toggle } from "./Toggle";

const TRANSPORTS: { id: SyslogTransport; label: string }[] = [
  { id: "udp", label: "UDP" },
  { id: "tcp", label: "TCP" },
  { id: "tls", label: "TLS" },
];

const BLANK: SyslogConfig = { host: "", port: SYSLOG_DEFAULT_PORT.tls, transport: "tls", facility: "authpriv", enabled: false };

/** ADR-0010 item 5: mirror every audit entry to a syslog server as RFC 5424. */
export function SyslogCard() {
  const [saved, setSaved] = useState<SyslogConfig | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(String(BLANK.port));
  const [transport, setTransport] = useState<SyslogTransport>(BLANK.transport);
  const [facility, setFacility] = useState<SyslogFacility>(BLANK.facility);
  const [enabled, setEnabled] = useState(false);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<SyslogTestResult | null>(null);
  const [busy, setBusy] = useState(false);

  const adopt = (c: SyslogConfig) => {
    setSaved(c);
    setHost(c.host);
    setPort(String(c.port));
    setTransport(c.transport);
    setFacility(c.facility);
    setEnabled(c.enabled);
  };

  useEffect(() => {
    let live = true;
    ipc.syslogGet().then(
      (c) => { if (!live) return; if (c) adopt(c); setLoaded(true); },
      (e: unknown) => { if (live) setError(describeError(e)); },
    );
    return () => { live = false; };
  }, []);

  const draft: SyslogConfig = { host: host.trim(), port: port.trim() === "" ? Number.NaN : Number(port), transport, facility, enabled };
  const errors = validateSyslog(draft);
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved ?? { ...BLANK, host: "" });
  const show = (k: keyof typeof errors) => (touched ? errors[k] : undefined);

  const changeTransport = (t: SyslogTransport) => {
    if (Number(port) === SYSLOG_DEFAULT_PORT[transport]) setPort(String(SYSLOG_DEFAULT_PORT[t]));
    setTransport(t);
  };

  const save = async () => {
    setTouched(true);
    if (hasErrors(errors) || busy) return;
    setBusy(true);
    try {
      adopt(await ipc.syslogSet(draft));
      setError(null);
      setTest(null);
      setStatus("Saved.");
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  const sendTest = async () => {
    setBusy(true);
    try {
      setTest(await ipc.syslogTest());
      setError(null);
    } catch (e: unknown) {
      setTest(null);
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsCard title="Syslog mirror" kicker="Audit" labelledBy="syslog-title">
      <form
        className="settings-body"
        aria-busy={!loaded || undefined}
        onSubmit={(e) => { e.preventDefault(); void save(); }}
        onChange={() => { setStatus(null); setTest(null); }}
      >
        <p className="field-hint mt-0">
          Every audit entry is also sent to your syslog server (RFC 5424). The local log is written first; a send failure never blocks it.
        </p>
        <Toggle checked={enabled} onChange={setEnabled} label="Mirror audit entries" />

        <div className="settings-grid">
          <div>
            <label className="field-label" htmlFor="sl-host">Host</label>
            <input id="sl-host" className="field mono" value={host} spellCheck={false} placeholder="logs.example.test"
              aria-invalid={show("host") ? true : undefined} onChange={(e) => { setHost(e.target.value); }} />
            {show("host") && <p className="settings-err" role="alert">{show("host")}</p>}
          </div>
          <div>
            <label className="field-label" htmlFor="sl-port">Port</label>
            <input id="sl-port" className="field mono tnum" inputMode="numeric" value={port}
              aria-invalid={show("port") ? true : undefined} onChange={(e) => { setPort(e.target.value); }} />
            {show("port") && <p className="settings-err" role="alert">{show("port")}</p>}
          </div>
        </div>

        <div className="settings-grid">
          <fieldset className="settings-seg">
            <legend className="field-label">Transport</legend>
            {TRANSPORTS.map((t) => (
              <label key={t.id} className="seg-opt" data-checked={transport === t.id || undefined}>
                <input type="radio" name="sl-transport" value={t.id} checked={transport === t.id} onChange={() => { changeTransport(t.id); }} />
                {t.label}
              </label>
            ))}
          </fieldset>
          <div>
            <label className="field-label" htmlFor="sl-facility">Facility</label>
            <select id="sl-facility" className="field" value={facility} onChange={(e) => { setFacility(e.target.value as SyslogFacility); }}>
              {SYSLOG_FACILITIES.map((f, i) => (
                <option key={f} value={f}>{`${f} (${i})`}</option>
              ))}
            </select>
          </div>
        </div>
        {transport !== "tls" && (
          <p className="settings-warn">Entries travel unencrypted over {transport.toUpperCase()}. Use TLS across networks you do not control.</p>
        )}

        <div className="settings-foot">
          <p role="alert" className="settings-err flex-1">{error}</p>
          {status && <p role="status" className="settings-ok">{status}</p>}
          <button type="button" className="btn" disabled={busy || saved === null || dirty}
            title={dirty ? "Save first" : undefined} onClick={() => void sendTest()}>
            Send test entry
          </button>
          <button type="submit" className="btn btn-primary" disabled={!dirty || busy}>Save</button>
        </div>
        {test && (
          <p role="status" className={test.ok ? "settings-ok" : "settings-err"} aria-label="Test result">
            {test.ok
              ? transport === "udp"
                ? "Test entry sent. UDP cannot confirm that it arrived."
                : "Test entry delivered."
              : `Test entry failed: ${test.error ?? "no reason given"}.`}
          </p>
        )}
      </form>
    </SettingsCard>
  );
}

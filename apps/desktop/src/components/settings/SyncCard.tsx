import { useEffect, useState } from "react";
import type { SyncConflict, SyncResolution, SyncRunState, SyncStatus } from "../../lib/ipc";
import { useCredentials } from "../../stores/credentials";
import { useSync } from "../../stores/sync";
import { SyncConfigDialog } from "./SyncConfigDialog";
import { SettingsCard } from "./Toggle";

const STATE_LABEL: Record<SyncRunState, string> = {
  disabled: "Off", idle: "Idle", running: "Syncing", error: "Error", fork: "Fork", rollback: "Rollback",
};

export function fmtUnix(t: number | null, now = Date.now()): string {
  if (t === null) return "never";
  const d = new Date(t * 1000);
  const diff = Math.round((now / 1000 - t));
  if (Math.abs(diff) < 60) return diff >= 0 ? "just now" : "in under a minute";
  const rel = Math.abs(diff) < 3600 ? `${Math.round(Math.abs(diff) / 60)} min` : Math.abs(diff) < 86400 ? `${Math.round(Math.abs(diff) / 3600)} h` : `${Math.round(Math.abs(diff) / 86400)} d`;
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC (${diff >= 0 ? `${rel} ago` : `in ${rel}`})`;
}

export function resolutionText(r: SyncResolution): string {
  switch (r.type) {
    case "keptBoth":
      return `both copies kept; the remote one is "… (conflict from <device>)"`;
    case "keptEdit":
      return "deleted on one side, edited on the other: the edit was kept";
    case "lastWriterWins":
      return "the newer edit won";
  }
}

function alarmText(s: SyncStatus): string {
  const by = s.remoteDevice ? ` by ${s.remoteDevice}` : "";
  if (s.alarm?.type === "fork") {
    return `Two devices published generation ${s.alarm.remote}${by}. Sync has stopped on this device until you choose which history to keep. Nothing was applied.`;
  }
  if (s.alarm?.type === "rollback") {
    return `The bucket holds generation ${s.alarm.remote}, older than the ${s.alarm.last} this device has seen${by}. This can be a restored backup or tampering. Nothing was applied.`;
  }
  return "";
}

function ConflictList({ conflicts }: { conflicts: SyncConflict[] }) {
  return (
    <div>
      <span className="field-label">Conflicts of the last merge</span>
      <ul className="trust-list" aria-label="Merge conflicts">
        {conflicts.map((c) => (
          <li key={`${c.kind}-${c.id}`} className="trust-row">
            <p className="trust-target"><span className="trust-names">{c.kind}</span><span className="text-text">{c.name}</span></p>
            <p className="field-hint text-right">{resolutionText(c.resolution)}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Settings → Vault sync (ADR-0017): status from `sync_status` + the `sync:status` event, and every action. */
export function SyncCard() {
  const status = useSync((s) => s.status);
  const error = useSync((s) => s.error);
  const notice = useSync((s) => s.notice);
  const busy = useSync((s) => s.busy);
  const creds = useCredentials((s) => s.items);
  const [configuring, setConfiguring] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [tick, setTick] = useState(Date.now());

  useEffect(() => {
    const sync = useSync.getState();
    void sync.load();
    const off = sync.watch();
    const t = setInterval(() => { setTick(Date.now()); }, 30_000);
    return () => { off(); clearInterval(t); };
  }, []);

  const s = status;
  const on = s !== null && s.config !== null;
  const key = on ? creds.find((c) => c.id === s.config?.credentialId) : undefined;
  const trustHint = s?.lastError?.code === "http.trust_prompt";

  return (
    <SettingsCard title="Vault sync" kicker="Devices" labelledBy="sync-title">
      <div className="settings-body" aria-busy={busy || undefined}>
        <p className="field-hint mt-0">
          Keeps this vault's folders, connections, credentials and trust stores in an S3 bucket as one encrypted blob (sealed with a key
          derived from the vault key). Every synced device unlocks with the same master password. Audit logs stay per device.
        </p>
        {error && <p role="alert" className="settings-err">{error}</p>}
        {notice && <p role="status" className="settings-ok">{notice}</p>}

        {s === null ? (
          <p className="field-hint" role="status">Loading…</p>
        ) : (
          <div className="sync-status" data-state={s.state} aria-label="Sync status">
            <div className="sync-state">
              <span aria-hidden className="state-dot" data-state={s.state === "running" ? "connecting" : s.state === "idle" ? "connected" : "closed"} />
              <span className="sync-state-label">{STATE_LABEL[s.state]}</span>
              <span className="m-micro ml-auto tnum">gen {s.counter}{s.remoteCounter !== null ? ` · remote ${s.remoteCounter}` : ""}</span>
            </div>
            {on && (
              <dl className="sync-facts">
                <dt>Storage</dt><dd className="mono select-text">{s.config?.backend.endpoint} / {s.config?.backend.bucket}{s.config?.backend.prefix ? ` / ${s.config.backend.prefix}` : ""}</dd>
                <dt>Access key</dt><dd>{key ? key.name : "credential missing"}</dd>
                <dt>Schedule</dt><dd>{s.config?.intervalMinutes === null ? "manual only" : `every ${s.config?.intervalMinutes} min`}{s.nextRunUnix !== null ? ` · next ${fmtUnix(s.nextRunUnix, tick)}` : ""}</dd>
                <dt>Last run</dt><dd>{fmtUnix(s.lastRunUnix, tick)}</dd>
                <dt>Last push</dt><dd>{fmtUnix(s.lastPushUnix, tick)}</dd>
                <dt>Last pull</dt><dd>{fmtUnix(s.lastPullUnix, tick)}{s.remoteDevice ? ` · last pushed by ${s.remoteDevice} ${fmtUnix(s.remoteCreatedUnix, tick)}` : ""}</dd>
                <dt>Vault id</dt><dd className="mono select-text">{s.vaultId}</dd>
                {s.deviceId && <><dt>This device</dt><dd className="mono">{s.deviceId}</dd></>}
              </dl>
            )}
            {!on && <p className="field-hint">Not configured. This vault's id is <span className="mono select-text">{s.vaultId}</span>; another device needs it to join.</p>}
            {s.lastError && (
              <p role="alert" className="settings-err">
                Last run failed: {s.lastError.message}{trustHint ? " — run Sync now to answer the certificate prompt." : ""}
              </p>
            )}
          </div>
        )}

        {s?.alarm && (
          <div className="sync-alarm" role="alert">
            <p className="sync-alarm-title">{s.alarm.type === "fork" ? "Fork detected" : "Rollback detected"}</p>
            <p>{alarmText(s)}</p>
            <div className="flex flex-wrap gap-2">
              <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void useSync.getState().resolve("local")}>Resolve: keep local</button>
              <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void useSync.getState().resolve("remote")}>Resolve: keep remote</button>
            </div>
            <p className="field-hint">Mooring asks you to confirm in a system dialog before anything is discarded.</p>
          </div>
        )}

        {s && s.conflicts.length > 0 && <ConflictList conflicts={s.conflicts} />}

        <div className="settings-foot">
          {on && !disabling && (
            <button type="button" className="btn btn-ghost btn-danger" disabled={busy} onClick={() => { setDisabling(true); }}>Disable…</button>
          )}
          {on && disabling && (
            <>
              <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void useSync.getState().disable(false).then(() => { setDisabling(false); })}>Disable, keep bucket</button>
              <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void useSync.getState().disable(true).then(() => { setDisabling(false); })}>Disable and delete remote</button>
              <button type="button" className="btn btn-ghost" onClick={() => { setDisabling(false); }}>Cancel</button>
            </>
          )}
          <span className="flex-1" />
          <button type="button" className="btn" disabled={s === null} onClick={() => { setConfiguring(true); }}>{on ? "Settings…" : "Set up…"}</button>
          {on && <button type="button" className="btn btn-primary" disabled={busy || s.alarm !== null} onClick={() => void useSync.getState().syncNow()}>Sync now</button>}
        </div>
      </div>
      {configuring && (
        <SyncConfigDialog current={s?.config ?? null} onClose={() => { setConfiguring(false); }} onSave={(c) => useSync.getState().configure(c)} />
      )}
    </SettingsCard>
  );
}

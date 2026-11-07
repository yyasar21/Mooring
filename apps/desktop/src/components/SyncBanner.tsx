import { useEffect } from "react";
import type { SyncStatus } from "../lib/ipc";
import { alarmKey, trustConflictText, trustConflicts, useSync } from "../stores/sync";
import { useUi, type SettingsIntent } from "../stores/ui";

/**
 * Global vault-sync alarm (ADR-0017, U3 decision 2). The shell subscribes to `sync:status` once
 * so a fork, a rollback, a trust conflict (review 6b L-35) or a failed background run is visible
 * wherever the user is, not only on the settings card. Resolving stays on the card (or, for a
 * trust conflict, in the known-certificates manager): this banner only names the problem and
 * jumps there. Dismissal is per alarm and per unlocked session (`useSync.dismiss`).
 */
export function SyncBanner() {
  const status = useSync((s) => s.status);
  const dismissed = useSync((s) => s.dismissed);
  const view = useUi((s) => s.view);

  useEffect(() => {
    const sync = useSync.getState();
    void sync.load();
    return sync.watch();
  }, []);

  const key = alarmKey(status);
  if (!status || key === null || key === dismissed || view === "settings") return null;
  const alarm = status.alarm;
  const trust = !alarm && trustConflicts(status).length > 0;
  const title = alarm ? (alarm.type === "fork" ? "Sync fork detected" : "Sync rollback detected") : trust ? "Certificate trust conflict" : "Vault sync failed";

  return (
    <div className="sync-banner" role="alert" data-kind={alarm || trust ? "alarm" : "error"}>
      <span aria-hidden className="state-dot" data-state="closed" />
      <p className="sync-banner-text">
        <strong className="sync-banner-title">{title}</strong>
        <span>{bannerText(status)}</span>
      </p>
      {trust ? (
        <button type="button" className="btn btn-primary" onClick={() => { openSettingsCard("trust-title"); }}>
          Open known certificates
        </button>
      ) : (
        <button type="button" className="btn btn-primary" onClick={() => { openSettingsCard("sync-title"); }}>
          Open Vault sync settings
        </button>
      )}
      <button type="button" className="btn btn-ghost" aria-label="Dismiss sync notice" onClick={() => { useSync.getState().dismiss(); }}>
        Dismiss
      </button>
    </div>
  );
}

/** One line: what happened and that nothing was applied. The card carries the long form. */
export function bannerText(s: SyncStatus): string {
  const by = s.remoteDevice ? ` by ${s.remoteDevice}` : "";
  if (s.alarm?.type === "fork") {
    return `Two devices published generation ${s.alarm.remote}${by}. Sync is paused on this device until you choose which history to keep.`;
  }
  if (s.alarm?.type === "rollback") {
    return `The bucket holds generation ${s.alarm.remote}, older than the ${s.alarm.last} this device has seen${by}. Sync is paused until you resolve it.`;
  }
  const [first, ...rest] = trustConflicts(s);
  if (first) {
    const more = rest.length > 0 ? ` ${String(rest.length)} more host${rest.length > 1 ? "s" : ""} in Settings → Trust.` : "";
    return `${trustConflictText(first)}${more}`;
  }
  if (s.lastError) {
    const hint = s.lastError.code === "http.trust_prompt" ? " Run Sync now from the settings to answer the certificate prompt." : "";
    return `The last run failed: ${s.lastError.message}.${hint}`;
  }
  return "";
}

/**
 * Settings view, then the named card's heading gets focus so its controls are one Tab away.
 * `intent` is something the card does on mount (U0: open "Add source…" for a chosen AppRole).
 */
export function openSettingsCard(headingId: "sync-title" | "trust-title" | "updates-title" | "sources-title", intent?: SettingsIntent): void {
  useUi.getState().showSettings(intent);
  requestAnimationFrame(() => {
    const h = document.getElementById(headingId);
    if (!h) return;
    h.tabIndex = -1;
    h.scrollIntoView({ block: "start" });
    h.focus();
  });
}

/** Title-bar hint while a run is in progress; nothing in the DOM otherwise. */
export function SyncIndicator() {
  const running = useSync((s) => s.status?.state === "running");
  if (!running) return null;
  return (
    <span className="sync-indicator" role="status">
      <span aria-hidden className="state-dot" data-state="connecting" />
      Syncing…
    </span>
  );
}

import { useEffect } from "react";
import type { SyncStatus } from "../lib/ipc";
import { alarmKey, useSync } from "../stores/sync";
import { useUi } from "../stores/ui";

/**
 * Global vault-sync alarm (ADR-0017, U3 decision 2). The shell subscribes to `sync:status` once
 * so a fork, a rollback or a failed background run is visible wherever the user is, not only on
 * the settings card. Resolving stays on the card: this banner only names the problem and jumps
 * there. Dismissal is per alarm and per unlocked session (`useSync.dismiss`).
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
  const title = alarm ? (alarm.type === "fork" ? "Sync fork detected" : "Sync rollback detected") : "Vault sync failed";

  return (
    <div className="sync-banner" role="alert" data-kind={alarm ? "alarm" : "error"}>
      <span aria-hidden className="state-dot" data-state="closed" />
      <p className="sync-banner-text">
        <strong className="sync-banner-title">{title}</strong>
        <span>{bannerText(status)}</span>
      </p>
      <button type="button" className="btn btn-primary" onClick={openSyncSettings}>
        Open Vault sync settings
      </button>
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
  if (s.lastError) {
    const hint = s.lastError.code === "http.trust_prompt" ? " Run Sync now from the settings to answer the certificate prompt." : "";
    return `The last run failed: ${s.lastError.message}.${hint}`;
  }
  return "";
}

/** Settings view, then the Vault sync card's heading gets focus so the resolve controls are one Tab away. */
function openSyncSettings(): void {
  useUi.getState().setView("settings");
  requestAnimationFrame(() => {
    const h = document.getElementById("sync-title");
    if (!h) return;
    h.tabIndex = -1;
    h.scrollIntoView({ block: "start" });
    h.focus();
  });
}

/** Title-bar hint while a run is in progress; silent otherwise. */
export function SyncIndicator() {
  const running = useSync((s) => s.status?.state === "running");
  return (
    <span className="sync-indicator" role="status" aria-live="polite">
      {running && (
        <>
          <span aria-hidden className="state-dot" data-state="connecting" />
          Syncing…
        </>
      )}
    </span>
  );
}

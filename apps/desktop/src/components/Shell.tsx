import { useEffect } from "react";
import { BrandMark, Kbd } from "@mooring/ui";
import { useApp } from "../stores/app";
import { INSPECTOR, SIDEBAR, useUi } from "../stores/ui";
import { useUpdate } from "../stores/update";
import { Sidebar } from "./tree/Sidebar";
import { Workspace } from "./Workspace";
import { Inspector } from "./inspector/Inspector";
import { CommandPalette } from "./CommandPalette";
import { AuditView } from "./audit/AuditView";
import { CredentialsView } from "./credentials/CredentialsView";
import { SettingsView } from "./settings/SettingsView";
import { DialogHost } from "./dialogs/DialogHost";
import { PaneHandle } from "./PaneHandle";
import { Telemetry } from "./Telemetry";
import { Toasts } from "./Toasts";
import { openSettingsCard, SyncBanner, SyncIndicator } from "./SyncBanner";
import { useShortcuts } from "./useShortcuts";

/** Main window once the vault is unlocked: title bar, sync alarm (if any), tree | tabs (or audit) | inspector, telemetry strip. */
export function Shell() {
  const ui = useUi();
  useShortcuts();

  return (
    <div className="deck grid h-full grid-rows-[42px_auto_1fr_var(--status-h)]">
      <TitleBar />
      {/* Always one grid item, so the `auto` row stays the banner's even while there is no alarm (U5). */}
      <div className="min-h-0" data-slot="sync-banner"><SyncBanner /></div>
      <div
        className="grid min-h-0"
        style={{
          gridTemplateColumns: `${ui.sidebarWidth}px auto minmax(320px,1fr)${ui.inspectorOpen ? ` auto ${ui.inspectorWidth}px` : ""}`,
        }}
      >
        <Sidebar />
        <PaneHandle label="Resize connection tree" value={ui.sidebarWidth} min={SIDEBAR.min} max={SIDEBAR.max} sign={1} onChange={ui.setSidebarWidth} />
        {/* Workspace stays mounted under the audit view so terminals keep their scrollback. */}
        <div className="relative min-w-0 overflow-hidden">
          <div className="absolute inset-0" hidden={ui.view !== "workspace"}>
            <Workspace />
          </div>
          {ui.view === "audit" && (
            <div className="absolute inset-0">
              <AuditView />
            </div>
          )}
          {ui.view === "credentials" && (
            <div className="absolute inset-0">
              <CredentialsView />
            </div>
          )}
          {ui.view === "settings" && (
            <div className="absolute inset-0">
              <SettingsView />
            </div>
          )}
        </div>
        {ui.inspectorOpen && (
          <>
            <PaneHandle label="Resize details" value={ui.inspectorWidth} min={INSPECTOR.min} max={INSPECTOR.max} sign={-1} onChange={ui.setInspectorWidth} />
            <Inspector />
          </>
        )}
      </div>
      <Telemetry />
      <CommandPalette />
      <DialogHost />
      <Toasts />
    </div>
  );
}

function TitleBar() {
  const setPalette = useUi((s) => s.setPalette);
  const view = useUi((s) => s.view);
  const setView = useUi((s) => s.setView);
  const theme = useUi((s) => s.theme);
  const toggleTheme = useUi((s) => s.toggleTheme);
  const lock = useApp((s) => s.lock);

  return (
    <header className="titlebar" data-tauri-drag-region>
      <span className="wordmark">
        <Mark />
        <span className="wordmark-text">MOORING</span>
      </span>
      <button type="button" onClick={() => { setPalette(true); }} className="seek">
        <span aria-hidden className="seek-caret">&gt;</span>
        <span className="flex-1 truncate">Open a connection</span>
        <Kbd>mod K</Kbd>
      </button>
      <SyncIndicator />
      <UpdateIndicator />
      <nav aria-label="Views" className="ml-auto flex items-center gap-1">
        <button
          type="button"
          aria-pressed={view === "credentials"}
          className="btn btn-ghost"
          onClick={() => { if (view === "credentials") setView("workspace"); else useUi.getState().showCredentials(); }}
        >
          Credentials
        </button>
        <button
          type="button"
          aria-pressed={view === "audit"}
          className="btn btn-ghost"
          onClick={() => { setView(view === "audit" ? "workspace" : "audit"); }}
        >
          Audit log
        </button>
        <button
          type="button"
          aria-pressed={view === "settings"}
          className="btn btn-ghost"
          onClick={() => { setView(view === "settings" ? "workspace" : "settings"); }}
        >
          Settings
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          title="Toggle theme"
          onClick={toggleTheme}
        >
          {theme === "dark" ? "Light" : "Dark"}
        </button>
        <button type="button" onClick={() => void lock()} className="btn btn-ghost">
          <svg width="10" height="11" viewBox="0 0 10 11" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
            <rect x="1" y="4.5" width="8" height="6" />
            <path d="M3 4.5V3a2 2 0 0 1 4 0v1.5" />
          </svg>
          Lock
        </button>
      </nav>
    </header>
  );
}

/**
 * Subtle title-bar notice of the opt-in background update check (ADR-0018 §3): the shell holds
 * the one `update:available` subscription for the unlocked session; the notice only names the
 * version and jumps to Settings → Updates, where installing is a separate, confirmed step.
 */
function UpdateIndicator() {
  const badge = useUpdate((s) => s.badge);
  const view = useUi((s) => s.view);

  useEffect(() => useUpdate.getState().watch(), []);

  if (badge === null || view === "settings") return null;
  return (
    <button type="button" className="update-indicator" onClick={() => { openSettingsCard("updates-title"); }} aria-label={`Update ${badge} available. Open update settings`}>
      <span aria-hidden className="state-dot" data-state="connected" />
      Update {badge}
    </button>
  );
}

/** Brand mark: a bollard seen from above, with a line made fast to it. */
function Mark() {
  return <BrandMark size={18} />;
}

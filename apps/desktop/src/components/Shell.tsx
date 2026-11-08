import { useEffect } from "react";
import { BrandMark, Icon, Kbd } from "@mooring/ui";
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
import { openSettingsCard, SyncBanner, SyncIndicator, SyncPill } from "./SyncBanner";
import { useShortcuts } from "./useShortcuts";
import { DevBadge } from "./DevBadge";
import { NavRail } from "./NavRail";

/**
 * Main window once the vault is unlocked (Harbor layout, design review 2026-11 §4.2): title bar,
 * sync alarm (if any), navigation rail | view, status bar. Hosts shows tree | sessions | details;
 * Credentials, Audit log and Settings take the full width.
 */
export function Shell() {
  const ui = useUi();
  useShortcuts();
  const hosts = ui.view === "workspace";

  return (
    <div className="deck app-shell">
      <TitleBar />
      {/* Always one grid item, so the `auto` row stays the banner's even while there is no alarm (U5). */}
      <div className="min-h-0" data-slot="sync-banner"><SyncBanner /></div>
      <div className="shell-body">
        <NavRail />
        <div
          className="grid min-h-0 min-w-0"
          style={{
            gridTemplateColumns: hosts
              ? `${ui.sidebarWidth}px auto minmax(320px,1fr)${ui.inspectorOpen ? ` auto ${ui.inspectorWidth}px` : ""}`
              : "minmax(0,1fr)",
          }}
        >
          {hosts && (
            <>
              <Sidebar />
              <PaneHandle label="Resize connection tree" value={ui.sidebarWidth} min={SIDEBAR.min} max={SIDEBAR.max} sign={1} onChange={ui.setSidebarWidth} />
            </>
          )}
          {/* Workspace stays mounted under the other views so terminals keep their scrollback. */}
          <div className="relative min-w-0 overflow-hidden">
            <div className="absolute inset-0" hidden={!hosts}>
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
          {/* Q7: the details pane belongs to Hosts only. */}
          {hosts && ui.inspectorOpen && (
            <>
              <PaneHandle label="Resize details" value={ui.inspectorWidth} min={INSPECTOR.min} max={INSPECTOR.max} sign={-1} onChange={ui.setInspectorWidth} />
              <Inspector />
            </>
          )}
        </div>
      </div>
      <Telemetry />
      <CommandPalette />
      <DialogHost />
      <Toasts />
    </div>
  );
}

/** Title bar: brand and vault, search (the command hub), sync state, help, Lock. */
function TitleBar() {
  const setPalette = useUi((s) => s.setPalette);
  const lock = useApp((s) => s.lock);
  const dev = useApp((s) => s.info?.channel === "dev");

  return (
    <header className="titlebar" data-tauri-drag-region>
      <span className="wordmark">
        <BrandMark size={20} />
        <span className="wordmark-text">Mooring</span>
        {dev && <DevBadge />}
        <VaultLabel />
      </span>
      <button type="button" onClick={() => { setPalette(true); }} className="seek" aria-label="Search hosts, credentials and commands">
        <Icon name="search" size={14} />
        <span className="flex-1 truncate">Search hosts, credentials and commands</span>
        <Kbd>mod K</Kbd>
      </button>
      <span className="title-actions">
        <SyncIndicator />
        <SyncPill />
        <UpdateIndicator />
        <button
          type="button"
          className="icon-btn"
          aria-label="Keyboard shortcuts and help"
          title="Keyboard shortcuts and help"
          onClick={() => { setPalette(true); }}
        >
          <Icon name="help" />
        </button>
        <button type="button" onClick={() => void lock()} className="btn btn-sm">
          <Icon name="lock" size={14} />
          Lock
        </button>
      </span>
    </header>
  );
}

/** Which vault is open. One local vault today; the label is where a vault switcher will sit. */
function VaultLabel() {
  return <span className="vault-label">Local vault</span>;
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
      <span aria-hidden className="state-dot" data-tone="ok" />
      Update {badge}
    </button>
  );
}

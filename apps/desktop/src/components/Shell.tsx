import { Kbd } from "@mooring/ui";
import { useApp } from "../stores/app";
import { INSPECTOR, SIDEBAR, useUi } from "../stores/ui";
import { Sidebar } from "./tree/Sidebar";
import { Workspace } from "./Workspace";
import { Inspector } from "./inspector/Inspector";
import { CommandPalette } from "./CommandPalette";
import { AuditView } from "./audit/AuditView";
import { DialogHost } from "./dialogs/DialogHost";
import { PaneHandle } from "./PaneHandle";
import { Telemetry } from "./Telemetry";
import { useShortcuts } from "./useShortcuts";

/** Main window once the vault is unlocked: tree | tabs (or audit) | inspector, over a telemetry strip. */
export function Shell() {
  const ui = useUi();
  useShortcuts();

  return (
    <div className="deck grid h-full grid-rows-[42px_1fr_var(--status-h)]">
      <TitleBar />
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
      <nav aria-label="Views" className="ml-auto flex items-center gap-1">
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

/** Brand mark: a bollard seen from above, with a line made fast to it. */
function Mark() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden>
      <path d="M9 1.5 15.5 5v8L9 16.5 2.5 13V5z" />
      <circle cx="9" cy="9" r="2.4" />
      <path d="M11.2 9h5.3" />
    </svg>
  );
}

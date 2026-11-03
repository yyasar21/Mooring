import { Kbd, StateDot } from "@nexus/ui";
import { useApp } from "../stores/app";
import { useSessions } from "../stores/sessions";
import { INSPECTOR, SIDEBAR, useUi } from "../stores/ui";
import { Sidebar } from "./tree/Sidebar";
import { Workspace } from "./Workspace";
import { Inspector } from "./inspector/Inspector";
import { CommandPalette } from "./CommandPalette";
import { AuditView } from "./audit/AuditView";
import { DialogHost } from "./dialogs/DialogHost";
import { PaneHandle } from "./PaneHandle";
import { useShortcuts } from "./useShortcuts";

/** Main window once the vault is unlocked: tree | tabs (or audit) | inspector, with a status line. */
export function Shell() {
  const ui = useUi();
  useShortcuts();

  return (
    <div className="grid h-full grid-rows-[40px_1fr_var(--status-h)]">
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
        <div className="relative min-w-0">
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
      <StatusBar />
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
    <header className="flex items-center gap-2 border-b border-line bg-bg-sunken px-3" data-tauri-drag-region>
      <span className="pr-2 font-semibold tracking-tight">Mooring</span>
      <button
        type="button"
        onClick={() => { setPalette(true); }}
        className="flex h-[26px] w-[380px] min-w-0 items-center gap-2 rounded-[var(--radius-s)] border border-line bg-bg px-2 text-left text-text-faint hover:border-line-strong"
      >
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
          Lock
        </button>
      </nav>
    </header>
  );
}

function StatusBar() {
  const info = useApp((s) => s.info);
  const tabs = useSessions((s) => s.tabs);
  const live = tabs.filter((t) => t.state === "connected").length;
  const pending = tabs.filter((t) => t.state === "connecting").length;

  return (
    <footer className="flex items-center gap-4 border-t border-line bg-bg-sunken px-3 text-[length:var(--fs-xs)] text-text-muted">
      <span className="flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-accent" /> Vault unlocked
      </span>
      <span className="tnum flex items-center gap-1.5">
        <StateDot state={live > 0 ? "connected" : "closed"} /> {live} connected
        {pending > 0 && <span className="text-text-faint">, {pending} connecting</span>}
      </span>
      {info && (
        <span className="ml-auto text-text-faint">
          {info.name} {info.version}, {info.os}/{info.arch}
          {info.debug ? ", debug build" : ""}
        </span>
      )}
    </footer>
  );
}

import { Kbd } from "@nexus/ui";
import { useApp } from "../stores/app";
import { Sidebar } from "./Sidebar";
import { Workspace } from "./Workspace";
import { Inspector } from "./Inspector";
import { CommandPalette } from "./CommandPalette";

/** Main window once the vault is unlocked: tree | tabs | inspector, with a one-line status bar. */
export function Shell() {
  const info = useApp((s) => s.info);
  const setPalette = useApp((s) => s.setPalette);
  const lock = useApp((s) => s.lock);

  return (
    <div className="grid h-full grid-rows-[40px_1fr_24px]">
      <header className="flex items-center gap-3 border-b border-line bg-bg-sunken px-3" data-tauri-drag-region>
        <span className="font-semibold tracking-tight">Nexus</span>
        <button
          type="button"
          onClick={() => { setPalette(true); }}
          className="ml-2 flex h-7 w-[360px] items-center gap-2 rounded-[var(--radius-s)] border border-line bg-bg px-2 text-left text-text-faint hover:border-line-strong"
        >
          <span className="flex-1">Open a connection</span>
          <Kbd>mod K</Kbd>
        </button>
        <button
          type="button"
          onClick={() => void lock()}
          className="ml-auto rounded-[var(--radius-s)] px-2 py-1 text-text-muted hover:bg-surface hover:text-text"
        >
          Lock
        </button>
      </header>

      <div className="grid min-h-0 grid-cols-[260px_1fr_300px]">
        <Sidebar />
        <Workspace />
        <Inspector />
      </div>

      <footer className="flex items-center gap-4 border-t border-line bg-bg-sunken px-3 text-[length:var(--fs-xs)] text-text-muted">
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-accent" /> vault unlocked
        </span>
        {info && (
          <span className="ml-auto">
            {info.name} {info.version} · {info.os}/{info.arch}
            {info.debug ? " · debug" : ""}
          </span>
        )}
      </footer>
      <CommandPalette />
    </div>
  );
}

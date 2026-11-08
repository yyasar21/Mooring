import { useEffect, useRef, useState } from "react";
import { Icon } from "@mooring/ui";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { useOnboarding } from "../../stores/onboarding";
import { READONLY_REASON } from "../vsphere/vsphere";

/**
 * Tree header (design review 2026-11, M3): the pane title, "New folder", and a "New" split
 * button. The main part creates a connection in the selected folder (accessible name "New
 * connection", an e2e contract); the arrow opens a menu with the other ways to add. Credentials
 * moved to the navigation rail.
 */
export function SidebarToolbar() {
  const openDialog = useUi((s) => s.openDialog);
  const selected = useTree((s) => s.selected);
  const folders = useTree((s) => s.folders);
  const connections = useTree((s) => s.connections);
  const targetFolder =
    selected?.kind === "folder"
      ? selected.id
      : (connections.find((c) => c.id === selected?.id)?.folderId ?? folders.find((f) => f.parentId === null)?.id ?? "");
  // ADR-0015: nothing is created inside a synced subtree.
  const readonly = folders.find((f) => f.id === targetFolder)?.syncSource ? READONLY_REASON : null;
  const blocked = !targetFolder || readonly !== null;
  const newConnection = () => { openDialog({ kind: "connection", folderId: targetFolder }); };
  const newFolder = () => { openDialog({ kind: "folder", parentId: targetFolder }); };

  return (
    <div className="deck-head">
      <h2 className="pane-title flex-1">Connections</h2>
      <button
        type="button"
        className="icon-btn"
        title={readonly ?? "New folder in the selected folder"}
        aria-label="New folder"
        disabled={blocked}
        onClick={newFolder}
      >
        <Icon name="folder-plus" />
      </button>
      <span className="split-btn">
        <button
          type="button"
          className="btn btn-primary btn-sm"
          title={readonly ?? "New connection in the selected folder"}
          aria-label="New connection"
          disabled={blocked}
          onClick={newConnection}
        >
          <Icon name="plus" size={14} />
          New
        </button>
        <NewMenu
          disabled={blocked}
          items={[
            { label: "Connection…", run: newConnection },
            { label: "Folder…", run: newFolder },
            { label: "Import connections…", run: () => { useOnboarding.getState().setImporting(true); } },
          ]}
        />
      </span>
    </div>
  );
}

interface MenuItem { label: string; run: () => void }

/** The split button's arrow: a menu (WAI-ARIA menu button). ↑↓ move, Enter runs, Esc closes. */
function NewMenu({ items, disabled }: { items: MenuItem[]; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLSpanElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    wrap.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    const away = (e: MouseEvent) => { if (!wrap.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", away);
    return () => { document.removeEventListener("mousedown", away); };
  }, [open]);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) trigger.current?.focus();
  };
  const onKey = (e: React.KeyboardEvent) => {
    const list = [...(wrap.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])];
    const at = list.indexOf(document.activeElement as HTMLElement);
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(true); }
    else if (e.key === "ArrowDown") { e.preventDefault(); list[(at + 1) % list.length]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); list[(at - 1 + list.length) % list.length]?.focus(); }
    else if (e.key === "Tab") close(false);
  };

  return (
    <span ref={wrap} onKeyDown={open ? onKey : undefined}>
      <button
        ref={trigger}
        type="button"
        className="btn btn-primary btn-sm"
        aria-label="More ways to add"
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={disabled}
        onClick={() => { setOpen(!open); }}
      >
        <Icon name="down" size={14} />
      </button>
      {open && (
        <div role="menu" aria-label="Add" className="split-menu">
          {items.map((it) => (
            <button key={it.label} type="button" role="menuitem" tabIndex={-1} onClick={() => { close(false); it.run(); }}>
              {it.label}
            </button>
          ))}
        </div>
      )}
    </span>
  );
}

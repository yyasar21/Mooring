import { useMemo, useState } from "react";
import { useTree, visibleRows, type NodeRef, type TreeRow } from "../../stores/tree";
import { useSessions, type TabState } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { TreeRowView } from "./TreeRowView";

/**
 * Left pane: the connection tree (WAI-ARIA tree pattern, roving tabindex).
 * ↑↓ move · → expand / first child · ← collapse / parent · Home End · Enter open or toggle ·
 * F2 rename · mod+Enter open in a new tab. Drag a row onto a folder to move it.
 */
export function Sidebar() {
  const folders = useTree((s) => s.folders);
  const connections = useTree((s) => s.connections);
  const collapsed = useTree((s) => s.collapsed);
  const selected = useTree((s) => s.selected);
  const error = useTree((s) => s.error);
  const tabs = useSessions((s) => s.tabs);
  const renaming = useUi((s) => s.renaming);
  const [dragging, setDragging] = useState<NodeRef | null>(null);
  const [dropOn, setDropOn] = useState<string | null>(null);

  const rows = useMemo(() => visibleRows(folders, connections, collapsed), [folders, connections, collapsed]);
  const focusIndex = Math.max(0, rows.findIndex((r) => r.ref.id === selected?.id));
  const siblings = useMemo(() => {
    const m = new Map<string, TreeRow[]>();
    for (const r of rows) {
      const k = r.parentId ?? "";
      m.set(k, [...(m.get(k) ?? []), r]);
    }
    return m;
  }, [rows]);

  const sessionState = (connectionId: string): TabState | null => {
    const ts = tabs.filter((t) => t.connectionId === connectionId);
    if (ts.some((t) => t.state === "connected")) return "connected";
    if (ts.some((t) => t.state === "connecting")) return "connecting";
    return null;
  };

  const { select, toggle, renameFolder, renameConnection, moveFolder, moveConnection } = useTree.getState();
  const setRenaming = useUi.getState().setRenaming;
  const openConnection = (id: string, newTab = false) => void useSessions.getState().open(id, { newTab });

  const activate = (r: TreeRow, newTab = false) => {
    if (r.ref.kind === "folder") toggle(r.ref.id);
    else openConnection(r.ref.id, newTab);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (renaming || rows.length === 0) return;
    const cur = rows[focusIndex];
    if (!cur) return;
    const go = (i: number) => {
      const r = rows[Math.max(0, Math.min(rows.length - 1, i))];
      if (r) select(r.ref);
    };
    const isFolder = cur.ref.kind === "folder";
    const open = isFolder && !(cur.ref.id in collapsed);
    let handled = true;
    switch (e.key) {
      case "ArrowDown": go(focusIndex + 1); break;
      case "ArrowUp": go(focusIndex - 1); break;
      case "Home": go(0); break;
      case "End": go(rows.length - 1); break;
      case "ArrowRight":
        if (isFolder && !open) toggle(cur.ref.id, true);
        else if (isFolder) go(focusIndex + 1);
        break;
      case "ArrowLeft":
        if (isFolder && open && cur.parentId !== null) toggle(cur.ref.id, false);
        else if (cur.parentId) select({ kind: "folder", id: cur.parentId });
        break;
      case "Enter": activate(cur, e.metaKey || e.ctrlKey); break;
      case "F2": if (cur.parentId !== null) setRenaming(cur.ref.id); break;
      default: handled = false;
    }
    if (handled) e.preventDefault();
  };

  const drop = (target: TreeRow) => {
    const src = dragging;
    setDragging(null);
    setDropOn(null);
    if (!src || target.ref.kind !== "folder" || src.id === target.ref.id) return;
    if (src.kind === "folder") void moveFolder(src.id, target.ref.id);
    else void moveConnection(src.id, target.ref.id);
  };

  return (
    <nav aria-label="Connection tree" className="flex h-full min-w-0 flex-col bg-bg-sunken">
      <SidebarToolbar />
      {error && (
        <p role="alert" className="mx-2 mb-1 rounded-[var(--radius-s)] bg-danger-soft px-2 py-1 text-[length:var(--fs-xs)] text-danger">
          {error}
        </p>
      )}
      <div
        role="tree"
        aria-label="Connections"
        aria-activedescendant={undefined}
        className="min-h-0 flex-1 overflow-y-auto pb-4"
        onKeyDown={onKeyDown}
        onFocus={(e) => {
          if (e.target === e.currentTarget && rows[focusIndex]) select(rows[focusIndex].ref);
        }}
        onDragLeave={(e) => {
          if (e.target === e.currentTarget) setDropOn(null);
        }}
      >
        {rows.map((r, i) => {
          const sibs = siblings.get(r.parentId ?? "") ?? [r];
          return (
            <TreeRowView
              key={r.ref.id}
              row={r}
              folder={r.ref.kind === "folder" ? folders.find((f) => f.id === r.ref.id) : undefined}
              connection={r.ref.kind === "connection" ? connections.find((c) => c.id === r.ref.id) : undefined}
              selected={selected?.id === r.ref.id}
              focused={i === focusIndex}
              expanded={!(r.ref.id in collapsed)}
              renaming={renaming === r.ref.id}
              dropTarget={dropOn === r.ref.id}
              sessionState={r.ref.kind === "connection" ? sessionState(r.ref.id) : null}
              setSize={sibs.length}
              posInSet={sibs.indexOf(r) + 1}
              onClick={() => { select(r.ref); }}
              onDoubleClick={() => { activate(r); }}
              onToggle={() => { toggle(r.ref.id); }}
              onRename={(name) => {
                setRenaming(null);
                if (name === null) return;
                if (r.ref.kind === "folder") void renameFolder(r.ref.id, name);
                else void renameConnection(r.ref.id, name);
              }}
              onDragStart={() => { setDragging(r.ref); }}
              onDragOver={() => { setDropOn(r.ref.id); }}
              onDrop={() => { drop(r); }}
            />
          );
        })}
      </div>
    </nav>
  );
}

function SidebarToolbar() {
  const openDialog = useUi((s) => s.openDialog);
  const selected = useTree((s) => s.selected);
  const folders = useTree((s) => s.folders);
  const connections = useTree((s) => s.connections);
  const targetFolder =
    selected?.kind === "folder"
      ? selected.id
      : (connections.find((c) => c.id === selected?.id)?.folderId ?? folders.find((f) => f.parentId === null)?.id ?? "");

  return (
    <div className="flex h-[var(--bar-h)] flex-none items-center gap-1 border-b border-line px-2">
      <span className="flex-1 pl-1 text-[length:var(--fs-xs)] font-medium text-text-muted">Connections</span>
      <button
        type="button"
        className="icon-btn"
        title="New connection in the selected folder"
        aria-label="New connection"
        disabled={!targetFolder}
        onClick={() => { openDialog({ kind: "connection", folderId: targetFolder }); }}
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
          <rect x="1.5" y="3" width="11" height="8" rx="1" />
          <path d="M7 5v4M5 7h4" />
        </svg>
      </button>
      <button
        type="button"
        className="icon-btn"
        title="New folder in the selected folder"
        aria-label="New folder"
        disabled={!targetFolder}
        onClick={() => { openDialog({ kind: "folder", parentId: targetFolder }); }}
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
          <path d="M1.5 3.5h4l1 1.5h6v6.5h-11z" />
          <path d="M7 6.5v3.5M5.25 8.25h3.5" />
        </svg>
      </button>
      <button
        type="button"
        className="icon-btn"
        title="Credentials"
        aria-label="Credentials"
        onClick={() => { openDialog({ kind: "credentials" }); }}
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
          <circle cx="4.5" cy="7" r="2.75" />
          <path d="M7.25 7H13M11 7v2.5M12.75 7v1.75" />
        </svg>
      </button>
    </div>
  );
}

import { useMemo, useState } from "react";
import { ipc } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { useTree, visibleRows, type NodeRef, type TreeRow } from "../../stores/tree";
import { useSessions, type TabState } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { TreeRowView } from "./TreeRowView";
import { SidebarToolbar } from "./SidebarToolbar";
import { filterTree, subtreeCounts } from "./treeFilter";
import { Icon } from "@mooring/ui";
import { READONLY_REASON, sourceName } from "../vsphere/vsphere";

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
  const [filter, setFilter] = useState("");

  // M3: the filter narrows the tree to matches and their folders, all expanded while it is set.
  const rows = useMemo(() => {
    if (!filter.trim()) return visibleRows(folders, connections, collapsed);
    const f = filterTree(folders, connections, filter);
    return visibleRows(f.folders, f.connections, {});
  }, [folders, connections, collapsed, filter]);
  const counts = useMemo(() => subtreeCounts(folders, connections), [folders, connections]);
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
    if (ts.some((t) => t.state === "connecting" || t.state === "reconnecting")) return "connecting";
    return null;
  };

  const { select, toggle, renameFolder, renameConnection, moveFolder, moveConnection } = useTree.getState();
  const setRenaming = useUi.getState().setRenaming;
  /** ADR-0015: the vCenter id of a row inside a synced subtree, else null. */
  const syncSourceOf = (r: TreeRow): string | null =>
    (r.ref.kind === "folder" ? folders.find((f) => f.id === r.ref.id)?.syncSource : connections.find((c) => c.id === r.ref.id)?.syncSource) ?? null;
  const refuseReadonly = () => { useTree.setState({ error: READONLY_REASON }); };
  const openConnection = (id: string, newTab = false) => void useSessions.getState().open(id, { newTab });

  const activate = (r: TreeRow, newTab = false) => {
    if (r.ref.kind === "folder") toggle(r.ref.id);
    else if (syncSourceOf(r) !== null) openVmConsole(r.ref.id);
    else openConnection(r.ref.id, newTab);
  };
  /** A synced VM row has no session of its own: Enter opens its vSphere Client window (ADR-0015 §4). */
  const openVmConsole = (id: string) => {
    select({ kind: "connection", id });
    if (connections.find((c) => c.id === id)?.syncState === "missing") { useTree.setState({ error: "vCenter no longer reports this VM." }); return; }
    ipc.vsphereConsole({ connectionId: id, kind: "client" }).catch((e: unknown) => { useTree.setState({ error: describeError(e) }); });
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
    const open = isFolder && (filter.trim() !== "" || !(cur.ref.id in collapsed));
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
      case "F2":
        if (cur.parentId === null) break;
        if (syncSourceOf(cur) !== null) refuseReadonly();
        else setRenaming(cur.ref.id);
        break;
      default: handled = false;
    }
    if (handled) e.preventDefault();
  };

  const drop = (target: TreeRow) => {
    const src = dragging;
    setDragging(null);
    setDropOn(null);
    if (!src || target.ref.kind !== "folder" || src.id === target.ref.id) return;
    if (syncSourceOf(target) !== null) { refuseReadonly(); return; }
    if (src.kind === "folder") void moveFolder(src.id, target.ref.id);
    else void moveConnection(src.id, target.ref.id);
  };

  return (
    <nav aria-label="Connection tree" className="deck-pane flex h-full flex-col">
      <SidebarToolbar />
      <div className="tree-filter">
        <span className="tree-filter-wrap block">
          <span className="tree-filter-icon" aria-hidden><Icon name="filter" size={14} /></span>
          <input
            type="search"
            className="field"
            aria-label="Filter connections"
            placeholder="Filter by name, host or tag"
            value={filter}
            onChange={(e) => { setFilter(e.target.value); }}
            onKeyDown={(e) => { if (e.key === "Escape" && filter) { e.stopPropagation(); setFilter(""); } }}
          />
        </span>
      </div>
      {filter.trim() && !rows.some((r) => r.ref.kind === "connection") && <p className="tree-empty" role="status">No connections match.</p>}
      {error && (
        <p role="alert" className="callout mx-3 mb-2 text-[length:var(--fs-12)]" data-tone="danger">
          {error}
        </p>
      )}
      <div
        role="tree"
        aria-label="Connections"
        aria-activedescendant={undefined}
        className="min-h-0 flex-1 overflow-y-auto py-1.5 pb-4"
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
              expanded={filter.trim() !== "" || !(r.ref.id in collapsed)}
              count={r.ref.kind === "folder" ? (counts.get(r.ref.id) ?? 0) : null}
              renaming={renaming === r.ref.id}
              dropTarget={dropOn === r.ref.id}
              sessionState={r.ref.kind === "connection" ? sessionState(r.ref.id) : null}
              syncSource={syncSourceOf(r) === null ? null : sourceName(connections, syncSourceOf(r))}
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

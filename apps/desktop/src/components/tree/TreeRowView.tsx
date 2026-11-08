import { useEffect, useRef, useState } from "react";
import { dotTone, Icon, ProtocolIcon } from "@mooring/ui";
import type { ConnectionSummary, Folder } from "../../lib/ipc";
import { useTree, viaNames, type TreeRow } from "../../stores/tree";
import { lineState, type TabState } from "../../stores/sessions";
import { SyncBadge } from "../vsphere/SyncBadge";

interface Props {
  row: TreeRow;
  folder: Folder | undefined;
  connection: ConnectionSummary | undefined;
  selected: boolean;
  focused: boolean;
  expanded: boolean;
  renaming: boolean;
  dropTarget: boolean;
  sessionState: TabState | null;
  /** The vCenter name when the row is inside a synced subtree (ADR-0015): read-only, badged. */
  syncSource: string | null;
  setSize: number;
  posInSet: number;
  /** Connections inside a folder row (sub-folders included); null for connection rows. */
  count: number | null;
  onClick: () => void;
  onDoubleClick: () => void;
  onToggle: () => void;
  onRename: (name: string | null) => void;
  onDragStart: () => void;
  onDragOver: () => void;
  onDrop: () => void;
}

const INDENT = 16;

/**
 * One `treeitem` (design review 2026-11, M3): chevron, folder icon with a count, or a protocol
 * icon with a status dot. The accessible name is unchanged (an e2e contract). Indentation guides
 * are drawn per depth level; the row itself is the focus target.
 */
export function TreeRowView(p: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const isFolder = p.row.ref.kind === "folder";
  const name = (isFolder ? p.folder?.name : p.connection?.name) ?? "";
  const pad = 4 + p.row.depth * INDENT;
  const synced = p.syncSource !== null;
  const missing = !isFolder && p.connection?.syncState === "missing";
  const syncedRoot = isFolder && synced && !p.folder?.externalId;
  // ADR-0025: a connection with a chain says which jump hosts it goes through.
  const via = useTree((s) => (p.connection ? viaNames(s.connections, p.connection) : null));

  useEffect(() => {
    if (p.focused && !p.renaming && document.activeElement !== ref.current) {
      const inTree = ref.current?.closest('[role="tree"]')?.contains(document.activeElement);
      if (inTree) ref.current?.focus();
    }
  }, [p.focused, p.renaming]);

  return (
    <div
      ref={ref}
      role="treeitem"
      id={`node-${p.row.ref.id}`}
      aria-level={p.row.depth + 1}
      aria-setsize={p.setSize}
      aria-posinset={p.posInSet}
      aria-selected={p.selected}
      aria-expanded={isFolder ? p.expanded : undefined}
      aria-label={`${isFolder ? name : `${name}, ${p.connection?.host ?? ""}`}${via ? `, via ${via}` : ""}${synced ? `, synced from ${p.syncSource ?? ""}` : ""}${missing ? ", missing in vCenter" : ""}`}
      aria-readonly={synced || undefined}
      tabIndex={p.focused ? 0 : -1}
      data-drop={p.dropTarget || undefined}
      data-sync={missing ? "missing" : synced ? "synced" : undefined}
      className={`tree-row ${isFolder ? "tree-folder" : ""}`}
      style={{ paddingLeft: pad }}
      // Synced rows are moved in vCenter, not here; a drop into a synced folder is refused the same way.
      draggable={!p.renaming && p.row.parentId !== null && !synced}
      onClick={p.onClick}
      onDoubleClick={p.onDoubleClick}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = "move";
        p.onDragStart();
      }}
      onDragOver={(e) => {
        if (!isFolder || synced) return;
        e.preventDefault();
        p.onDragOver();
      }}
      onDrop={(e) => {
        e.preventDefault();
        p.onDrop();
      }}
    >
      {Array.from({ length: p.row.depth }, (_, i) => (
        <span key={i} aria-hidden className="tree-guide" style={{ left: 11.5 + i * INDENT }} />
      ))}
      {isFolder ? (
        <button
          type="button"
          tabIndex={-1}
          aria-hidden
          className="tree-chev"
          onClick={(e) => {
            e.stopPropagation();
            p.onToggle();
          }}
        >
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" style={{ transform: p.expanded ? "rotate(90deg)" : "none" }}>
            <path d="M6.25 4.5L9.75 8l-3.5 3.5" />
          </svg>
        </button>
      ) : (
        <span aria-hidden className="tree-chev" />
      )}
      {isFolder ? (
        <span aria-hidden className="tree-folder-icon"><Icon name="folder" /></span>
      ) : (
        p.connection && (
          <ProtocolIcon
            protocol={p.connection.protocol}
            tone={p.sessionState ? dotTone(lineState(p.sessionState)) : null}
            {...(p.sessionState ? { dotLabel: `session ${p.sessionState}` } : {})}
          />
        )
      )}
      {p.renaming ? (
        <RenameField initial={name} onDone={p.onRename} />
      ) : (
        <span className="tree-name">{name}</span>
      )}
      {via && !p.renaming && <span className="tree-via" aria-hidden title={`Connects via ${via}`}>via {via}</span>}
      {missing && <span className="tree-missing" aria-hidden>missing</span>}
      {isFolder && synced && <SyncBadge source={p.syncSource ?? ""} compact={!syncedRoot} />}
      {isFolder && p.count !== null && !p.renaming && (
        <span className="tree-count" aria-hidden title={`${p.count} ${p.count === 1 ? "connection" : "connections"}`}>{p.count}</span>
      )}
      {isFolder && p.folder?.defaultCredentialId && (
        <span title="Folder supplies a default credential" aria-label="has default credential" className="flex-none text-text-faint">
          <svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
            <circle cx="4" cy="6" r="2.5" />
            <path d="M6.5 6H11M9.5 6v2" />
          </svg>
        </span>
      )}
    </div>
  );
}

function RenameField({ initial, onDone }: { initial: string; onDone: (name: string | null) => void }) {
  const [value, setValue] = useState(initial);
  const ref = useRef<HTMLInputElement>(null);
  const done = useRef(false);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.select();
  }, []);
  const finish = (v: string | null) => {
    if (done.current) return;
    done.current = true;
    onDone(v);
  };
  return (
    <input
      ref={ref}
      aria-label="New name"
      className="field h-[22px] flex-1 px-1"
      value={value}
      onClick={(e) => { e.stopPropagation(); }}
      onChange={(e) => { setValue(e.target.value); }}
      onBlur={() => { finish(value.trim() && value.trim() !== initial ? value.trim() : null); }}
      onKeyDown={(e) => {
        e.stopPropagation();
        if (e.key === "Enter") finish(value.trim() && value.trim() !== initial ? value.trim() : null);
        else if (e.key === "Escape") finish(null);
      }}
    />
  );
}

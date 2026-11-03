import { useEffect, useRef, useState } from "react";
import { ProtocolPip, StateDot } from "@mooring/ui";
import type { ConnectionSummary, Folder } from "../../lib/ipc";
import type { TreeRow } from "../../stores/tree";
import type { TabState } from "../../stores/sessions";

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
  setSize: number;
  posInSet: number;
  onClick: () => void;
  onDoubleClick: () => void;
  onToggle: () => void;
  onRename: (name: string | null) => void;
  onDragStart: () => void;
  onDragOver: () => void;
  onDrop: () => void;
}

/** One `treeitem`. Indentation guides are drawn per depth level; the row itself is the focus target. */
export function TreeRowView(p: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const isFolder = p.row.ref.kind === "folder";
  const name = (isFolder ? p.folder?.name : p.connection?.name) ?? "";
  const pad = 8 + p.row.depth * 14;

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
      aria-label={isFolder ? name : `${name}, ${p.connection?.host ?? ""}`}
      tabIndex={p.focused ? 0 : -1}
      data-drop={p.dropTarget || undefined}
      className={`tree-row ${isFolder ? "tree-folder" : ""}`}
      style={{ paddingLeft: pad }}
      draggable={!p.renaming && p.row.parentId !== null}
      onClick={p.onClick}
      onDoubleClick={p.onDoubleClick}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = "move";
        p.onDragStart();
      }}
      onDragOver={(e) => {
        if (!isFolder) return;
        e.preventDefault();
        p.onDragOver();
      }}
      onDrop={(e) => {
        e.preventDefault();
        p.onDrop();
      }}
    >
      {Array.from({ length: p.row.depth }, (_, i) => (
        <span key={i} aria-hidden className="tree-guide" style={{ left: 13 + i * 14 }} />
      ))}
      {isFolder ? (
        <button
          type="button"
          tabIndex={-1}
          aria-hidden
          className="grid h-4 w-4 flex-none place-items-center text-text-faint"
          onClick={(e) => {
            e.stopPropagation();
            p.onToggle();
          }}
        >
          <svg width="8" height="8" viewBox="0 0 8 8" style={{ transform: p.expanded ? "rotate(90deg)" : "none", transition: "transform 90ms" }}>
            <path d="M2 1l4 3-4 3z" fill="currentColor" />
          </svg>
        </button>
      ) : (
        p.connection && <ProtocolPip protocol={p.connection.protocol} live={p.sessionState === "connected"} />
      )}
      {p.renaming ? (
        <RenameField initial={name} onDone={p.onRename} />
      ) : (
        <span className="tree-name">{name}</span>
      )}
      {!p.renaming && <span aria-hidden className="tree-link" data-state={p.sessionState ?? undefined} />}
      {p.sessionState && <StateDot state={p.sessionState} label={`session ${p.sessionState}`} />}
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

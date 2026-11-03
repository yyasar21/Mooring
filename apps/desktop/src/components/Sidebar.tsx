import { useMemo, useState } from "react";
import { ProtocolPip } from "@nexus/ui";
import { useApp, type Folder } from "../stores/app";

/** Left pane: the connection tree. Single click selects, double click / Enter opens. */
export function Sidebar() {
  const folders = useApp((s) => s.folders);
  const root = folders.find((f) => f.parent === null);
  return (
    <nav aria-label="Connections" className="h-full overflow-y-auto border-r border-line bg-bg-sunken py-2">
      {root && <FolderNode folder={root} depth={0} />}
    </nav>
  );
}

function FolderNode({ folder, depth }: { folder: Folder; depth: number }) {
  const [open, setOpen] = useState(true);
  const folders = useApp((s) => s.folders);
  const all = useApp((s) => s.connections);
  const children = useMemo(() => folders.filter((f) => f.parent === folder.id), [folders, folder.id]);
  const connections = useMemo(() => all.filter((c) => c.folder === folder.id), [all, folder.id]);
  const pad = 10 + depth * 14;

  return (
    <div>
      <button
        type="button"
        onClick={() => { setOpen((o) => !o); }}
        aria-expanded={open}
        className="flex w-full items-center gap-1.5 py-1 pr-2 text-left text-text-muted hover:text-text"
        style={{ paddingLeft: pad }}
      >
        <span aria-hidden className="inline-block w-3 text-text-faint" style={{ transform: open ? "rotate(90deg)" : "none" }}>
          ▸
        </span>
        <span className="truncate font-medium">{folder.name}</span>
      </button>
      {open && (
        <div>
          {children.map((f) => (
            <FolderNode key={f.id} folder={f} depth={depth + 1} />
          ))}
          {connections.map((c) => (
            <ConnectionRow key={c.id} id={c.id} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function ConnectionRow({ id, depth }: { id: string; depth: number }) {
  const c = useApp((s) => s.connections.find((x) => x.id === id));
  const selected = useApp((s) => s.selected === id);
  const open = useApp((s) => s.tabs.some((t) => t.connectionId === id));
  const select = useApp((s) => s.select);
  const openTab = useApp((s) => s.openTab);
  if (!c) return null;
  return (
    <div
      role="button"
      tabIndex={0}
      aria-selected={selected}
      onClick={() => { select(id); }}
      onDoubleClick={() => { openTab(id); }}
      onKeyDown={(e) => {
        if (e.key === "Enter") openTab(id);
      }}
      className={`flex cursor-default items-center gap-2 py-[5px] pr-2 ${
        selected ? "bg-accent-soft text-text" : "text-text-muted hover:bg-surface hover:text-text"
      }`}
      style={{ paddingLeft: 10 + depth * 14 + 14, borderLeft: selected ? "2px solid var(--accent)" : "2px solid transparent" }}
    >
      <ProtocolPip protocol={c.protocol} />
      <span className="truncate">{c.name}</span>
      {open && <span aria-label="open" className="ml-auto h-1.5 w-1.5 rounded-full bg-ok" />}
    </div>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import { Kbd, ProtocolPip } from "@nexus/ui";
import type { ConnectionHit } from "../lib/ipc";
import { bestScore } from "../lib/fuzzy";
import { folderPath, useTree } from "../stores/tree";
import { useSessions } from "../stores/sessions";
import { useUi } from "../stores/ui";
import { useApp } from "../stores/app";

interface Action {
  id: string;
  label: string;
  run: () => void;
}

type Item = { kind: "conn"; hit: ConnectionHit } | { kind: "action"; action: Action };

/** The front door. Connections come from `connection_search` (fuzzy, ranked by Rust); actions are local. */
export function CommandPalette() {
  const open = useUi((s) => s.paletteOpen);
  const setPalette = useUi((s) => s.setPalette);
  const folders = useTree((s) => s.folders);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<ConnectionHit[]>([]);
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const reqId = useRef(0);

  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
      queueMicrotask(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const id = ++reqId.current;
    void useTree.getState().search(query.trim(), 30).then((h) => {
      if (id === reqId.current) setHits(h);
    });
  }, [query, open]);

  const actions = useMemo<Action[]>(() => {
    const ui = useUi.getState();
    const tree = useTree.getState();
    const root = tree.folders.find((f) => f.parentId === null)?.id ?? "";
    const close = () => { setPalette(false); };
    return [
      { id: "new-conn", label: "New connection", run: () => { ui.openDialog({ kind: "connection", folderId: root }); } },
      { id: "new-folder", label: "New folder", run: () => { ui.openDialog({ kind: "folder", parentId: root }); } },
      { id: "creds", label: "Manage credentials", run: () => { ui.openDialog({ kind: "credentials" }); } },
      { id: "audit", label: "Show audit log", run: () => { ui.setView("audit"); } },
      { id: "theme", label: "Toggle light and dark theme", run: () => { ui.toggleTheme(); close(); } },
      { id: "lock", label: "Lock vault", run: () => { close(); void useApp.getState().lock(); } },
    ];
  }, [setPalette]);

  const items = useMemo<Item[]>(() => {
    const q = query.trim();
    const acts = q ? actions.filter((a) => bestScore(q, [a.label]) !== null) : actions;
    return [...hits.map((hit) => ({ kind: "conn" as const, hit })), ...acts.map((action) => ({ kind: "action" as const, action }))];
  }, [hits, actions, query]);

  if (!open) return null;

  const run = (i: number, newTab = false) => {
    const it = items[i];
    if (!it) return;
    if (it.kind === "conn") {
      setPalette(false);
      useUi.getState().setView("workspace");
      useTree.getState().select({ kind: "connection", id: it.hit.id });
      void useSessions.getState().open(it.hit.id, { newTab });
    } else it.action.run();
  };

  const optionId = (i: number) => `palette-opt-${i}`;

  return (
    <>
      <div className="scrim" onMouseDown={() => { setPalette(false); }} />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="pop fixed left-1/2 top-[12vh] z-50 w-[640px] max-w-[calc(100vw-32px)] -translate-x-1/2 overflow-hidden"
      >
        <input
          ref={inputRef}
          value={query}
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-activedescendant={items.length ? optionId(cursor) : undefined}
          aria-label="Search connections"
          placeholder="Host, name or tag, or a command"
          spellCheck={false}
          onChange={(e) => {
            setQuery(e.target.value);
            setCursor(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setCursor((c) => Math.min(c + 1, items.length - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setCursor((c) => Math.max(c - 1, 0));
            } else if (e.key === "Enter") {
              e.preventDefault();
              run(cursor, e.metaKey || e.ctrlKey);
            } else if (e.key === "Escape") {
              e.preventDefault();
              setPalette(false);
            } else if (e.key === "Tab") e.preventDefault();
          }}
          className="h-11 w-full border-b border-line bg-transparent px-4 text-[length:var(--fs-l)] text-text placeholder:text-text-faint focus:outline-none"
        />
        <ul id="palette-list" role="listbox" aria-label="Results" className="max-h-[52vh] overflow-y-auto py-1">
          {items.length === 0 && (
            <li className="px-4 py-6 text-center text-text-faint">No connection or command matches “{query}”.</li>
          )}
          {items.map((it, i) => (
            <li
              key={it.kind === "conn" ? it.hit.id : it.action.id}
              id={optionId(i)}
              role="option"
              aria-selected={i === cursor}
              onMouseMove={() => { if (cursor !== i) setCursor(i); }}
              onClick={() => { run(i); }}
              className={`flex h-8 cursor-default items-center gap-3 px-4 ${i === cursor ? "bg-accent-soft" : ""}`}
            >
              {it.kind === "conn" ? (
                <>
                  <ProtocolPip protocol={it.hit.protocol} />
                  <span className="font-medium">{it.hit.name}</span>
                  <span className="mono truncate text-text-muted">{it.hit.host}</span>
                  <span className="ml-auto truncate text-[length:var(--fs-xs)] text-text-faint">
                    {folderPath(folders, it.hit.folderId).join(" / ")}
                  </span>
                </>
              ) : (
                <>
                  <span aria-hidden className="w-[30px] text-center text-text-faint">›</span>
                  <span>{it.action.label}</span>
                </>
              )}
            </li>
          ))}
        </ul>
        <div className="flex gap-4 border-t border-line px-4 py-2 text-[length:var(--fs-xs)] text-text-faint">
          <span><Kbd>↑↓</Kbd> move</span>
          <span><Kbd>↵</Kbd> open</span>
          <span><Kbd>mod ↵</Kbd> open in new tab</span>
          <span><Kbd>esc</Kbd> close</span>
        </div>
      </div>
    </>
  );
}

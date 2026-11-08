import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { Icon, Kbd, ProtocolIcon } from "@mooring/ui";
import type { ConnectionHit } from "../lib/ipc";
import { bestScore } from "../lib/fuzzy";
import { folderPath, useTree } from "../stores/tree";
import { useSessions } from "../stores/sessions";
import { useUi } from "../stores/ui";
import { recentConnections } from "../stores/recent";
import { paletteActions, settingsPages, type PaletteAction } from "./paletteActions";

type Item = { kind: "conn"; hit: ConnectionHit } | { kind: "action"; action: PaletteAction; settings?: boolean };
interface Group { id: string; label: string; items: Item[] }

/** Matches an action or settings page against the query: the label first, then its extra words. */
function score(q: string, a: PaletteAction): number | null {
  const label = bestScore(q, [a.label]);
  if (label !== null) return label + 1000;
  return a.terms ? bestScore(q, [a.terms]) : null;
}

const filterRank = (q: string, list: PaletteAction[]) =>
  q ? list.map((a) => ({ a, s: score(q, a) })).filter((x) => x.s !== null).sort((x, y) => (y.s ?? 0) - (x.s ?? 0)).map((x) => x.a) : list;

/**
 * The front door (L3): connections from `connection_search` (fuzzy, ranked by Rust), the recent
 * ones first when nothing is typed, every app action with its shortcut, and the settings pages.
 * One listbox, grouped; ↑↓ move across groups, Enter runs, mod+Enter opens a connection in a new tab.
 */
export function CommandPalette() {
  const open = useUi((s) => s.paletteOpen);
  const setPalette = useUi((s) => s.setPalette);
  const folders = useTree((s) => s.folders);
  const connections = useTree((s) => s.connections);
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

  const groups = useMemo<Group[]>(() => {
    if (!open) return [];
    const close = () => { setPalette(false); };
    const q = query.trim();
    const recentIds = q ? [] : recentConnections();
    const recent: Item[] = recentIds.flatMap((id) => {
      const c = connections.find((x) => x.id === id);
      return c ? [{ kind: "conn" as const, hit: { id: c.id, name: c.name, host: c.host, protocol: c.protocol, folderId: c.folderId } }] : [];
    });
    const conns: Item[] = hits.filter((h) => !recentIds.includes(h.id)).map((hit) => ({ kind: "conn", hit }));
    const actions: Item[] = filterRank(q, paletteActions(close)).map((action) => ({ kind: "action", action }));
    // Settings pages are many: listed when the query asks for them.
    const pages: Item[] = q ? filterRank(q, settingsPages(close)).map((action) => ({ kind: "action", action, settings: true })) : [];
    return [
      { id: "recent", label: "Recent", items: recent },
      { id: "conns", label: "Connections", items: conns },
      { id: "actions", label: "Actions", items: actions },
      { id: "settings", label: "Settings", items: pages },
    ].filter((g) => g.items.length > 0);
  }, [open, query, hits, connections, setPalette]);

  const items = groups.flatMap((g) => g.items);

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

  const optionId = (i: number) => `palette-opt-${String(i)}`;
  let index = -1;

  return (
    <>
      <div className="scrim" onMouseDown={() => { setPalette(false); }} />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="pop m-hud fixed left-1/2 top-[12vh] z-50 w-[660px] max-w-[calc(100vw-32px)] -translate-x-1/2"
        data-active
      >
        <div className="palette-input-row">
          <span aria-hidden className="palette-caret"><Icon name="search" /></span>
          <input
            ref={inputRef}
            value={query}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={items.length ? optionId(cursor) : undefined}
            aria-label="Search connections"
            placeholder="Search hosts, credentials and commands"
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
            className="h-12 min-w-0 flex-1 bg-transparent text-[length:var(--fs-16)] text-text placeholder:text-text-3 focus:shadow-none focus:outline-none"
          />
          <span className="palette-meta tnum" aria-live="polite">{items.length} results</span>
        </div>
        <div id="palette-list" role="listbox" aria-label="Results" className="max-h-[52vh] overflow-y-auto py-1">
          {items.length === 0 && (
            <p className="px-4 py-6 text-center text-text-faint">No connection or command matches “{query}”.</p>
          )}
          {groups.map((g) => (
            <div key={g.id} role="group" aria-labelledby={`palette-g-${g.id}`}>
              <p id={`palette-g-${g.id}`} className="palette-group t-caption" role="presentation">{g.label}</p>
              {g.items.map((it) => {
                index += 1;
                const i = index;
                return (
                  <Fragment key={it.kind === "conn" ? `${g.id}-${it.hit.id}` : it.action.id}>
                    <div
                      id={optionId(i)}
                      role="option"
                      aria-selected={i === cursor}
                      onMouseMove={() => { if (cursor !== i) setCursor(i); }}
                      onClick={() => { run(i); }}
                      className="palette-opt"
                    >
                      {it.kind === "conn" ? (
                        <>
                          <ProtocolIcon protocol={it.hit.protocol} />
                          <span className="font-medium">{it.hit.name}</span>
                          <span className="mono truncate text-text-muted">{it.hit.host}</span>
                          <span className="palette-meta ml-auto truncate">{folderPath(folders, it.hit.folderId).join(" / ")}</span>
                          {i === cursor && <Kbd>↵</Kbd>}
                        </>
                      ) : (
                        <>
                          <span aria-hidden className="palette-action-icon"><Icon name={it.settings ? "gear" : "right"} /></span>
                          <span>{it.action.label}</span>
                          {it.settings && <span className="palette-meta">Settings</span>}
                          {it.action.keys && <span className="ml-auto"><Kbd>{it.action.keys}</Kbd></span>}
                        </>
                      )}
                    </div>
                  </Fragment>
                );
              })}
            </div>
          ))}
        </div>
        <div className="flex gap-5 border-t border-line px-4 py-2.5 text-[length:var(--fs-12)] text-text-faint">
          <span><Kbd>↑↓</Kbd> move</span>
          <span><Kbd>↵</Kbd> open or run</span>
          <span><Kbd>mod ↵</Kbd> open in new tab</span>
          <span><Kbd>esc</Kbd> close</span>
        </div>
      </div>
    </>
  );
}

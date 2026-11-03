import { useEffect, useMemo, useRef, useState } from "react";
import { Kbd, ProtocolPip } from "@nexus/ui";
import { useApp } from "../stores/app";

/** The front door: fuzzy-free substring search over name, host and tags, plus app actions. */
export function CommandPalette() {
  const open = useApp((s) => s.paletteOpen);
  const setPalette = useApp((s) => s.setPalette);
  const connections = useApp((s) => s.connections);
  const openTab = useApp((s) => s.openTab);
  const lock = useApp((s) => s.lock);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette(!useApp.getState().paletteOpen);
      } else if (e.key === "Escape" && useApp.getState().paletteOpen) {
        setPalette(false);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); };
  }, [setPalette]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
      queueMicrotask(() => inputRef.current?.focus());
    }
  }, [open]);

  const q = query.trim().toLowerCase();
  const items = useMemo(() => {
    const hits = q
      ? connections.filter(
          (c) => c.name.toLowerCase().includes(q) || c.host.toLowerCase().includes(q) || c.tags.some((t) => t.includes(q)),
        )
      : connections;
    const actions = [{ id: "action:lock", label: "Lock vault", hint: "wipes keys from memory" }].filter(
      (a) => !q || a.label.toLowerCase().includes(q),
    );
    return [...hits.map((c) => ({ kind: "conn" as const, c })), ...actions.map((a) => ({ kind: "action" as const, a }))];
  }, [q, connections]);

  if (!open) return null;

  function run(i: number) {
    const it = items[i];
    if (!it) return;
    if (it.kind === "conn") openTab(it.c.id);
    else {
      setPalette(false);
      void lock();
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/40" onMouseDown={() => { setPalette(false); }}>
      <div
        role="dialog"
        aria-label="Command palette"
        onMouseDown={(e) => { e.stopPropagation(); }}
        className="mx-auto mt-[12vh] w-[620px] overflow-hidden rounded-[var(--radius-m)] bg-surface-raised"
        style={{ boxShadow: "var(--shadow-pop)" }}
      >
        <input
          ref={inputRef}
          value={query}
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
            } else if (e.key === "Enter") run(cursor);
          }}
          placeholder="Host, name or tag"
          aria-label="Search connections"
          className="w-full border-b border-line bg-transparent px-4 py-3 text-[length:var(--fs-l)] text-text placeholder:text-text-faint focus:outline-none"
        />
        <ul role="listbox" className="max-h-[50vh] overflow-y-auto py-1">
          {items.length === 0 && <li className="px-4 py-6 text-center text-text-faint">No connection matches “{query}”.</li>}
          {items.map((it, i) => (
            <li
              key={it.kind === "conn" ? it.c.id : it.a.id}
              role="option"
              aria-selected={i === cursor}
              onMouseEnter={() => { setCursor(i); }}
              onClick={() => { run(i); }}
              className={`flex cursor-default items-center gap-3 px-4 py-2 ${i === cursor ? "bg-accent-soft" : ""}`}
            >
              {it.kind === "conn" ? (
                <>
                  <ProtocolPip protocol={it.c.protocol} />
                  <span className="font-medium">{it.c.name}</span>
                  <span className="mono text-text-muted">{it.c.host}</span>
                  <span className="ml-auto text-[length:var(--fs-xs)] text-text-faint">{it.c.tags.join(" ")}</span>
                </>
              ) : (
                <>
                  <span className="w-[30px]" />
                  <span className="font-medium">{it.a.label}</span>
                  <span className="text-text-muted">{it.a.hint}</span>
                </>
              )}
            </li>
          ))}
        </ul>
        <div className="flex gap-4 border-t border-line px-4 py-2 text-[length:var(--fs-xs)] text-text-faint">
          <span>
            <Kbd>↑↓</Kbd> move
          </span>
          <span>
            <Kbd>↵</Kbd> open
          </span>
          <span>
            <Kbd>esc</Kbd> close
          </span>
        </div>
      </div>
    </div>
  );
}

import { useMemo } from "react";
import { ProtocolPip } from "@mooring/ui";
import type { ImportItem, ImportPreview } from "../../lib/ipc";
import { useTree } from "../../stores/tree";
import { plural } from "./importText";

/**
 * The dry run as a tree of checkboxes: folders and connections in plan order, each connection
 * with protocol, host, port and user. An unchecked folder lifts its children a level (I1 rule); a
 * duplicate carries the name of the connection it repeats.
 */
export function PreviewTree({ preview, excluded, onToggle, onAll, skipDuplicates }: {
  preview: ImportPreview;
  excluded: ReadonlySet<string>;
  onToggle: (key: string, on: boolean) => void;
  onAll: (on: boolean) => void;
  skipDuplicates: boolean;
}) {
  const existing = useTree((s) => s.connections);
  const rows = useMemo(() => flatten(preview.items), [preview.items]);
  const kept = preview.items.filter((i) => !excluded.has(i.key)).length;
  const dupName = (id: string) => existing.find((c) => c.id === id)?.name ?? "an existing connection";

  return (
    <section className="imp-tree" aria-label="Items to import">
      <header className="imp-tree-head">
        <span className="imp-tree-title">{preview.rootName}</span>
        <span className="imp-tree-kept tnum" role="status">{kept} of {plural(preview.items.length, "item")} selected</span>
        <button type="button" className="btn btn-ghost" onClick={() => { onAll(true); }}>All</button>
        <button type="button" className="btn btn-ghost" onClick={() => { onAll(false); }}>None</button>
      </header>
      <ul className="imp-rows">
        {rows.map(({ item, depth }) => {
          const on = !excluded.has(item.key);
          const dup = item.duplicateOf !== undefined;
          const greyed = !on || (dup && skipDuplicates);
          return (
            <li key={item.key} className="imp-row" data-kind={item.kind} data-off={greyed || undefined} style={{ paddingLeft: 10 + depth * 18 }}>
              <label className="imp-row-label">
                <input type="checkbox" checked={on} onChange={(e) => { onToggle(item.key, e.target.checked); }} aria-label={item.name} />
                {item.kind === "folder" ? (
                  <svg className="imp-row-glyph" width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.1" aria-hidden>
                    <path d="M1 3h3.5l1 1.5H11V10H1z" />
                  </svg>
                ) : (
                  <ProtocolPip protocol={item.protocol ?? "ssh"} />
                )}
                <span className="imp-row-name">{item.name}</span>
              </label>
              {item.kind === "connection" && (
                <span className="imp-row-target mono">
                  {item.username && <span className="imp-row-user">{item.username}@</span>}
                  {item.host}
                  {item.port !== undefined && <span className="imp-row-port">:{item.port}</span>}
                </span>
              )}
              {dup && (
                <span className="imp-dup" title={`Same protocol, host, port and user as “${dupName(item.duplicateOf ?? "")}”`}>
                  {skipDuplicates ? "Duplicate, skipped" : "Duplicate"}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function flatten(items: ImportItem[]): { item: ImportItem; depth: number }[] {
  const children = new Map<string | null, ImportItem[]>();
  for (const it of items) children.set(it.parent, [...(children.get(it.parent) ?? []), it]);
  const out: { item: ImportItem; depth: number }[] = [];
  const seen = new Set<string>();
  const walk = (parent: string | null, depth: number) => {
    for (const it of children.get(parent) ?? []) {
      if (seen.has(it.key)) continue; // a cycle in the plan never hangs the view
      seen.add(it.key);
      out.push({ item: it, depth });
      if (it.kind === "folder") walk(it.key, depth + 1);
    }
  };
  walk(null, 0);
  // Orphans (a parent the plan never listed) land at the root, like the import root in Rust.
  for (const it of items) if (!seen.has(it.key)) { seen.add(it.key); out.push({ item: it, depth: 0 }); }
  return out;
}

import { useApp } from "../stores/app";

/** Right pane: properties of the selected connection. Credentials show as a reference, never a value. */
export function Inspector() {
  const selected = useApp((s) => s.selected);
  const c = useApp((s) => s.connections.find((x) => x.id === selected));
  const folder = useApp((s) => s.folders.find((f) => f.id === c?.folder));

  if (!c) {
    return (
      <aside aria-label="Details" className="h-full border-l border-line bg-bg-sunken p-4 text-text-faint">
        Select a connection to see its details.
      </aside>
    );
  }

  const rows: [string, string, boolean][] = [
    ["Name", c.name, false],
    ["Host", c.host, true],
    ["Protocol", c.protocol, false],
    ["Folder", folder?.name ?? "", false],
    ["Tags", c.tags.join(", ") || "none", false],
    ["Credential", "inherited from folder", false],
  ];

  return (
    <aside aria-label="Details" className="h-full overflow-y-auto border-l border-line bg-bg-sunken">
      <h2 className="border-b border-line px-4 py-3 text-[length:var(--fs-l)] font-medium">{c.name}</h2>
      <dl className="px-4 py-2">
        {rows.map(([k, v, mono]) => (
          <div key={k} className="grid grid-cols-[88px_1fr] gap-2 py-1.5">
            <dt className="text-text-muted">{k}</dt>
            <dd className={`truncate ${mono ? "mono" : ""}`}>{v}</dd>
          </div>
        ))}
      </dl>
      <p className="px-4 pt-2 text-[length:var(--fs-xs)] text-text-faint">
        Revealing or copying a credential writes an audit entry and clears the clipboard after 30 seconds.
      </p>
    </aside>
  );
}

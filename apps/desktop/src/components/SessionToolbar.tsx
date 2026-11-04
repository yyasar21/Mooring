export type SessionTool = "terminal" | "forwards" | "files";

const TOOLS: { id: SessionTool; label: string }[] = [
  { id: "terminal", label: "Terminal" },
  { id: "forwards", label: "Forwards" },
  { id: "files", label: "Files" },
];

/** Switches an SSH tab between its terminal, port forwards and the SFTP browser. */
export function SessionToolbar({ tool, onTool, onDetach = null }: { tool: SessionTool; onTool: (t: SessionTool) => void; onDetach?: (() => void) | null }) {
  return (
    <div role="toolbar" aria-label="Session tools" className="session-toolbar">
      {TOOLS.map((t) => (
        <button
          key={t.id}
          type="button"
          className="btn btn-ghost"
          aria-pressed={tool === t.id}
          onClick={() => { onTool(t.id); }}
        >
          {t.label}
        </button>
      ))}
      <span className="flex-1" />
      <button type="button" className="btn btn-ghost" disabled={!onDetach} onClick={() => { onDetach?.(); }}>
        Detach to window
      </button>
    </div>
  );
}

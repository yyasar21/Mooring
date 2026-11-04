export type SessionTool = "terminal" | "forwards" | "files";

const TOOLS: { id: SessionTool; label: string }[] = [
  { id: "terminal", label: "Terminal" },
  { id: "forwards", label: "Forwards" },
  { id: "files", label: "Files" },
];

/** Switches an SSH tab between its terminal, port forwards and the SFTP browser. */
export function SessionToolbar({ tool, onTool }: { tool: SessionTool; onTool: (t: SessionTool) => void }) {
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
    </div>
  );
}

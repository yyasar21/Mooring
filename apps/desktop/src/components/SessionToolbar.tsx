import { Icon, type IconName } from "@mooring/ui";

export type SessionTool = "terminal" | "forwards" | "files";

const TOOLS: { id: SessionTool; label: string; icon: IconName }[] = [
  { id: "terminal", label: "Terminal", icon: "ssh" },
  { id: "forwards", label: "Forwards", icon: "forward" },
  { id: "files", label: "Files", icon: "file" },
];

/**
 * An SSH tab's view switch (a segmented control: terminal, port forwards, the SFTP browser) and
 * its window action. The toolbar name, the button names and `aria-pressed` are the e2e contract.
 */
export function SessionToolbar({ tool, onTool, onDetach = null }: { tool: SessionTool; onTool: (t: SessionTool) => void; onDetach?: (() => void) | null }) {
  return (
    <>
      <div role="toolbar" aria-label="Session tools" className="segmented session-views">
        {TOOLS.map((t) => (
          <button key={t.id} type="button" aria-pressed={tool === t.id} onClick={() => { onTool(t.id); }}>
            <Icon name={t.icon} size={14} />
            {t.label}
          </button>
        ))}
      </div>
      <DetachButton onDetach={onDetach} />
    </>
  );
}

/** "Detach to window" as an icon button (the accessible name is kept; the tooltip says the same). */
export function DetachButton({ onDetach }: { onDetach: (() => void) | null }) {
  return (
    <button
      type="button"
      className="icon-btn"
      aria-label="Detach to window"
      title="Detach to window"
      disabled={!onDetach}
      onClick={() => { onDetach?.(); }}
    >
      <Icon name="external" />
    </button>
  );
}

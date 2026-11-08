import { useId } from "react";
import { Icon, type IconName } from "@mooring/ui";
import { canDisconnect, disconnect } from "../stores/sessions.disconnect";
import type { Tab } from "../stores/sessions";

export type SessionTool = "terminal" | "forwards" | "files";

const TOOLS: { id: SessionTool; label: string; icon: IconName }[] = [
  { id: "terminal", label: "Terminal", icon: "ssh" },
  { id: "forwards", label: "Forwards", icon: "forward" },
  { id: "files", label: "Files", icon: "file" },
];

/**
 * An SSH tab's view switch (a segmented control: terminal, port forwards, the SFTP browser) and
 * its window action. The toolbar name, the button names and `aria-pressed` are the e2e contract:
 * the open-forward count on "Forwards" is a description, so the name stays "Forwards".
 */
export function SessionToolbar({ tool, onTool, onDetach = null, forwards = 0 }: {
  tool: SessionTool;
  onTool: (t: SessionTool) => void;
  onDetach?: (() => void) | null;
  forwards?: number;
}) {
  const countId = useId();
  return (
    <>
      <div role="toolbar" aria-label="Session tools" className="segmented session-views">
        {TOOLS.map((t) => (
          <button
            key={t.id}
            type="button"
            aria-pressed={tool === t.id}
            aria-describedby={t.id === "forwards" && forwards > 0 ? countId : undefined}
            onClick={() => { onTool(t.id); }}
          >
            <Icon name={t.icon} size={14} />
            {t.label}
            {t.id === "forwards" && forwards > 0 && <span className="seg-count tnum" aria-hidden>{forwards}</span>}
          </button>
        ))}
      </div>
      {forwards > 0 && <span id={countId} className="sr-only">{forwards === 1 ? "1 forward open" : `${String(forwards)} forwards open`}</span>}
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

/** The header's Disconnect: ends the session, keeps the tab (closed, with Reconnect). */
export function DisconnectButton({ tab }: { tab: Tab }) {
  return (
    <button type="button" className="btn btn-sm" disabled={!canDisconnect(tab)} onClick={() => void disconnect(tab.id)}>
      Disconnect
    </button>
  );
}

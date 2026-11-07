import type { ConnectionSummary, HopState } from "../../lib/ipc";
import type { Tab } from "../../stores/sessions";
import { useTree } from "../../stores/tree";

const HOP_TEXT: Record<HopState, string> = {
  connecting: "connecting",
  authenticating: "signing in",
  up: "connected",
  failed: "failed",
};

/** The name of jump host `hop` of `target` (the hop's connection name, else its host). */
export function hopName(connections: readonly ConnectionSummary[], target: ConnectionSummary | undefined, hop: number, host = ""): string {
  const id = target?.via?.[hop];
  const c = id ? connections.find((x) => x.id === id) : undefined;
  return c?.name ?? (host.replace(/:\d+$/, "") || `jump host ${String(hop + 1)}`);
}

/**
 * ADR-0025 hop progress on a session tab: one chip per jump host from `hop_status`, in chain
 * order, with its state and `host:port`. Shown while the chain comes up and after it failed;
 * hidden once the target is connected.
 */
export function HopStrip({ tab }: { tab: Tab }) {
  const connections = useTree((s) => s.connections);
  const target = connections.find((c) => c.id === tab.connectionId);
  const hops = tab.hops ?? [];
  const failed = hops.some((h) => h.state === "failed");
  if (hops.length === 0 || (tab.state === "connected" && !failed) || tab.state === "detached") return null;
  return (
    <ol className="hop-strip" aria-label="Jump hosts" aria-live="polite">
      <li className="hop-strip-label" aria-hidden>Via</li>
      {hops.map((h, i) => {
        const name = hopName(connections, target, h.hop, h.host);
        return (
          <li key={h.hop} className="contents">
            {i > 0 && <span aria-hidden className="hop-sep">→</span>}
            <span className="hop-chip" data-state={h.state} aria-label={`Jump host ${String(h.hop + 1)} of ${String(h.of)}, ${name}, ${h.host}: ${HOP_TEXT[h.state]}`}>
              <span>{name}</span>
              <span className="hop-chip-host">{h.host}</span>
              <span>{HOP_TEXT[h.state]}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}

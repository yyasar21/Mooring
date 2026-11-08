import { useEffect, useState, type ReactNode } from "react";
import { StateDot } from "@mooring/ui";
import type { ConnectionSummary } from "../lib/ipc";
import type { Tab } from "../stores/sessions";
import { connectedSince, fmtDuration, sessionStatus } from "../stores/sessionClock";
import { folderPath, useTree } from "../stores/tree";

/** `host:port`, or the host alone when the connection uses its protocol's default port. */
export function hostLabel(c: Pick<ConnectionSummary, "host" | "port"> | undefined): string {
  if (!c) return "";
  return c.port ? `${c.host}:${String(c.port)}` : c.host;
}

/** Ticks once a second while `on`. */
function useSecondTick(on: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!on) return;
    setNow(Date.now());
    const id = window.setInterval(() => { setNow(Date.now()); }, 1000);
    return () => { window.clearInterval(id); };
  }, [on]);
  return now;
}

/** The status pill: a dot and a label, plus how long the session has been up. */
export function SessionStatusPill({ tab }: { tab: Tab }) {
  const st = sessionStatus(tab);
  const since = connectedSince(tab.id);
  const now = useSecondTick(since !== null);
  return (
    <span className="pill session-pill" data-tone={st.tone === "neutral" ? undefined : st.tone}>
      <StateDot tone={st.dot} />
      {st.label}
      {since !== null && (
        <>
          <span aria-hidden> · </span>
          <span className="session-timer" aria-label={`for ${fmtDuration(now - since)}`}>{fmtDuration(now - since)}</span>
        </>
      )}
    </span>
  );
}

/**
 * The header of every session tab (design review §4.2): the folder breadcrumb, the name and the
 * host in mono, the status pill with its timer, then the tab's own view switch and window actions
 * (`children`). Purely presentational: the controls keep their own names and roles.
 */
export function SessionHeader({ tab, connection, children }: { tab: Tab; connection: ConnectionSummary | undefined; children?: ReactNode }) {
  const folders = useTree((s) => s.folders);
  const crumbs = folderPath(folders, connection?.folderId);
  const host = hostLabel(connection);
  return (
    <div className="session-header">
      <div className="session-id">
        {crumbs.length > 0 && (
          <nav aria-label="Folder" className="session-crumbs">
            <ol>
              {crumbs.map((name, i) => (
                <li key={`${String(i)}-${name}`}>{name}</li>
              ))}
            </ol>
          </nav>
        )}
        <div className="session-title">
          <span className="session-name">{connection?.name ?? "Session"}</span>
          {host && <span className="session-host mono select-text">{host}</span>}
          <SessionStatusPill tab={tab} />
        </div>
      </div>
      <div className="session-actions">{children}</div>
    </div>
  );
}

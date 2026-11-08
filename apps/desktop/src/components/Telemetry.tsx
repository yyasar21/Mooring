import { useEffect, useState } from "react";
import { Icon, StateDot } from "@mooring/ui";
import { ipc, type AuditVerify } from "../lib/ipc";
import { useApp } from "../stores/app";
import { useSessions } from "../stores/sessions";
import { useUi } from "../stores/ui";

const VERIFY_EVERY_MS = 60_000;

/**
 * The status bar (design review 2026-11, Q8): plain words for vault state, open sessions, anyone
 * waiting for input and the audit chain, then the version. Build details live in Settings →
 * About. Read-only; no live regions here (the audit view owns the chain status).
 */
export function Telemetry() {
  const info = useApp((s) => s.info);
  const tabs = useSessions((s) => s.tabs);
  const live = tabs.filter((t) => t.state === "connected").length;
  const pending = tabs.filter((t) => t.state === "connecting").length;
  const waiting = tabs.filter((t) => t.prompt !== null).length;

  return (
    <footer className="statusbar telemetry" aria-label="Status">
      <span className="status-item">
        <StateDot tone="ok" />
        Vault unlocked
      </span>
      <span className="status-item tnum">
        {live} {live === 1 ? "session" : "sessions"} open{pending > 0 && `, ${pending} connecting`}
      </span>
      {waiting > 0 && (
        <span className="status-item" data-tone="warning">
          <StateDot tone="wait" />
          {waiting} waiting for you
        </span>
      )}
      <ChainItem />
      <span className="status-spacer" />
      {info && <span className="status-item tnum">Mooring {info.version}</span>}
    </footer>
  );
}

function ChainItem() {
  const [v, setV] = useState<AuditVerify | null>(null);
  const view = useUi((s) => s.view);

  useEffect(() => {
    let alive = true;
    const run = () => {
      ipc.auditVerify().then((r) => { if (alive) setV(r); }, () => { if (alive) setV(null); });
    };
    run();
    const t = setInterval(run, VERIFY_EVERY_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [view]);

  if (v === null) return <span className="status-item">Checking audit chain…</span>;
  if (v.ok) {
    return (
      <span className="status-item">
        <Icon name="shield" size={13} />
        Audit chain verified
      </span>
    );
  }
  return (
    <span className="status-item" data-tone="danger">
      <Icon name="alert" size={13} />
      Audit chain broken at entry {v.brokenAt ?? "?"}
    </span>
  );
}

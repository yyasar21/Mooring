import { useEffect, useState } from "react";
import { StateDot } from "@mooring/ui";
import { ipc, type AuditVerify } from "../lib/ipc";
import { useApp } from "../stores/app";
import { useSessions } from "../stores/sessions";
import { useUi } from "../stores/ui";

const VERIFY_EVERY_MS = 60_000;

/**
 * The telemetry strip at the bottom of the deck: vault state, session counts, audit chain health,
 * build and a local clock. Read-only; no live regions here (the audit view owns the chain status).
 */
export function Telemetry() {
  const info = useApp((s) => s.info);
  const tabs = useSessions((s) => s.tabs);
  const live = tabs.filter((t) => t.state === "connected").length;
  const pending = tabs.filter((t) => t.state === "connecting").length;
  const waiting = tabs.filter((t) => t.prompt !== null).length;

  return (
    <footer className="telemetry" aria-label="Status">
      <span className="tele-cell">
        <span aria-hidden className="state-dot" data-state="connected" />
        Vault <span className="tele-val" data-tone="ok">unlocked</span>
      </span>
      <span className="tele-cell">
        <StateDot state={live > 0 ? "connected" : pending > 0 ? "connecting" : "closed"} />
        Links
        <span className="tele-val tnum">
          {live} connected{pending > 0 && `, ${pending} connecting`}
        </span>
      </span>
      {waiting > 0 && (
        <span className="tele-cell">
          <span aria-hidden className="tab-attn" />
          <span className="tele-val" data-tone="hot">{waiting} waiting for you</span>
        </span>
      )}
      <ChainCell />
      <span className="tele-spacer" />
      {info && (
        <span className="tele-cell">
          Build
          <span className="tele-val">
            {info.version} {info.os}/{info.arch}
            {info.debug ? " debug" : ""}
          </span>
        </span>
      )}
      <Clock />
    </footer>
  );
}

function ChainCell() {
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

  return (
    <span className="tele-cell">
      Audit chain
      {v === null ? (
        <span className="tele-val">checking</span>
      ) : v.ok ? (
        <span className="tele-val tnum" data-tone="ok">OK {v.entries}</span>
      ) : (
        <span className="tele-val" data-tone="hot">broken at {v.brokenAt ?? "?"}</span>
      )}
    </span>
  );
}

/** Local time, ticking once a second in its own tiny component so nothing else re-renders. */
function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => { setNow(new Date()); }, 1000);
    return () => { clearInterval(t); };
  }, []);
  const p = (n: number) => n.toString().padStart(2, "0");
  return (
    <span className="tele-cell">
      Local
      <time className="tele-val tnum" dateTime={now.toISOString()}>
        {p(now.getHours())}:{p(now.getMinutes())}:{p(now.getSeconds())}
      </time>
    </span>
  );
}

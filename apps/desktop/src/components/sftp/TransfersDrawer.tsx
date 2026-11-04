import { useState } from "react";
import { isFinished, uploadTarget, useTransfers, type Transfer } from "../../stores/transfers";
import { formatBytes, percent } from "./format";

const STATE_LABEL: Record<Transfer["state"], string> = {
  starting: "Starting",
  running: "Running",
  done: "Done",
  failed: "Failed",
  cancelled: "Cancelled",
};

/** Transfers of one session, newest last. Collapsible; running transfers keep going when closed. */
export function TransfersDrawer({ sessionId }: { sessionId: string }) {
  const items = useTransfers((s) => s.items).filter((t) => t.sessionId === sessionId);
  const clearFinished = useTransfers((s) => s.clearFinished);
  const [open, setOpen] = useState(true);
  const active = items.filter((t) => !isFinished(t)).length;
  const finished = items.length - active;

  return (
    <section aria-label="Transfers" className="xfer-drawer" data-open={open || undefined}>
      <header className="xfer-head">
        <button type="button" className="btn btn-ghost" aria-expanded={open} onClick={() => { setOpen(!open); }}>
          <span aria-hidden className="xfer-caret">{open ? "v" : ">"}</span>
          Transfers
        </button>
        <span className="chip tnum" data-tone={active > 0 ? "ok" : undefined}>
          {active} active
        </span>
        <span className="flex-1" />
        {finished > 0 && (
          <button type="button" className="btn btn-ghost" onClick={() => { clearFinished(sessionId); }}>
            Clear finished
          </button>
        )}
      </header>
      {open && (
        <ul className="xfer-list">
          {items.length === 0 && <li className="xfer-empty">No transfers yet. Download a file or upload one from this computer.</li>}
          {items.map((t) => (
            <TransferRow key={t.key} t={t} />
          ))}
        </ul>
      )}
    </section>
  );
}

function TransferRow({ t }: { t: Transfer }) {
  const cancel = useTransfers((s) => s.cancel);
  const dismiss = useTransfers((s) => s.dismiss);
  const pct = percent(t.bytesDone, t.bytesTotal);
  const done = isFinished(t);
  const label = t.direction === null ? t.name : `${t.direction === "download" ? "Download" : "Upload"} ${t.name}`;

  return (
    <li className="xfer-row" data-state={t.state} aria-label={label}>
      <span className="xfer-dir" aria-hidden>{t.direction === null ? "··" : t.direction === "download" ? "DN" : "UP"}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="truncate font-medium">{t.name}</span>
          <span className="mono truncate text-[length:var(--fs-xs)] text-text-faint">
            {t.direction === null ? "resumed after unlock" : t.direction === "download" ? `from ${t.remote}` : `to ${uploadTarget(t)}`}
          </span>
        </div>
        <div
          role="progressbar"
          aria-label={`${label} progress`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct ?? undefined}
          aria-valuetext={`${STATE_LABEL[t.state]}${pct !== null ? `, ${pct}%` : ""}`}
          className="xfer-bar"
        >
          <span className="xfer-fill" style={{ width: `${pct ?? (t.state === "done" ? 100 : 0)}%` }} />
        </div>
        <div className="xfer-meta">
          <span className="xfer-state">{STATE_LABEL[t.state]}</span>
          <span className="mono tnum">
            {formatBytes(t.bytesDone)}
            {t.bytesTotal !== null && ` of ${formatBytes(t.bytesTotal)}`}
          </span>
          {t.error && <span className="xfer-error">{t.error}</span>}
          {t.cancelRequested && !done && <span>Cancelling…</span>}
        </div>
      </div>
      {done ? (
        <button type="button" className="btn btn-ghost" aria-label={`Dismiss ${t.name}`} onClick={() => { dismiss(t.key); }}>
          Dismiss
        </button>
      ) : (
        <button type="button" className="btn btn-ghost btn-danger" aria-label={`Cancel ${t.name}`} onClick={() => void cancel(t.key)}>
          Cancel
        </button>
      )}
    </li>
  );
}

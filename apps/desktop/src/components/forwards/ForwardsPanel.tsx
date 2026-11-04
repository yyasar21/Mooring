import { useState } from "react";
import { FORWARD_LIMITS, type ForwardInfo } from "../../lib/ipc";
import { ForwardForm, KIND_META } from "./ForwardForm";
import { formatHostPort, useForwards } from "./useForwards";

/** Port forwards of one SSH session: list, open, close. Forwards die with the session. */
export function ForwardsPanel({ sessionId }: { sessionId: string | null }) {
  const fw = useForwards(sessionId);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!sessionId) {
    return (
      <section aria-label="Port forwards" className="tool-panel">
        <p className="tool-empty">Forwards are available once the session is connected.</p>
      </section>
    );
  }

  const full = fw.items.length >= FORWARD_LIMITS.perSession;

  return (
    <section aria-label="Port forwards" className="tool-panel">
      <header className="tool-head">
        <h2 className="m-display text-[length:var(--fs-l)]">Port forwards</h2>
        <span className="chip tnum" title="Forwards on this session / limit">
          {fw.items.length} / {FORWARD_LIMITS.perSession}
        </span>
        <span className="flex-1" />
        {!adding && (
          <button type="button" className="btn btn-primary" disabled={full} onClick={() => { setAdding(true); fw.clearError(); }}>
            New forward
          </button>
        )}
      </header>
      {fw.error && <p role="alert" className="tool-error">{fw.error}</p>}

      {adding && (
        <ForwardForm
          busy={busy}
          onCancel={() => { setAdding(false); }}
          onSubmit={async (d) => {
            setBusy(true);
            const ok = (await fw.open(d)) !== null;
            setBusy(false);
            if (ok) setAdding(false);
            return ok;
          }}
        />
      )}

      <div className="fw-table" role="table" aria-label="Forwards on this session">
        <div role="row" className="fw-row fw-row-head">
          <span role="columnheader">Kind</span>
          <span role="columnheader">Bind</span>
          <span role="columnheader">Target</span>
          <span role="columnheader">Exposure</span>
          <span role="columnheader" className="text-right">Conns</span>
          <span role="columnheader"><span className="sr-only">Actions</span></span>
        </div>
        {fw.items.map((f) => (
          <ForwardRow key={f.id} f={f} onClose={() => void fw.close(f.id)} />
        ))}
        {fw.items.length === 0 && !fw.loading && (
          <div role="row" className="fw-row-empty">
            <span role="cell">No forwards yet. A local forward makes a service behind the server reachable on this machine.</span>
          </div>
        )}
      </div>
    </section>
  );
}

function ForwardRow({ f, onClose }: { f: ForwardInfo; onClose: () => void }) {
  const bind = formatHostPort(f.bind);
  return (
    <div role="row" className="fw-row" data-external={f.exposure === "external" || undefined}>
      <span role="cell" className="inline-flex items-center gap-2">
        <span className="fw-kind-tag" aria-hidden>{KIND_META[f.kind].short}</span>
        {KIND_META[f.kind].label}
      </span>
      <span role="cell" className="mono select-text truncate">{bind}</span>
      <span role="cell" className="mono select-text truncate">{f.target ? formatHostPort(f.target) : "SOCKS5"}</span>
      <span role="cell">
        {f.exposure === "external" ? (
          <span className="chip" data-tone="hot">External</span>
        ) : (
          <span className="chip">Loopback</span>
        )}
      </span>
      <span role="cell" className="mono tnum text-right" data-live={f.connections > 0 || undefined}>{f.connections}</span>
      <span role="cell" className="text-right">
        <button type="button" className="btn btn-ghost btn-danger" aria-label={`Close forward ${bind}`} onClick={onClose}>
          Close
        </button>
      </span>
    </div>
  );
}

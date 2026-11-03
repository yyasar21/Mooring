import { useEffect, useState } from "react";
import { useCredentials } from "../../stores/credentials";

/**
 * "Copy password" asks Rust to write the clipboard (and audit it). The UI never sees the value
 * and never touches the clipboard; it only shows how long until Rust clears it.
 */
export function CopyPassword({ credentialId }: { credentialId: string }) {
  const until = useCredentials((s) => s.copiedUntil[credentialId]);
  const copy = useCredentials((s) => s.copyPassword);
  const [now, setNow] = useState(() => Date.now());
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (until === undefined) return;
    setNow(Date.now());
    const t = setInterval(() => {
      const n = Date.now();
      setNow(n);
      useCredentials.getState().expireCopies(n);
    }, 250);
    return () => { clearInterval(t); };
  }, [until]);

  const left = until === undefined ? 0 : Math.max(0, until - now);
  const seconds = Math.ceil(left / 1000);
  const frac = Math.min(1, left / 30_000);

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        className="btn"
        disabled={busy}
        onClick={() => {
          setBusy(true);
          void copy(credentialId).finally(() => { setBusy(false); });
        }}
      >
        {until === undefined ? "Copy password" : "Copy again"}
      </button>
      {until !== undefined && seconds > 0 && (
        <span className="countdown tnum" role="status" aria-live="polite" aria-label={`Clipboard clears in ${seconds} seconds`}>
          <span
            aria-hidden
            className="countdown-ring"
            style={{ background: `conic-gradient(var(--accent) ${frac * 360}deg, var(--line-strong) 0)` }}
          />
          clears in {seconds}s
        </span>
      )}
    </div>
  );
}

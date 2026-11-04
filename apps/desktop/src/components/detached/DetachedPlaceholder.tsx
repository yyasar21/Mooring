import { useState } from "react";
import { bringBack } from "../../stores/sessions.detach";

/**
 * Shown in `main` over a tab whose session lives in a `detached-<sessionId>` window (after Rust's
 * `detached` event). "Bring back" is `window_attach`; the tab returns on `attached`.
 */
export function DetachedPlaceholder({ tabId, name }: { tabId: string; name: string }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="link-banner detached-card m-hud" role="status" aria-label="Open in a separate window">
      <span className="m-micro">Detached</span>
      <span className="m-display text-[length:var(--fs-l)]">Open in a separate window</span>
      <span className="text-text-muted">
        {name} is shown in its own window. Input and output go there; closing that window brings it back here.
      </span>
      {error && (
        <span role="alert" className="text-[length:var(--fs-xs)] text-danger">
          {error}
        </span>
      )}
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void bringBack(tabId).then((e) => {
              setError(e);
              setBusy(false);
            });
          }}
        >
          Bring back
        </button>
      </div>
    </div>
  );
}

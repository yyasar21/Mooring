import { createPortal } from "react-dom";
import { useToasts } from "../stores/toast";

/**
 * Bottom-right confirmations ("Credential saved"). One polite live region, so a screen reader
 * hears each message once; each toast can be dismissed early with its button. Errors never go
 * here: they stay next to the control that failed.
 */
export function Toasts() {
  const toasts = useToasts((s) => s.toasts);
  const dismiss = useToasts((s) => s.dismiss);
  // Portalled to <body>: fixed in the corner, outside the shell grid (whose rows count its children).
  // A bare polite live region (no role), so it never competes with a screen's own status lines.
  return createPortal(
    <div className="toast-stack" aria-live="polite" aria-atomic="false" data-testid="toasts">
      {toasts.map((t) => (
        <div key={t.id} className="toast m-hud" data-active>
          <span aria-hidden className="state-dot" data-state="connected" />
          <span className="min-w-0 flex-1 truncate">{t.text}</span>
          <button type="button" className="icon-btn" aria-label={`Dismiss: ${t.text}`} onClick={() => { dismiss(t.id); }}>
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
              <path d="M2 2l6 6M8 2l-6 6" />
            </svg>
          </button>
        </div>
      ))}
    </div>,
    document.body,
  );
}

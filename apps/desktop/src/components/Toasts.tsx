import { createPortal } from "react-dom";
import { Icon, type IconName } from "@mooring/ui";
import { useToasts, type ToastTone } from "../stores/toast";

const ICON: Record<ToastTone, IconName> = { success: "check-circle", info: "info", warning: "alert" };

/**
 * Bottom-right confirmations ("Credential saved"): a status icon, a title and an optional second
 * line, and a dismiss button. One polite live region, so a screen reader hears each message once.
 * Errors never go here: they stay next to the control that failed.
 */
export function Toasts() {
  const toasts = useToasts((s) => s.toasts);
  const dismiss = useToasts((s) => s.dismiss);
  // Portalled to <body>: fixed in the corner, outside the shell grid (whose rows count its children).
  // A bare polite live region (no role), so it never competes with a screen's own status lines.
  return createPortal(
    <div className="toast-stack" aria-live="polite" aria-atomic="false" data-testid="toasts">
      {toasts.map((t) => (
        <div key={t.id} className="toast" data-tone={t.tone}>
          <span className="toast-icon" aria-hidden>
            <Icon name={ICON[t.tone]} />
          </span>
          <span className="toast-body">
            <span className="toast-title">{t.text}</span>
            {t.detail && <span className="toast-detail">{t.detail}</span>}
          </span>
          <button type="button" className="icon-btn" aria-label={`Dismiss: ${t.text}`} onClick={() => { dismiss(t.id); }}>
            <Icon name="x" size={14} />
          </button>
        </div>
      ))}
    </div>,
    document.body,
  );
}

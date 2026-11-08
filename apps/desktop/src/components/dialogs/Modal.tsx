import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Icon } from "@mooring/ui";
import type { DecisionTone } from "./TrustDialog";

const TONE_ICON = { info: "info", warning: "shield", danger: "alert" } as const;

/** Modal shell: focus moves in on open, Tab is trapped, Escape closes, focus returns on close. */
export function Modal({
  title,
  onClose,
  children,
  width = 440,
  tone,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
  /** M8: a confirmation gets the decision header (tone icon + title). */
  tone?: DecisionTone;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const first = ref.current?.querySelector<HTMLElement>("[autofocus], input, select, textarea, button");
    first?.focus();
    return () => { previous?.focus(); };
  }, []);

  const trap = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key !== "Tab" || !ref.current) return;
    const items = [...ref.current.querySelectorAll<HTMLElement>("input, select, textarea, button, [tabindex='0']")].filter(
      (el) => !el.hasAttribute("disabled"),
    );
    const first = items[0];
    const last = items.at(-1);
    if (!first || !last) return;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  // Portalled to <body>: a modal opened from inside a panel must not inherit its stacking context.
  return createPortal(
    <>
      <div className="scrim" onMouseDown={onClose} />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onKeyDown={trap}
        className="modal fixed left-1/2 top-[14vh] z-50 max-h-[76vh] max-w-[calc(100vw-32px)] -translate-x-1/2 overflow-y-auto"
        data-tone={tone}
        style={{ width }}
      >
        <h2 className="modal-title">
          {tone && (
            <span className="decision-icon" data-tone={tone} aria-hidden>
              <Icon name={TONE_ICON[tone]} size={20} />
            </span>
          )}
          {title}
        </h2>
        {children}
      </div>
    </>,
    document.body,
  );
}

/** Footer row with the error line on the left and actions on the right. */
export function DialogFooter({ error, children }: { error: string | null; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 border-t border-[var(--border)] px-4 py-3">
      <p role="alert" className="min-w-0 flex-1 truncate text-[length:var(--fs-13)] text-danger">
        {error}
      </p>
      {children}
    </div>
  );
}

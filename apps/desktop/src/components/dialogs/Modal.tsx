import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

/** Modal shell: focus moves in on open, Tab is trapped, Escape closes, focus returns on close. */
export function Modal({
  title,
  onClose,
  children,
  width = 440,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
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
        className="pop m-hud fixed left-1/2 top-[14vh] z-50 max-h-[76vh] max-w-[calc(100vw-32px)] -translate-x-1/2 overflow-y-auto"
        data-active
        style={{ width }}
      >
        <h2 className="m-display flex items-center gap-3 border-b border-line px-4 py-3.5 text-[length:var(--fs-l)]">
          <span aria-hidden className="state-dot" data-state="connected" />
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
    <div className="flex items-center gap-2 border-t border-line px-4 py-3">
      <p role="alert" className="min-w-0 flex-1 truncate text-[length:var(--fs-s)] text-danger">
        {error}
      </p>
      {children}
    </div>
  );
}

import { useEffect, useRef, type KeyboardEvent, type ReactNode, type RefObject } from "react";
import { Icon, type IconName } from "@mooring/ui";
import { Modal } from "./Modal";

/** Tone of a decision: warning = check before you go on, danger = something is wrong or exposed. */
export type DecisionTone = "info" | "warning" | "danger";

const TONE_ICON: Record<DecisionTone, IconName> = { info: "info", warning: "shield", danger: "alert" };

/**
 * The header of every confirmation and trust question (M8): a tone icon and the title. The same
 * block heads the in-session trust dialogs and the confirmation modals, so they read as one family.
 */
export function DecisionHeader({ id, tone, icon, children }: { id?: string; tone: DecisionTone; icon?: IconName | undefined; children: ReactNode }) {
  return (
    <div className="decision-head" data-tone={tone}>
      <span className="decision-icon" aria-hidden>
        <Icon name={icon ?? TONE_ICON[tone]} size={20} />
      </span>
      <h2 id={id} className="decision-title">{children}</h2>
    </div>
  );
}

/**
 * The mono well for what the user must compare: a fingerprint, an address or a version. Selectable,
 * wraps on any character, never truncated.
 */
export function FingerprintWell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="fp-well">
      <span className="fp-well-label">{label}</span>
      <div className="fp-well-value mono select-text">{children}</div>
    </div>
  );
}

/** Footer row of a decision: the safe action first (it holds the initial focus), the risky one last. */
export function DecisionActions({ children }: { children: ReactNode }) {
  return <div className="decision-actions">{children}</div>;
}

/**
 * The in-session trust dialog shell (host key, certificate, RD Gateway certificate). It never
 * decides on its own:
 *  - focus starts on `safeRef` (Reject), never on a trust button, and moves there again for each
 *    new question (`focusKey`);
 *  - Escape always calls `onReject`;
 *  - Tab stays inside the dialog.
 * What a button answers is up to the caller; this shell changes no trust decision.
 */
export function TrustDialog({ headingId, bodyId, tone, title, icon, safeRef, focusKey, onReject, width = 520, className, children }: {
  headingId: string;
  bodyId: string;
  tone: DecisionTone;
  title: ReactNode;
  icon?: IconName;
  safeRef: RefObject<HTMLElement | null>;
  focusKey: unknown;
  onReject: () => void;
  width?: number;
  className?: string;
  children: ReactNode;
}) {
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    (safeRef.current ?? boxRef.current)?.focus();
  }, [focusKey, safeRef]);

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation();
      onReject();
      return;
    }
    if (e.key !== "Tab" || !boxRef.current) return;
    const items = [...boxRef.current.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled)")];
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
  }

  return (
    <div className="absolute inset-0 z-20 grid place-items-center overflow-y-auto py-4" style={{ background: "var(--scrim)" }}>
      <div
        ref={boxRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={headingId}
        aria-describedby={bodyId}
        tabIndex={-1}
        className={`decision-dialog${className ? ` ${className}` : ""}`}
        data-tone={tone}
        style={{ width, maxWidth: "calc(100% - 32px)" }}
        onKeyDown={onKeyDown}
      >
        <DecisionHeader id={headingId} tone={tone} icon={icon}>{title}</DecisionHeader>
        {children}
      </div>
    </div>
  );
}

/**
 * A confirmation modal in the same pattern (expose a forward, install an update): the decision
 * header, the mono well with what is at stake, a sentence, then Cancel (focused first) and the
 * action. Escape and the scrim cancel. It keeps role "dialog" with the title as its name.
 */
export function ConfirmDialog({ title, tone, well, confirmLabel, danger = false, busy = false, onConfirm, onCancel, width = 460, children }: {
  title: string;
  tone: DecisionTone;
  well?: { label: string; value: ReactNode };
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  width?: number;
  children: ReactNode;
}) {
  return (
    <Modal title={title} onClose={onCancel} width={width} tone={tone}>
      <div className="decision-body">
        {well && <FingerprintWell label={well.label}>{well.value}</FingerprintWell>}
        {children}
      </div>
      <DecisionActions>
        <button type="button" className="btn" onClick={onCancel}>Cancel</button>
        <button type="button" className={danger ? "btn btn-danger-solid" : "btn btn-primary"} disabled={busy} onClick={onConfirm}>
          {confirmLabel}
        </button>
      </DecisionActions>
    </Modal>
  );
}

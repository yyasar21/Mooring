import { useEffect, useRef, useState } from "react";
import type { VmAction, VmPowerState } from "../../lib/ipc";
import { ACTIONS, actionFit } from "./vsphere";

/**
 * The power menu of a VM row (ADR-0015 §3, owner decision 6). It only *requests*: Rust opens the
 * native confirmation naming the VM and the vCenter, so no second confirm is shown here.
 * `blocked` (opt-in off) keeps the trigger disabled and says why.
 */
export function PowerMenu({ state, blocked, busy, onAction }: { state: VmPowerState | null; blocked: string | null; busy: boolean; onAction: (a: VmAction) => void }) {
  const [open, setOpen] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (open) menu.current?.querySelector<HTMLElement>("[role='menuitem']:not([aria-disabled])")?.focus();
  }, [open]);

  const choose = (a: VmAction) => {
    setOpen(false);
    trigger.current?.focus();
    onAction(a);
  };

  return (
    <div className="relative">
      <button
        ref={trigger}
        type="button"
        className="btn"
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={busy || blocked !== null}
        title={blocked ?? "Each action is confirmed in a system dialog with three buttons (Cancel, the action, Not now); only a click on the action confirms"}
        onClick={() => { setOpen(!open); }}
      >
        Power
        <svg width="9" height="9" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
          <path d="M2 4l3 3 3-3" />
        </svg>
      </button>
      {open && (
        <div
          ref={menu}
          role="menu"
          aria-label="Power actions"
          className="copy-menu pop m-hud vs-power-menu"
          onKeyDown={(e) => {
            const els = [...(menu.current?.querySelectorAll<HTMLElement>("[role='menuitem']:not([aria-disabled])") ?? [])];
            const i = els.indexOf(document.activeElement as HTMLElement);
            if (e.key === "ArrowDown" || e.key === "ArrowUp") {
              e.preventDefault();
              els[(i + (e.key === "ArrowDown" ? 1 : -1) + els.length) % els.length]?.focus();
            } else if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              setOpen(false);
              trigger.current?.focus();
            }
          }}
          onBlur={(e) => { if (!menu.current?.contains(e.relatedTarget)) setOpen(false); }}
        >
          {ACTIONS.map((a) => {
            const unfit = actionFit(a.action, state);
            return (
              <button
                key={a.action}
                type="button"
                role="menuitem"
                className="menu-item vs-menu-item"
                data-destructive={a.destructive || undefined}
                aria-disabled={unfit ? true : undefined}
                title={unfit ?? a.hint}
                onClick={() => { if (!unfit) choose(a.action); }}
              >
                <span>{a.label}</span>
                <span className="vs-menu-hint">{unfit ?? (a.destructive ? "may lose data" : a.guest ? "needs VMware Tools" : "")}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { CredentialMeta, CredentialRole, KindSchema, Protocol } from "../../lib/ipc";
import { accountSummary, credentialValidFor } from "../../lib/credentials";
import { openSettingsCard } from "../SyncBanner";
import { APPROLE_HINT } from "./kindMeta";
import { KindBadge } from "./fields";

export interface PickerOption {
  /** Credential id, or "" for the empty choice (inherit / same as primary / none). */
  value: string;
  label: string;
  detail: string;
  meta: CredentialMeta | null;
  disabledReason: string | null;
  group: string;
}

/** Build the options for one role on one protocol. Pure, so the matrix filtering is testable. */
export function pickerOptions(
  creds: CredentialMeta[],
  kinds: KindSchema[],
  protocol: Protocol,
  role: CredentialRole,
  emptyLabel: string,
  emptyDetail: string,
): PickerOption[] {
  const empty: PickerOption = { value: "", label: emptyLabel, detail: emptyDetail, meta: null, disabledReason: null, group: "" };
  const rows = [...creds]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((c): PickerOption => {
      const r = credentialValidFor(kinds, c, protocol, role);
      const askAtConnect = c.kind === "prompt";
      return {
        value: c.id,
        label: c.name,
        detail: accountSummary(c),
        meta: c,
        disabledReason: r.ok ? null : r.reason,
        group: !r.ok ? "Not usable here" : askAtConnect ? "Ask at connect" : "Stored",
      };
    });
  const order = ["Ask at connect", "Stored", "Not usable here"];
  rows.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group));
  return [empty, ...rows];
}

/**
 * Listbox for choosing a credential by reference. Incompatible credentials stay visible, disabled,
 * with the matrix reason underneath, so a user can see why their key is not offered for RDP.
 */
export function CredentialPicker({
  label,
  value,
  options,
  kinds,
  onChange,
  hint,
}: {
  label: string;
  value: string;
  options: PickerOption[];
  kinds: KindSchema[];
  onChange: (id: string) => void;
  hint?: string;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const button = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const current = options.find((o) => o.value === value) ?? options[0];
  const enabled = useMemo(() => options.map((o, i) => (o.disabledReason ? -1 : i)).filter((i) => i >= 0), [options]);

  useEffect(() => {
    if (!open) return;
    setActive(Math.max(0, options.findIndex((o) => o.value === value)));
    list.current?.focus();
  }, [open, options, value]);

  const step = (dir: 1 | -1) => {
    const pos = enabled.indexOf(active);
    const next = enabled[(pos + dir + enabled.length) % enabled.length];
    if (next !== undefined) setActive(next);
  };
  const choose = (i: number) => {
    const o = options[i];
    if (!o || o.disabledReason) return;
    onChange(o.value);
    setOpen(false);
    button.current?.focus();
  };

  let lastGroup = "";
  return (
    <div className="cred-picker relative min-w-0">
      <span className="field-label" id={`${id}-l`}>{label}</span>
      <button
        ref={button}
        type="button"
        className="field picker-btn"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-labelledby={`${id}-l ${id}-v`}
        onClick={() => { setOpen(!open); }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        {current?.meta ? <KindBadge kind={current.meta.kind} kinds={kinds} /> : <span className="kind-badge" data-empty>—</span>}
        <span id={`${id}-v`} className="min-w-0 flex-1 truncate text-left">
          {current?.label}
          {current?.detail && <span className="mono ml-2 text-text-faint">{current.detail}</span>}
        </span>
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
          <path d="M2 4l3 3 3-3" />
        </svg>
      </button>
      {hint && <p className="field-hint">{hint}</p>}
      {open && (
        <ul
          ref={list}
          role="listbox"
          tabIndex={-1}
          aria-label={label}
          aria-activedescendant={`${id}-o${active}`}
          className="picker-list pop m-hud"
          onBlur={(e) => {
            if (!e.currentTarget.parentElement?.contains(e.relatedTarget)) setOpen(false);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); step(1); }
            else if (e.key === "ArrowUp") { e.preventDefault(); step(-1); }
            else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(active); }
            // Tab reaches a hint's "Secret sources" link inside the list before it closes.
            else if (e.key === "Tab" && !e.shiftKey && e.target === e.currentTarget && e.currentTarget.querySelector(".picker-link")) return;
            else if (e.key === "Escape" || e.key === "Tab") {
              if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); }
              setOpen(false);
              button.current?.focus();
            }
          }}
        >
          {options.map((o, i) => {
            const head = o.group && o.group !== lastGroup ? o.group : null;
            lastGroup = o.group;
            return (
              <li key={o.value || "empty"} role="presentation">
                {head && <p className="picker-group m-micro" role="presentation">{head}</p>}
                <div
                  id={`${id}-o${i}`}
                  role="option"
                  aria-selected={o.value === value}
                  aria-disabled={o.disabledReason ? true : undefined}
                  data-active={i === active || undefined}
                  className="picker-opt"
                  onMouseDown={(e) => { e.preventDefault(); }}
                  onMouseEnter={() => { if (!o.disabledReason) setActive(i); }}
                  onClick={() => { choose(i); }}
                >
                  {o.meta ? <KindBadge kind={o.meta.kind} kinds={kinds} /> : <span className="kind-badge" data-empty>—</span>}
                  <span className="min-w-0 flex-1">
                    <span className="block truncate">{o.label}</span>
                    <span className={`block truncate text-[length:var(--fs-xs)] ${o.disabledReason ? "" : "mono text-text-faint"}`}>
                      {o.disabledReason ?? (o.detail || " ")}
                    </span>
                    {o.disabledReason && o.meta?.kind === "vault_approle" && (
                      <span className="picker-hint">
                        <span>{APPROLE_HINT}</span>
                        <button
                          type="button"
                          className="picker-link"
                          onKeyDown={(e) => {
                            e.stopPropagation();
                            if (e.key === "Escape") { setOpen(false); button.current?.focus(); }
                          }}
                          onClick={(e) => {
                            e.stopPropagation();
                            setOpen(false);
                            openSettingsCard("sources-title", { kind: "add-secret-source", credentialId: o.meta?.id ?? null });
                          }}
                        >
                          Open Secret sources
                        </button>
                      </span>
                    )}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

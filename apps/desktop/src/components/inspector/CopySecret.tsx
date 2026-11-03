import { useEffect, useRef, useState } from "react";
import type { CredentialMeta, KindSchema } from "../../lib/ipc";
import { OTP_SEED_SCHEMA, schemaFor } from "../../lib/credentials";
import { copyKey, useCredentials } from "../../stores/credentials";

/** Re-render every 250 ms while any deadline is pending, and drop expired ones. */
function useTicker(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const t = setInterval(() => {
      const n = Date.now();
      setNow(n);
      useCredentials.getState().expireCopies(n);
    }, 250);
    return () => { clearInterval(t); };
  }, [active]);
  return now;
}

/** Copyable secrets that are stored, labelled from the schema. */
export function copyableSecrets(meta: CredentialMeta, kinds: KindSchema[]): { name: string; label: string }[] {
  const schema = schemaFor(kinds, meta.kind);
  return (schema?.fields ?? [])
    .filter((f) => f.secret && f.copyable && meta.secretNames.includes(f.name))
    .map((f) => ({ name: f.name, label: f.label }));
}

/**
 * "Copy" menu: one entry per stored, copyable secret (`secretNames` ∩ schema `copyable`) plus
 * "Copy OTP code" when a seed is attached. Rust writes the clipboard and audits; the UI only
 * shows how long the copy lives. The OTP ring drains over the code's remaining validity.
 */
export function CopySecret({ meta, kinds }: { meta: CredentialMeta; kinds: KindSchema[] }) {
  const items = copyableSecrets(meta, kinds);
  const hasOtp = meta.secretNames.includes(OTP_SEED_SCHEMA.name);
  const copiedUntil = useCredentials((s) => s.copiedUntil);
  const otp = useCredentials((s) => s.otp[meta.id]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  const pending = items.some((i) => copiedUntil[copyKey(meta.id, i.name)] !== undefined) || otp !== undefined;
  const now = useTicker(pending);

  useEffect(() => {
    if (open) menu.current?.querySelector<HTMLElement>("[role='menuitem']")?.focus();
  }, [open]);

  if (items.length === 0 && !hasOtp) return null;

  const run = (fn: () => Promise<boolean>) => {
    setOpen(false);
    setBusy(true);
    trigger.current?.focus();
    void fn().finally(() => { setBusy(false); });
  };
  const store = useCredentials.getState();
  const latest = items
    .map((i) => ({ ...i, until: copiedUntil[copyKey(meta.id, i.name)] }))
    .filter((i): i is { name: string; label: string; until: number } => i.until !== undefined && i.until > now)
    .sort((a, b) => b.until - a.until)[0];

  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative">
        <button
          ref={trigger}
          type="button"
          className="btn"
          aria-haspopup="menu"
          aria-expanded={open}
          disabled={busy}
          onClick={() => { setOpen(!open); }}
        >
          Copy secret
          <svg width="9" height="9" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
            <path d="M2 4l3 3 3-3" />
          </svg>
        </button>
        {open && (
          <div
            ref={menu}
            role="menu"
            aria-label="Copy secret"
            className="copy-menu pop m-hud"
            onKeyDown={(e) => {
              const els = [...(menu.current?.querySelectorAll<HTMLElement>("[role='menuitem']") ?? [])];
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
            {items.map((i) => (
              <button key={i.name} type="button" role="menuitem" className="menu-item" onClick={() => { run(() => store.copySecret(meta.id, i.name)); }}>
                Copy {i.label.toLowerCase()}
              </button>
            ))}
            {hasOtp && (
              <button type="button" role="menuitem" className="menu-item" onClick={() => { run(() => store.copyOtp(meta.id)); }}>
                Copy OTP code
              </button>
            )}
          </div>
        )}
      </div>
      {hasOtp && (
        <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => { run(() => store.copyOtp(meta.id)); }}>
          Copy OTP code
        </button>
      )}
      {latest && <Countdown label={`${latest.label} copied`} left={latest.until - now} total={30_000} />}
      {otp && otp.validUntil > now && (
        <Countdown label="OTP code copied, valid" left={otp.validUntil - now} total={otp.periodMs} tone="otp" />
      )}
    </div>
  );
}

function Countdown({ label, left, total, tone }: { label: string; left: number; total: number; tone?: "otp" }) {
  const seconds = Math.ceil(left / 1000);
  const frac = Math.max(0, Math.min(1, left / total));
  if (seconds <= 0) return null;
  const aria = tone === "otp" ? `OTP code valid for ${seconds} more seconds` : `Clipboard clears in ${seconds} seconds`;
  return (
    <span className="countdown tnum" data-tone={tone} role="status" aria-live="polite" aria-label={aria} title={label}>
      <svg className="countdown-ring" viewBox="0 0 14 14" aria-hidden>
        <circle cx="7" cy="7" r="5.5" className="ring-track" />
        <circle cx="7" cy="7" r="5.5" className="ring-fill" pathLength={100} strokeDasharray={`${frac * 100} 100`} />
      </svg>
      {tone === "otp" ? `code ${seconds}s` : `clears in ${seconds}s`}
    </span>
  );
}

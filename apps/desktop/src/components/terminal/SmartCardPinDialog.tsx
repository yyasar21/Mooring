import { useEffect, useRef, useState } from "react";
import type { PendingPrompt } from "../../stores/sessions";
import { useSessions } from "../../stores/sessions";

/** The answer Rust reads as "cancel": the sign-in closes with `user` ("smart card PIN cancelled"). */
export const PIN_CANCEL = "";

/**
 * ADR-0027: the PIN of a smart card (`purpose: "smart_card_pin"`), asked when ssh-agent does not
 * hold the card's key yet. Rust hands it to the agent once (`ADD_SMARTCARD_KEY`) and never stores it.
 *
 * The PIN never enters React state: the input is uncontrolled, read once on submit, and emptied
 * before the answer is sent and again when the dialog goes away. Escape and Cancel send the empty
 * answer, which cancels the sign-in. Nothing here is logged.
 */
export function SmartCardPinDialog({ tabId, prompt, hop }: { tabId: string; prompt: PendingPrompt; hop: string | null }) {
  const answer = useSessions((s) => s.answer);
  const input = useRef<HTMLInputElement>(null);
  const [sent, setSent] = useState(false);
  const [empty, setEmpty] = useState(true);
  const headingId = `pin-h-${tabId}`;
  const bodyId = `pin-b-${tabId}`;

  useEffect(() => {
    setSent(false);
    setEmpty(true);
    const el = input.current;
    el?.focus();
    return () => { if (el) el.value = ""; };
  }, [prompt.id]);

  function send(pin: string) {
    if (sent) return;
    setSent(true);
    if (input.current) input.current.value = "";
    setEmpty(true);
    void answer(tabId, pin);
  }

  function submit() {
    const pin = input.current?.value ?? "";
    if (pin === "") return;
    send(pin);
  }

  return (
    <div className="absolute inset-0 z-20 grid place-items-center" style={{ background: "var(--scrim)" }}>
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={headingId}
        aria-describedby={bodyId}
        className="pop m-hud pin-dialog w-[440px] max-w-[calc(100%-32px)] p-5"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            send(PIN_CANCEL);
          }
        }}
      >
        <h2 id={headingId} className="m-display text-[length:var(--fs-l)]">
          {hop ? `Jump host ${hop}: smart card PIN` : "Smart card PIN"}
        </h2>
        <p id={bodyId} className="mt-2 text-[length:var(--fs-s)] text-text-muted select-text">
          {prompt.message || "Enter the PIN of the smart card."}
        </p>
        <form
          className="mt-4 space-y-3"
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div>
            <label className="field-label" htmlFor={`pin-${tabId}`}>PIN</label>
            <input
              ref={input}
              id={`pin-${tabId}`}
              type="password"
              inputMode="numeric"
              autoComplete="off"
              spellCheck={false}
              maxLength={64}
              data-secret
              className="field mono"
              disabled={sent}
              onChange={(e) => { setEmpty(e.target.value === ""); }}
            />
            <p className="field-hint">
              Mooring hands the PIN to your ssh-agent once to load the card and never stores it. Too many wrong PINs can lock the card.
            </p>
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn btn-ghost" disabled={sent} onClick={() => { send(PIN_CANCEL); }}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={sent || empty}>
              Unlock card
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

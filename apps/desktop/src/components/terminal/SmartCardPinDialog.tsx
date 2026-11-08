import { useCallback, useEffect, useRef, useState } from "react";
import type { PendingPrompt } from "../../stores/sessions";
import { useSessions } from "../../stores/sessions";
import { DecisionActions, FingerprintWell, TrustDialog } from "../dialogs/TrustDialog";
import { useSecretInput } from "../settings/useSecretInput";

/** The answer Rust reads as "cancel": the sign-in closes with `user` ("smart card PIN cancelled"). */
export const PIN_CANCEL = "";

/** L-49: Rust loads the card with an ssh-agent lifetime constraint (`CARD_LIFETIME_SECS` = 3600). */
export const CARD_LIFETIME_MINUTES = 60;

/**
 * ADR-0027: the PIN of a smart card (`purpose: "smart_card_pin"`), asked when ssh-agent does not
 * hold the card's key yet, on the M8 decision shell. Rust hands it to the agent once
 * (`ADD_SMARTCARD_KEY`) and never stores it.
 *
 * The PIN never enters React state: the input is uncontrolled (`useSecretInput`), read once on
 * submit, and emptied before the answer is sent and again when the dialog goes away. Escape and
 * Cancel send the empty answer, which cancels the sign-in. Focus starts on the PIN. Nothing here
 * is logged.
 */
export function SmartCardPinDialog({ tabId, prompt, hop }: { tabId: string; prompt: PendingPrompt; hop: string | null }) {
  const answer = useSessions((s) => s.answer);
  const pin = useSecretInput();
  const input = useRef<HTMLInputElement | null>(null);
  const [sent, setSent] = useState(false);
  const headingId = `pin-h-${tabId}`;
  const bodyId = `pin-b-${tabId}`;
  const pinRef = pin.ref;
  const clear = pin.clear;
  // Stable: a new callback each render would detach the field and empty it.
  const setInput = useCallback((el: HTMLInputElement | null) => {
    input.current = el;
    pinRef(el);
  }, [pinRef]);

  useEffect(() => {
    setSent(false);
    clear();
  }, [prompt.id, clear]);

  function send(value: string) {
    if (sent) return;
    setSent(true);
    clear();
    void answer(tabId, value);
  }

  function submit() {
    if (pin.empty) return;
    send(pin.take());
  }

  return (
    <TrustDialog
      headingId={headingId}
      bodyId={bodyId}
      tone="info"
      icon="key"
      title={hop ? `Jump host ${hop}: smart card PIN` : "Smart card PIN"}
      safeRef={input}
      focusKey={prompt.id}
      onReject={() => { send(PIN_CANCEL); }}
      width={460}
      className="pin-dialog"
    >
      <FingerprintWell label="The card asks">
        <span id={bodyId} className="whitespace-pre-wrap">{prompt.message || "Enter the PIN of the smart card."}</span>
      </FingerprintWell>
      <form
        className="flex flex-col gap-3"
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div>
          <label className="field-label" htmlFor={`pin-${tabId}`}>PIN</label>
          <input
            ref={setInput}
            id={`pin-${tabId}`}
            type="password"
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            maxLength={64}
            data-secret
            className="field mono"
            disabled={sent}
            onChange={pin.onChange}
          />
          <p className="field-hint">
            Mooring hands the PIN to your ssh-agent once to load the card and never stores it. Too many wrong PINs can lock the card.
          </p>
          <p className="field-hint" data-testid="pin-lifetime">
            The card then stays loaded in ssh-agent for {CARD_LIFETIME_MINUTES} minutes, so a reconnect in that time does not ask
            again. After that the agent forgets it and Mooring asks for the PIN on the next sign-in.
          </p>
        </div>
        <DecisionActions>
          <button type="button" className="btn" disabled={sent} onClick={() => { send(PIN_CANCEL); }}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={sent || pin.empty}>
            Unlock card
          </button>
        </DecisionActions>
      </form>
    </TrustDialog>
  );
}

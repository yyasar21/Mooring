import { useCallback, useRef } from "react";
import type { PendingPrompt } from "../../stores/sessions";
import { useSessions } from "../../stores/sessions";
import { CredentialPrompt } from "./CredentialPrompt";
import { CertificateTrustDialog } from "../remote/CertificateTrustDialog";
import { SmartCardPinDialog } from "./SmartCardPinDialog";
import { useTree } from "../../stores/tree";
import { hopName } from "./HopStrip";
import { DecisionActions, FingerprintWell, TrustDialog } from "../dialogs/TrustDialog";
import { useSecretInput } from "../settings/useSecretInput";

/** ADR-0025: the jump host a hop-tagged prompt comes from, by name (null = the target asks). */
function useHopName(tabId: string, prompt: PendingPrompt): string | null {
  const connectionId = useSessions((s) => s.tabs.find((t) => t.id === tabId)?.connectionId);
  const hops = useSessions((s) => s.tabs.find((t) => t.id === tabId)?.hops);
  const connections = useTree((s) => s.connections);
  const hop = prompt.hop;
  if (hop === null || hop === undefined) return null;
  const target = connections.find((c) => c.id === connectionId);
  return hopName(connections, target, hop, hops?.[hop]?.host ?? "");
}

/**
 * Inline modal over the terminal for a session `Prompt` (TOFU host key, keyboard-interactive).
 * Trust questions get Trust / Reject buttons; `credential` prompts (ADR-0009 `prompt` kind) get
 * the sign-in form; other prompts get a text field (hidden when `secret`).
 * The dialog is chosen by the typed `purpose` from Rust, never by the server-controlled text.
 * The typed answer lives only in the field (never in React state) and is cleared when it is sent.
 * M8: focus starts on Reject (trust) or the answer field, never on a trust button.
 */
export function PromptModal({ tabId, prompt, host }: { tabId: string; prompt: PendingPrompt; host: string }) {
  const hop = useHopName(tabId, prompt);
  if (prompt.purpose === "credential") return <CredentialPrompt tabId={tabId} prompt={prompt} host={host} hop={hop} />;
  if ((prompt.purpose === "certificate_trust" || prompt.purpose === "gateway_certificate_trust") && !prompt.secret) {
    return <CertificateTrustDialog tabId={tabId} prompt={prompt} />;
  }
  if (prompt.purpose === "smart_card_pin") return <SmartCardPinDialog tabId={tabId} prompt={prompt} hop={hop} />;
  return <AnswerPrompt tabId={tabId} prompt={prompt} host={host} hop={hop} />;
}

function AnswerPrompt({ tabId, prompt, host, hop }: { tabId: string; prompt: PendingPrompt; host: string; hop: string | null }) {
  const answer = useSessions((s) => s.answer);
  // The typed answer (often a one-time code or a password) stays in the DOM field, not in state.
  const field = useSecretInput();
  const rejectRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const fieldRef = field.ref;
  // Stable on purpose: a new callback each render would detach the field and empty it.
  const setInput = useCallback((el: HTMLInputElement | null) => {
    inputRef.current = el;
    fieldRef(el);
  }, [fieldRef]);
  const isTrust = prompt.purpose === "host_key_trust" && !prompt.secret;
  const headingId = `prompt-h-${tabId}`;
  const bodyId = `prompt-b-${tabId}`;

  function send(value: string) {
    field.clear();
    void answer(tabId, value);
  }

  if (isTrust) {
    return (
      <TrustDialog
        headingId={headingId}
        bodyId={bodyId}
        tone="warning"
        title={hop ? `Jump host ${hop}: verify host identity` : "Verify host identity"}
        safeRef={rejectRef}
        focusKey={prompt.id}
        onReject={() => { send("no"); }}
      >
        <p id={bodyId} className="decision-text">
          Mooring has no stored host key for this server. Compare the fingerprint with one you got from the server owner. Trusting
          records it in the audit log.
        </p>
        <FingerprintWell label="Host key">
          <span className="whitespace-pre-wrap">{prompt.message}</span>
        </FingerprintWell>
        <DecisionActions>
          <button ref={rejectRef} type="button" className="btn" onClick={() => { send("no"); }}>
            Reject and disconnect
          </button>
          <button type="button" className="btn btn-primary" onClick={() => { send("yes"); }}>
            Trust and connect
          </button>
        </DecisionActions>
      </TrustDialog>
    );
  }

  return (
    <TrustDialog
      headingId={headingId}
      bodyId={bodyId}
      tone="info"
      icon="info"
      title={hop ? `Jump host ${hop} asks` : `${host} asks`}
      safeRef={inputRef}
      focusKey={prompt.id}
      onReject={() => { send(""); }}
    >
      <FingerprintWell label="Message from the server">
        <span id={bodyId} className="whitespace-pre-wrap">{prompt.message}</span>
      </FingerprintWell>
      <form
        className="decision-form"
        onSubmit={(e) => {
          e.preventDefault();
          send(field.take());
        }}
      >
        <input
          ref={setInput}
          aria-label="Answer"
          type={prompt.secret ? "password" : "text"}
          autoComplete="off"
          spellCheck={false}
          className="field mono flex-1"
          onChange={field.onChange}
        />
        <button type="submit" className="btn btn-primary">
          Send
        </button>
      </form>
    </TrustDialog>
  );
}

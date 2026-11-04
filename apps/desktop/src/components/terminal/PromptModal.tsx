import { useEffect, useRef, useState } from "react";
import type { PendingPrompt } from "../../stores/sessions";
import { useSessions } from "../../stores/sessions";
import { CredentialPrompt } from "./CredentialPrompt";
import { CertificateTrustDialog } from "../remote/CertificateTrustDialog";

/**
 * Inline modal over the terminal for a session `Prompt` (TOFU host key, keyboard-interactive).
 * Trust questions get Trust / Reject buttons; `credential` prompts (ADR-0009 `prompt` kind) get
 * the sign-in form; other prompts get a text field (hidden when `secret`).
 * The dialog is chosen by the typed `purpose` from Rust, never by the server-controlled text.
 * The typed answer lives only in this component and is cleared as soon as it is sent.
 */
export function PromptModal({ tabId, prompt, host }: { tabId: string; prompt: PendingPrompt; host: string }) {
  if (prompt.purpose === "credential") return <CredentialPrompt tabId={tabId} prompt={prompt} host={host} />;
  if (prompt.purpose === "certificate_trust" && !prompt.secret) return <CertificateTrustDialog tabId={tabId} prompt={prompt} />;
  return <AnswerPrompt tabId={tabId} prompt={prompt} host={host} />;
}

function AnswerPrompt({ tabId, prompt, host }: { tabId: string; prompt: PendingPrompt; host: string }) {
  const answer = useSessions((s) => s.answer);
  const [text, setText] = useState("");
  const firstRef = useRef<HTMLInputElement & HTMLButtonElement>(null);
  const isTrust = prompt.purpose === "host_key_trust" && !prompt.secret;
  const headingId = `prompt-h-${tabId}`;
  const bodyId = `prompt-b-${tabId}`;

  useEffect(() => {
    firstRef.current?.focus();
  }, [prompt.id]);

  function send(value: string) {
    setText("");
    void answer(tabId, value);
  }

  return (
    <div className="absolute inset-0 z-20 grid place-items-center" style={{ background: "var(--scrim)" }}>
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={headingId}
        aria-describedby={bodyId}
        className="pop m-hud w-[480px] max-w-[calc(100%-32px)] p-5"
        data-tone="hot"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            send(isTrust ? "no" : "");
          }
        }}
      >
        <p aria-hidden className="m-micro mb-2" style={{ color: "var(--hot)" }}>
          {isTrust ? "Unknown host key" : "Remote prompt"}
        </p>
        <h2 id={headingId} className="m-display flex items-center gap-2.5 text-[length:var(--fs-l)]">
          <span aria-hidden className="tab-attn" />
          {isTrust ? "Verify host identity" : `${host} asks`}
        </h2>
        <p id={bodyId} className="mono mt-3 whitespace-pre-wrap border-l-2 border-[var(--hot-line)] bg-bg-sunken p-3 text-text select-text">
          {prompt.message}
        </p>
        {isTrust ? (
          <>
            <p className="mt-3 text-[length:var(--fs-s)] text-text-muted">
              Compare the fingerprint with one you got from the server owner. Trusting records it in the audit log.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" className="btn btn-ghost" onClick={() => { send("no"); }}>
                Reject and disconnect
              </button>
              <button ref={firstRef} type="button" className="btn btn-primary" onClick={() => { send("yes"); }}>
                Trust and connect
              </button>
            </div>
          </>
        ) : (
          <form
            className="mt-4 flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              send(text);
            }}
          >
            <input
              ref={firstRef}
              aria-label="Answer"
              type={prompt.secret ? "password" : "text"}
              autoComplete="off"
              spellCheck={false}
              className="field mono flex-1"
              value={text}
              onChange={(e) => { setText(e.target.value); }}
            />
            <button type="submit" className="btn btn-primary">
              Send
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

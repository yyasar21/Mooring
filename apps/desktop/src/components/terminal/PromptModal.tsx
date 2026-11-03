import { useEffect, useRef, useState } from "react";
import type { PendingPrompt } from "../../stores/sessions";
import { useSessions } from "../../stores/sessions";

/**
 * Inline modal over the terminal for a session `Prompt` (TOFU host key, keyboard-interactive).
 * Trust questions get Trust / Reject buttons; other prompts get a text field (hidden when `secret`).
 * The typed answer lives only in this component and is cleared as soon as it is sent.
 */
export function PromptModal({ tabId, prompt, host }: { tabId: string; prompt: PendingPrompt; host: string }) {
  const answer = useSessions((s) => s.answer);
  const [text, setText] = useState("");
  const firstRef = useRef<HTMLInputElement & HTMLButtonElement>(null);
  const isTrust = /trust|authenticity|fingerprint/i.test(prompt.message) && !prompt.secret;
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
        className="pop w-[460px] max-w-[calc(100%-32px)] p-4"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            send(isTrust ? "no" : "");
          }
        }}
      >
        <h2 id={headingId} className="flex items-center gap-2 text-[length:var(--fs-l)] font-medium">
          <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: "var(--warn)" }} />
          {isTrust ? "Verify host identity" : `${host} asks`}
        </h2>
        <p id={bodyId} className="mono mt-3 whitespace-pre-wrap rounded-[var(--radius-s)] bg-bg-sunken p-3 text-text select-text">
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

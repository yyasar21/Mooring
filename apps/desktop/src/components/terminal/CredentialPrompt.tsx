import { useCallback, useRef, useState } from "react";
import type { PendingPrompt } from "../../stores/sessions";
import { useSessions } from "../../stores/sessions";
import { isAccountError, parseAccount } from "../../lib/credentials";
import { DecisionActions, TrustDialog } from "../dialogs/TrustDialog";
import { useSecretInput } from "../settings/useSecretInput";

/**
 * Connect-time sign-in for a `prompt` credential (`purpose: "credential"`), on the M8 decision
 * shell. Username and domain are pre-filled from the credential and the connection's overrides.
 * Typing `CORP\alice` or `alice@corp.example` in the username splits it. The password field is
 * uncontrolled (`useSecretInput`): React holds only whether it is empty; it is read once on
 * submit, emptied, emptied again when the dialog goes away, and handed to Rust as
 * `SessionInput::CredentialAnswer`. Focus starts on the password when the username is known;
 * Escape and Cancel send the empty answer.
 */
export function CredentialPrompt({ tabId, prompt, host, hop = null }: { tabId: string; prompt: PendingPrompt; host: string; hop?: string | null }) {
  const answer = useSessions((s) => s.answerCredential);
  const a = prompt.account;
  const [user, setUser] = useState(a?.username ?? "");
  const [domain, setDomain] = useState(a?.domain ?? "");
  const [tried, setTried] = useState(false);
  const pw = useSecretInput();
  const start = useRef<HTMLInputElement | null>(null);
  const headingId = `cred-prompt-h-${tabId}`;
  const bodyId = `cred-prompt-b-${tabId}`;
  const askDomain = a?.needsDomain === true || domain !== "";
  const startOnPassword = Boolean(a?.username);
  const pwRef = pw.ref;
  // Stable callback refs (a new one per render would detach the field and empty it).
  const setPw = useCallback((el: HTMLInputElement | null) => {
    pwRef(el);
    if (startOnPassword && el) start.current = el;
  }, [pwRef, startOnPassword]);
  const setUserEl = useCallback((el: HTMLInputElement | null) => {
    if (!startOnPassword && el) start.current = el;
  }, [startOnPassword]);

  // A typed DOMAIN\user or user@domain fills the domain (UPN keeps the whole account as user).
  const parsed = user.includes("\\") ? parseAccount(user) : null;
  const split = parsed && !isAccountError(parsed) ? parsed : null;

  function submit() {
    const username = split ? split.user : user.trim();
    setTried(!username || pw.empty);
    if (!username || pw.empty) return;
    const password = pw.take();
    void answer(tabId, { username, domain: split ? split.domain : domain.trim() || null, password });
  }

  function cancel() {
    pw.clear();
    void answer(tabId, { username: "", domain: null, password: "" });
  }

  return (
    <TrustDialog
      headingId={headingId}
      bodyId={bodyId}
      tone="info"
      icon="key"
      title={hop ? `Jump host ${hop}: sign in` : `Sign in to ${host}`}
      safeRef={start}
      focusKey={prompt.id}
      onReject={cancel}
      width={460}
    >
      <p id={bodyId} className="decision-text">
        This connection stores no password. What you type is used for this session only and is not saved.
      </p>
      <form
        className="flex flex-col gap-3"
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="grid gap-3" style={{ gridTemplateColumns: askDomain && !split ? "1fr 1fr" : "1fr" }}>
          <div>
            <label className="field-label" htmlFor={`${headingId}-u`}>Username</label>
            <input
              ref={setUserEl}
              id={`${headingId}-u`}
              className="field mono"
              spellCheck={false}
              autoComplete="off"
              value={user}
              aria-invalid={tried && !user.trim() ? true : undefined}
              onChange={(e) => { setUser(e.target.value); }}
            />
            {split && <p className="field-hint">User <span className="mono text-text">{split.user}</span> in domain <span className="mono text-text">{split.domain}</span></p>}
          </div>
          {askDomain && !split && (
            <div>
              <label className="field-label" htmlFor={`${headingId}-d`}>Domain</label>
              <input id={`${headingId}-d`} className="field mono" spellCheck={false} autoComplete="off" value={domain} onChange={(e) => { setDomain(e.target.value); }} />
            </div>
          )}
        </div>
        <div>
          <label className="field-label" htmlFor={`${headingId}-p`}>Password</label>
          <input
            ref={setPw}
            id={`${headingId}-p`}
            type="password"
            className="field mono"
            autoComplete="off"
            spellCheck={false}
            data-secret
            aria-invalid={tried && pw.empty ? true : undefined}
            onChange={pw.onChange}
          />
        </div>
        {tried && (!user.trim() || pw.empty) && <p role="alert" className="field-error">Enter a username and a password.</p>}
        <DecisionActions>
          <button type="button" className="btn" onClick={cancel}>Cancel and disconnect</button>
          <button type="submit" className="btn btn-primary">Sign in</button>
        </DecisionActions>
      </form>
    </TrustDialog>
  );
}

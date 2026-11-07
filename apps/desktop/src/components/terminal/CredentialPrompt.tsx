import { useEffect, useRef, useState } from "react";
import type { PendingPrompt } from "../../stores/sessions";
import { useSessions } from "../../stores/sessions";
import { isAccountError, parseAccount } from "../../lib/credentials";

/**
 * Connect-time sign-in for a `prompt` credential (`purpose: "credential"`). Username and domain
 * are pre-filled from the credential and the connection's overrides. Typing `CORP\alice` or
 * `alice@corp.example` in the username splits it. The password input is uncontrolled: it is read
 * once on submit, cleared, and handed to Rust as `SessionInput::CredentialAnswer`.
 */
export function CredentialPrompt({ tabId, prompt, host, hop = null }: { tabId: string; prompt: PendingPrompt; host: string; hop?: string | null }) {
  const answer = useSessions((s) => s.answerCredential);
  const a = prompt.account;
  const [user, setUser] = useState(a?.username ?? "");
  const [domain, setDomain] = useState(a?.domain ?? "");
  const [tried, setTried] = useState(false);
  const pw = useRef<HTMLInputElement>(null);
  const userRef = useRef<HTMLInputElement>(null);
  const headingId = `cred-prompt-h-${tabId}`;
  const askDomain = a?.needsDomain === true || domain !== "";

  // A typed DOMAIN\user or user@domain fills the domain (UPN keeps the whole account as user).
  const parsed = user.includes("\\") ? parseAccount(user) : null;
  const split = parsed && !isAccountError(parsed) ? parsed : null;

  useEffect(() => {
    (user ? pw.current : userRef.current)?.focus();
    // focus once per prompt
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prompt.id]);

  function submit() {
    setTried(true);
    const password = pw.current?.value ?? "";
    const username = split ? split.user : user.trim();
    if (!username || !password) return;
    if (pw.current) pw.current.value = "";
    void answer(tabId, { username, domain: split ? split.domain : domain.trim() || null, password });
  }

  function cancel() {
    if (pw.current) pw.current.value = "";
    void answer(tabId, { username: "", domain: null, password: "" });
  }

  return (
    <div className="absolute inset-0 z-20 grid place-items-center" style={{ background: "var(--scrim)" }}>
      <form
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={headingId}
        className="pop m-hud w-[440px] max-w-[calc(100%-32px)] p-5"
        data-tone="hot"
        autoComplete="off"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            cancel();
          }
        }}
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <p aria-hidden className="m-micro mb-2" style={{ color: "var(--hot)" }}>Ask at connect</p>
        <h2 id={headingId} className="m-display flex items-center gap-2.5 text-[length:var(--fs-l)]">
          <span aria-hidden className="tab-attn" />
          {hop ? `Jump host ${hop}: sign in` : `Sign in to ${host}`}
        </h2>
        <p className="mt-2 text-[length:var(--fs-s)] text-text-muted">
          This connection stores no password. What you type is used for this session only and is not saved.
        </p>
        <div className="mt-4 grid gap-3" style={{ gridTemplateColumns: askDomain && !split ? "1fr 1fr" : "1fr" }}>
          <div>
            <label className="field-label" htmlFor={`${headingId}-u`}>Username</label>
            <input
              ref={userRef}
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
        <div className="mt-3">
          <label className="field-label" htmlFor={`${headingId}-p`}>Password</label>
          <input ref={pw} id={`${headingId}-p`} type="password" className="field mono" autoComplete="off" spellCheck={false} />
        </div>
        {tried && <p role="alert" className="mt-2 text-[length:var(--fs-s)] text-hot">Enter a username and a password.</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="btn btn-ghost" onClick={cancel}>Cancel and disconnect</button>
          <button type="submit" className="btn btn-primary">Sign in</button>
        </div>
      </form>
    </div>
  );
}

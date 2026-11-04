import { useState } from "react";
import { OPTION_LIMITS, type WebConnOptions } from "../../../lib/ipc";
import { checkUrl, originOf, type OptionErrors } from "../../../lib/validate.options";
import { Toggle } from "../../settings/Toggle";
import { ReadOnly, Warn } from "./controls";

/** `WebConnOptions` (ADR-0013): start URL, extra origins, storage opt-in, http opt-in. */
export function WebOptions({ value, errors, onChange }: { value: WebConnOptions; errors: OptionErrors; onChange: (v: WebConnOptions) => void }) {
  const set = (p: Partial<WebConnOptions>) => { onChange({ ...value, ...p }); };
  const [draft, setDraft] = useState("");
  const [draftError, setDraftError] = useState<string | null>(null);
  const full = value.allowedOrigins.length >= OPTION_LIMITS.maxAllowedOrigins;
  const own = value.url && !errors.url ? originOf(value.url) : null;

  function add() {
    const o = draft.trim().replace(/\/$/, "");
    const bad = o === "" ? "Type an origin such as https://sso.example.test." : checkUrl(o, value.allowHttp, true);
    if (bad) {
      setDraftError(bad);
      return;
    }
    const norm = originOf(o) ?? o;
    if (norm === own || value.allowedOrigins.some((x) => (originOf(x) ?? x) === norm)) {
      setDraftError("That origin is already allowed.");
      return;
    }
    set({ allowedOrigins: [...value.allowedOrigins, o] });
    setDraft("");
    setDraftError(null);
  }

  return (
    <div className="opt-grid">
      <div>
        <label className="field-label" htmlFor="web-url">Start URL</label>
        <input
          id="web-url"
          className="field mono"
          spellCheck={false}
          placeholder="https://console.example.test/"
          aria-invalid={errors.url ? true : undefined}
          aria-describedby="web-url-hint"
          value={value.url}
          onChange={(e) => { set({ url: e.target.value }); }}
        />
        <p id="web-url-hint" className={errors.url ? "field-hint field-problem" : "field-hint"} role={errors.url ? "alert" : undefined}>
          {errors.url ?? "https:// only, no user name or password in the address."}
        </p>
      </div>

      <div className="opt-danger" data-on={value.allowHttp || undefined}>
        <Toggle checked={value.allowHttp} onChange={(allowHttp) => { set({ allowHttp }); }} label="Allow http://" hint="For appliances without TLS. Recorded in the audit log." />
        {value.allowHttp && <Warn>Pages loaded over http:// can be read and changed by anyone on the network path, including what you type.</Warn>}
      </div>

      <fieldset className="opt-origins">
        <legend className="field-label">Also allowed origins ({value.allowedOrigins.length}/{OPTION_LIMITS.maxAllowedOrigins})</legend>
        <p className="field-hint">
          The window navigates only to {own ? <span className="mono">{own}</span> : "the start URL's origin"} and the origins listed here, for
          example a single sign-on page. Exact origins, no paths or wildcards.
        </p>
        {value.allowedOrigins.length > 0 && (
          <ul className="opt-origin-list" aria-label="Allowed origins">
            {value.allowedOrigins.map((o) => (
              <li key={o}>
                <span className="mono select-text">{o}</span>
                <button
                  type="button"
                  className="btn btn-ghost btn-danger"
                  aria-label={`Remove ${o}`}
                  onClick={() => { set({ allowedOrigins: value.allowedOrigins.filter((x) => x !== o) }); }}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}
        <div className="flex gap-2">
          <input
            aria-label="New origin"
            className="field mono flex-1"
            spellCheck={false}
            placeholder="https://sso.example.test"
            disabled={full}
            aria-invalid={draftError ? true : undefined}
            value={draft}
            onChange={(e) => { setDraft(e.target.value); setDraftError(null); }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add();
              }
            }}
          />
          <button type="button" className="btn" disabled={full} onClick={add}>Add origin</button>
        </div>
        {(draftError ?? errors.allowedOrigins) && (
          <p className="field-hint field-problem" role="alert">{draftError ?? errors.allowedOrigins}</p>
        )}
      </fieldset>

      <div className="opt-danger" data-on={value.persistent || undefined}>
        <Toggle
          checked={value.persistent}
          onChange={(persistent) => { set({ persistent }); }}
          label="Keep me signed in (persistent storage)"
          hint="Off by default: the window is private and forgets the sign-in when it closes."
        />
        {value.persistent && (
          <Warn>
            Cookies and site data for this connection are kept on disk, unencrypted, outside the vault. Anyone with access to your user
            account can reuse the sign-in. Opening the window with persistent storage is recorded in the audit log; “Clear site data” and
            deleting the connection wipe it. Not available on macOS 11 to 13, where the window stays private.
          </Warn>
        )}
      </div>
      <ReadOnly label="Window">Opens in its own window, isolated from Mooring.</ReadOnly>
    </div>
  );
}

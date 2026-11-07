import { useState } from "react";
import { ipc, SECRET_AUTH_CREDENTIAL, SOURCE_KIND_LABEL, SOURCE_LOGIN_KIND, type SecretAuthMethod, type SecretSource, type SecretSourceInput, type SecretSourceKind } from "../../lib/ipc";
import { checkUrl } from "../../lib/validate.options";
import { validateSecretSource } from "../../lib/validate.secrets";
import { describeError } from "../../stores/errors";
import { DialogFooter, Modal } from "../dialogs/Modal";
import { CaPemField, Seg, Warn } from "../dialogs/options/controls";
import { KindCredentialSelect } from "./KindCredentialSelect";
import { Toggle } from "./Toggle";
import { BwsPathField, KIND_HINT } from "./SourceProviderFields";

const KINDS: { value: SecretSourceKind; label: string }[] = [
  { value: "vault", label: "Vault / OpenBao" },
  { value: "onepassword", label: "1Password Connect" },
  { value: "bitwarden", label: "Bitwarden" },
];

const ADDRESS: Record<SecretSourceKind, { placeholder: string; hint: string }> = {
  vault: { placeholder: "https://vault.example.test:8200", hint: "Vault or OpenBao, https:// only. The certificate is pinned on first use or checked against the CA below." },
  onepassword: { placeholder: "https://connect.example.test:8080", hint: "Your 1Password Connect server, https:// only. The certificate is pinned on first use or checked against the CA below." },
  bitwarden: { placeholder: "https://bitwarden.example.test", hint: "The self-hosted Bitwarden server. Mooring passes it to bws as BWS_SERVER_URL." },
};

const METHODS: { value: SecretAuthMethod; label: string }[] = [
  { value: "token", label: "Token" },
  { value: "approle", label: "AppRole" },
  { value: "oidc", label: "OIDC" },
];

const METHOD_HINT: Record<SecretAuthMethod, string> = {
  token: "A Vault token you already hold, stored as an API token credential. Tokens with the root policy are refused.",
  approle: "Mooring logs in with a role id and secret id (both sealed in the vault) and revokes its token on lock.",
  oidc: "Mooring opens an isolated sign-in window for your identity provider. Nothing is stored; you sign in again after each lock.",
};

export const OIDC_REDIRECT_URI = "http://localhost:8250/oidc/callback";

const BLANK: SecretSourceInput = {
  kind: "vault", name: "", address: "", namespace: null, authMethod: "approle", authMount: "", credentialId: null, oidcRole: null,
  options: { caPem: null, allowHttp: false, allowedOrigins: [] },
};

/** A fresh form of one kind: 1Password and Bitwarden sign in with a token only (ADR-0026). */
function blank(kind: SecretSourceKind, credentialId: string | null): SecretSourceInput {
  if (kind === "vault") return { ...BLANK, credentialId };
  return {
    ...BLANK, kind, authMethod: "token", credentialId,
    options: { caPem: null, allowHttp: false, allowedOrigins: [], ...(kind === "bitwarden" ? { bwsPath: null } : {}) },
  };
}

function toInput(s: SecretSource): SecretSourceInput {
  const options = structuredClone(s.options);
  if (s.kind !== "bitwarden") delete options.bwsPath;
  else options.bwsPath ??= null;
  return { kind: s.kind, name: s.name, address: s.address, namespace: s.namespace, authMethod: s.authMethod, authMount: s.authMount, credentialId: s.credentialId, oidcRole: s.oidcRole, options };
}

/** Create or edit one ADR-0016 secret source. Login material is a credential id; nothing secret is typed here. */
export function SecretSourceDialog({ source, initialCredentialId = null, initialKind = "vault", onClose, onSaved }: {
  source?: SecretSource | undefined;
  /** A new AppRole source preselects this login credential (U0: "Create secret source" on an AppRole). */
  initialCredentialId?: string | null;
  /** ADR-0026: "Create secret source" on a Bitwarden access token starts a Bitwarden source. */
  initialKind?: SecretSourceKind;
  onClose: () => void;
  onSaved: (s: SecretSource) => void;
}) {
  const [d, setD] = useState<SecretSourceInput>(() => (source ? toInput(source) : blank(initialKind, initialCredentialId)));
  const kind = d.kind ?? "vault";
  const vault = kind === "vault";
  const [origin, setOrigin] = useState("");
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const errors = validateSecretSource(d);
  const show = (k: string) => (tried ? errors[k] : undefined);
  const patch = (p: Partial<SecretSourceInput>) => { setD((cur) => ({ ...cur, ...p })); };
  const patchOptions = (p: Partial<SecretSourceInput["options"]>) => { setD((cur) => ({ ...cur, options: { ...cur.options, ...p } })); };
  const credentialKind = vault ? SECRET_AUTH_CREDENTIAL[d.authMethod] : SOURCE_LOGIN_KIND[kind];

  const changeMethod = (m: SecretAuthMethod) => {
    setD((cur) => ({
      ...cur, authMethod: m, authMount: "", credentialId: null, oidcRole: m === "oidc" ? (cur.oidcRole ?? "") : null,
      options: { ...cur.options, allowedOrigins: m === "oidc" ? cur.options.allowedOrigins : [] },
    }));
  };

  const addOrigin = () => {
    const o = origin.trim().toLowerCase().replace(/\/+$/, "");
    if (o === "" || checkUrl(o, false, true)) { setError(checkUrl(o, false, true) ?? "Enter an origin."); return; }
    if (!d.options.allowedOrigins.includes(o)) patchOptions({ allowedOrigins: [...d.options.allowedOrigins, o] });
    setOrigin("");
    setError(null);
  };

  async function save() {
    setTried(true);
    if (Object.keys(errors).length > 0 || busy) return;
    setBusy(true);
    try {
      const input: SecretSourceInput = { ...d, name: d.name.trim(), namespace: d.namespace?.trim() || null, oidcRole: d.oidcRole?.trim() || null };
      onSaved(source ? await ipc.secretSourceUpdate({ id: source.id, ...input }) : await ipc.secretSourceCreate(input));
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={source ? `Edit ${source.name}` : "New secret source"} onClose={onClose} width={560}>
      <form onSubmit={(e) => { e.preventDefault(); void save(); }} autoComplete="off">
        <div className="settings-body">
          {source ? (
            <p className="field-hint mt-0">Provider: <span className="text-text">{SOURCE_KIND_LABEL[kind]}</span>. The provider of a source cannot change.</p>
          ) : (
            <Seg legend="Provider" name="ss-kind" value={kind} options={KINDS} onChange={(k) => { setD((cur) => ({ ...blank(k, null), name: cur.name, address: cur.address })); setTried(false); }} hint={KIND_HINT[kind]} />
          )}
          <div className={vault ? "settings-grid" : undefined}>
            <div>
              <label className="field-label" htmlFor="ss-name">Name</label>
              <input id="ss-name" className="field" autoFocus maxLength={200} value={d.name} aria-invalid={show("name") ? true : undefined} onChange={(e) => { patch({ name: e.target.value }); }} />
              {show("name") && <p className="field-hint field-problem">{show("name")}</p>}
            </div>
            {vault && <div>
              <label className="field-label" htmlFor="ss-ns">Namespace <span className="field-opt">optional</span></label>
              <input id="ss-ns" className="field mono" spellCheck={false} placeholder="admin/team" value={d.namespace ?? ""} aria-invalid={show("namespace") ? true : undefined} onChange={(e) => { patch({ namespace: e.target.value }); }} />
              {show("namespace") && <p className="field-hint field-problem">{show("namespace")}</p>}
            </div>}
          </div>
          <div>
            <label className="field-label" htmlFor="ss-addr">Address</label>
            <input id="ss-addr" className="field mono" spellCheck={false} placeholder={ADDRESS[kind].placeholder} value={d.address} aria-invalid={show("address") ? true : undefined} onChange={(e) => { patch({ address: e.target.value }); }} />
            <p className={`field-hint${show("address") ? " field-problem" : ""}`}>{show("address") ?? ADDRESS[kind].hint}</p>
          </div>

          {vault && <Seg legend="Sign-in method" name="ss-method" value={d.authMethod} options={METHODS} onChange={changeMethod} hint={METHOD_HINT[d.authMethod]} />}

          {credentialKind && (
            <KindCredentialSelect id="ss-cred" label={kind === "onepassword" ? "Connect token credential" : kind === "bitwarden" ? "Access token credential" : d.authMethod === "token" ? "Token credential" : "AppRole credential"} kind={credentialKind}
              value={d.credentialId ?? ""} onChange={(id) => { patch({ credentialId: id || null }); }} problem={show("credentialId")}
              hint="Only the credential id is stored on the source; its secrets stay sealed in the vault." />
          )}
          {d.authMethod === "oidc" && (
            <div>
              <label className="field-label" htmlFor="ss-role">OIDC role</label>
              <input id="ss-role" className="field mono" spellCheck={false} placeholder="ops" value={d.oidcRole ?? ""} aria-invalid={show("oidcRole") ? true : undefined} onChange={(e) => { patch({ oidcRole: e.target.value }); }} />
              <p className={`field-hint${show("oidcRole") ? " field-problem" : ""}`}>
                {show("oidcRole") ?? <>The role's <span className="mono">allowed_redirect_uris</span> must include <span className="mono select-text">{OIDC_REDIRECT_URI}</span>. Mooring intercepts that redirect; no port is opened.</>}
              </p>
            </div>
          )}
          {kind === "bitwarden" && <BwsPathField value={d.options.bwsPath ?? null} onChange={(bwsPath) => { patchOptions({ bwsPath }); }} problem={show("bwsPath")} />}
          {vault && d.authMethod !== "token" && (
            <div>
              <label className="field-label" htmlFor="ss-mount">Auth mount <span className="field-opt">optional</span></label>
              <input id="ss-mount" className="field mono" spellCheck={false} placeholder={d.authMethod} value={d.authMount} aria-invalid={show("authMount") ? true : undefined} onChange={(e) => { patch({ authMount: e.target.value }); }} />
              <p className={`field-hint${show("authMount") ? " field-problem" : ""}`}>{show("authMount") ?? `Where the ${d.authMethod === "oidc" ? "OIDC" : "AppRole"} method is mounted; empty = ${d.authMethod}.`}</p>
            </div>
          )}

          {d.authMethod === "oidc" && (
            <fieldset className="opt-origins">
              <legend className="field-label">Extra sign-in origins <span className="field-opt">optional</span></legend>
              <p className="field-hint mt-0">The identity provider's origin is always allowed. Add others only if your provider redirects through them (at most 16).</p>
              {d.options.allowedOrigins.length > 0 && (
                <ul className="opt-origin-list" aria-label="Allowed origins">
                  {d.options.allowedOrigins.map((o) => (
                    <li key={o}><span className="mono">{o}</span>
                      <button type="button" className="btn btn-ghost" aria-label={`Remove ${o}`} onClick={() => { patchOptions({ allowedOrigins: d.options.allowedOrigins.filter((x) => x !== o) }); }}>Remove</button>
                    </li>
                  ))}
                </ul>
              )}
              <div className="flex gap-2">
                <input aria-label="Origin to allow" className="field mono flex-1" spellCheck={false} placeholder="https://login.example.test" value={origin}
                  onChange={(e) => { setOrigin(e.target.value); }} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addOrigin(); } }} />
                <button type="button" className="btn" onClick={addOrigin}>Add</button>
              </div>
              {show("allowedOrigins") && <p className="field-hint field-problem">{show("allowedOrigins")}</p>}
            </fieldset>
          )}

          {kind !== "bitwarden" && <div className="settings-toggles">
            <CaPemField id="ss-ca" value={d.options.caPem} error={show("caPem")} onChange={(caPem) => { patchOptions({ caPem }); }} />
            <Toggle checked={d.options.allowHttp} onChange={(allowHttp) => { patchOptions({ allowHttp }); }} label="Allow http:// (loopback only)"
              hint={`For a ${vault ? "Vault dev server" : "Connect server"} on 127.0.0.1 or [::1]. The change is recorded in the audit log.`} />
            {d.options.allowHttp && <Warn>Tokens and secrets travel in clear text over http://. Never use this beyond the loopback interface.</Warn>}
          </div>}
        </div>
        <DialogFooter error={error ?? (tried && Object.keys(errors).length > 0 ? "Fix the highlighted fields." : null)}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{source ? "Save source" : "Create source"}</button>
        </DialogFooter>
      </form>
    </Modal>
  );
}

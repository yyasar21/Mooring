import { useEffect } from "react";
import { LDAP_CREDENTIAL_KINDS, LDAP_LIMITS, type CredentialMeta, type LdapBindInfo, type LdapKind, type LdapScope } from "../../lib/ipc";
import { accountSummary } from "../../lib/credentials";
import { useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";
import { CaPemField, Seg } from "../dialogs/options/controls";
import { LDAP_DN_EXAMPLE, LDAP_URL_EXAMPLE, type LdapForm, type LdapFormErrors } from "./ldapForm";

const SCOPES: readonly { value: LdapScope; label: string }[] = [{ value: "sub", label: "Subtree" }, { value: "one", label: "One level" }];
const KINDS: readonly { value: LdapKind; label: string }[] = [{ value: "ad", label: "Active Directory" }, { value: "openldap", label: "OpenLDAP" }];
const KIND_HINT: Record<LdapKind, string> = {
  ad: "Reads objectClass=computer: the DNS host name and the operating system. Windows becomes an RDP connection, anything else SSH.",
  openldap: "Reads ipHost and device objects: the first ipHostNumber, else the name, becomes the host; every connection is SSH.",
};

/**
 * The wizard's `directory` step (ADR-0019 §4, I2): the LDAPS server, the base DN, scope, directory
 * kind, name filter, the bind credential (domain or user/password only), the extra CA and the
 * size cap. "Test bind" shows where Mooring bound and as whom; the certificate prompt is a
 * Rust-native dialog, so the form only ever shows its outcome as text.
 */
export function DirectoryForm({ value, errors, bind, busy, onChange, onTest }: {
  value: LdapForm;
  errors: LdapFormErrors;
  bind: LdapBindInfo | null;
  busy: boolean;
  onChange: (patch: Partial<LdapForm>) => void;
  onTest: () => void;
}) {
  const items = useCredentials((s) => s.items);
  const kinds = useCredentials((s) => s.kinds);
  const showCredentials = useUi((s) => s.showCredentials);
  useEffect(() => {
    if (items.length === 0) void useCredentials.getState().load();
  }, [items.length]);
  const compatible = items
    .filter((c) => (LDAP_CREDENTIAL_KINDS as readonly string[]).includes(c.kind))
    .sort((a, b) => a.name.localeCompare(b.name));
  const detail = (c: CredentialMeta) => {
    const a = accountSummary(c);
    const k = kinds.find((x) => x.kind === c.kind)?.label ?? c.kind;
    return a ? `${c.name} · ${a} (${k})` : `${c.name} (${k})`;
  };
  const problem = (k: keyof LdapForm) => errors[k];
  const hintClass = (k: keyof LdapForm) => `field-hint${problem(k) ? " field-problem" : ""}`;

  return (
    <div className="imp-dir" data-busy={busy || undefined}>
      <p className="text-text-muted">
        Mooring binds to the directory over TLS, reads the computer objects under the base DN once, and keeps the result as a plan in memory for ten minutes. Each OU becomes a folder; every connection shares one credential that asks at connect. Nothing is written to the directory.
      </p>

      <div>
        <label className="field-label" htmlFor="ldap-url">Server</label>
        <input id="ldap-url" className="field mono" spellCheck={false} placeholder={LDAP_URL_EXAMPLE} value={value.url} disabled={busy}
          aria-invalid={problem("url") ? true : undefined} aria-describedby="ldap-url-hint" onChange={(e) => { onChange({ url: e.target.value }); }} data-focus-first />
        <p id="ldap-url-hint" className={hintClass("url")}>{problem("url") ?? "ldaps:// only, port 636 unless given. Plain ldap:// and StartTLS are refused; an unknown certificate opens Mooring's trust dialog."}</p>
      </div>

      <div>
        <label className="field-label" htmlFor="ldap-base">Base DN</label>
        <input id="ldap-base" className="field mono" spellCheck={false} placeholder={LDAP_DN_EXAMPLE} value={value.baseDn} disabled={busy}
          aria-invalid={problem("baseDn") ? true : undefined} aria-describedby="ldap-base-hint" onChange={(e) => { onChange({ baseDn: e.target.value }); }} />
        <p id="ldap-base-hint" className={hintClass("baseDn")}>{problem("baseDn") ?? "Where the search starts. Use an OU to import one part of the directory; folders mirror the OUs below it, eight levels at most."}</p>
      </div>

      <div className="imp-dir-row">
        <Seg legend="Scope" name="ldap-scope" value={value.scope} options={SCOPES} onChange={(scope) => { onChange({ scope }); }} />
        <Seg legend="Directory kind" name="ldap-kind" value={value.kind} options={KINDS} onChange={(kind) => { onChange({ kind }); }} />
      </div>
      <p className="field-hint mt-0">{KIND_HINT[value.kind]}</p>

      <div>
        <label className="field-label" htmlFor="ldap-filter">Name filter <span className="field-opt">optional</span></label>
        <input id="ldap-filter" className="field mono" spellCheck={false} placeholder="web" value={value.filter} disabled={busy}
          aria-invalid={problem("filter") ? true : undefined} aria-describedby="ldap-filter-hint" onChange={(e) => { onChange({ filter: e.target.value }); }} />
        <p id="ldap-filter-hint" className={hintClass("filter")}>
          {problem("filter") ?? "Keeps the computers whose name or DNS host name contains this text. It is matched as plain text: *, ( ), \\ and the like are escaped, never interpreted."}
        </p>
      </div>

      <div>
        <label className="field-label" htmlFor="ldap-cred">Bind credential</label>
        <div className="flex gap-2">
          <select id="ldap-cred" className="field min-w-0 flex-1" value={value.credentialId} disabled={busy || compatible.length === 0}
            aria-invalid={problem("credentialId") ? true : undefined} aria-describedby="ldap-cred-hint" onChange={(e) => { onChange({ credentialId: e.target.value }); }}>
            <option value="">{compatible.length === 0 ? "No domain or user/password credential yet" : "Choose…"}</option>
            {compatible.map((c) => <option key={c.id} value={c.id}>{detail(c)}</option>)}
          </select>
          <button type="button" className="btn" disabled={busy} onClick={() => { showCredentials({ mode: "new" }); }}>New credential…</button>
        </div>
        <p id="ldap-cred-hint" className={hintClass("credentialId")}>
          {problem("credentialId") ?? "A Windows domain or a user and password credential that may read the directory. Its password is read from the vault for the bind and dropped; the directory never hands a credential back."}
        </p>
      </div>

      <CaPemField id="ldap-ca" value={value.caPem} error={problem("caPem")} onChange={(caPem) => { onChange({ caPem }); }} />

      <div className="imp-dir-row">
        <div>
          <label className="field-label" htmlFor="ldap-size">Size limit</label>
          <input id="ldap-size" className="field mono tnum" inputMode="numeric" value={value.sizeLimit} disabled={busy} size={6}
            aria-invalid={problem("sizeLimit") ? true : undefined} aria-describedby="ldap-size-hint" onChange={(e) => { onChange({ sizeLimit: e.target.value }); }} />
          <p id="ldap-size-hint" className={hintClass("sizeLimit")}>
            {problem("sizeLimit") ?? `At most ${LDAP_LIMITS.maxSizeLimit.toLocaleString("en-US")} entries per run, and 30 seconds. A search that matches more stops with an error instead of importing a part.`}
          </p>
        </div>
      </div>

      <div className="imp-dock m-hud" data-active={bind ? true : undefined}>
        {bind ? (
          <div className="imp-dock-file" role="status">
            <span className="imp-dock-name">{bind.host}<span className="imp-row-port">:{bind.port}</span></span>
            <span className="imp-dock-size">Bound as <span className="mono select-text">{bind.boundAs}</span>, then disconnected. Nothing was searched.</span>
          </div>
        ) : (
          <span className="imp-dock-empty">Not tested yet. A test binds and disconnects without searching.</span>
        )}
        <button type="button" className="btn" disabled={busy} onClick={onTest}>Test bind</button>
      </div>
    </div>
  );
}

import type { CredentialMeta, CredentialRole, KindSchema, Protocol } from "../../lib/ipc";
import { CredentialPicker, type PickerOption } from "../credentials/CredentialPicker";

/** The connection dialog's Sign-in section (L1): who signs in, the account overrides, sudo and the Vault certificate. */
export function SignInFields(p: {
  protocol: Protocol;
  kinds: KindSchema[];
  primary: string;
  primaryOptions: PickerOption[];
  onPrimary: (v: string) => void;
  inherited: CredentialMeta | undefined;
  inheritedProblem: string | null;
  canUser: boolean;
  canDomain: boolean;
  userOv: string;
  domainOv: string;
  onUserOv: (v: string) => void;
  onDomainOv: (v: string) => void;
  become: string;
  becomeOptions: PickerOption[];
  onBecome: (v: string) => void;
  certificate: string;
  certificateOptions: PickerOption[];
  onCertificate: (v: string) => void;
  dropped: boolean;
  onNew: (role: CredentialRole) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <CredentialPicker label="Credential" value={p.primary} options={p.primaryOptions} kinds={p.kinds} onChange={p.onPrimary} />
        </div>
        <button type="button" className="btn mt-[26px]" aria-label="New credential…" onClick={() => { p.onNew("primary"); }}>
          New…
        </button>
      </div>
      {p.inherited && p.inheritedProblem && (
        <p className="field-hint field-problem" role="note">
          The folder credential “{p.inherited.name}” cannot sign in here: {p.inheritedProblem} Choose one above, or the session will fail.
        </p>
      )}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="field-label" htmlFor="conn-user-ov">
            Username override<span className="field-opt">optional</span>
          </label>
          <input
            id="conn-user-ov"
            className="field mono"
            spellCheck={false}
            disabled={!p.canUser}
            placeholder={p.canUser ? "use the credential's" : "not used by this kind"}
            value={p.canUser ? p.userOv : ""}
            onChange={(e) => { p.onUserOv(e.target.value); }}
          />
        </div>
        <div>
          <label className="field-label" htmlFor="conn-domain-ov">
            Domain override<span className="field-opt">optional</span>
          </label>
          <input
            id="conn-domain-ov"
            className="field mono"
            spellCheck={false}
            disabled={!p.canDomain}
            placeholder={p.canDomain ? "use the credential's" : "not used by this kind"}
            value={p.canDomain ? p.domainOv : ""}
            onChange={(e) => { p.onDomainOv(e.target.value); }}
          />
        </div>
      </div>
      <p className="field-hint">Overrides replace the account for this connection only. The stored secret is shared.</p>
      {p.protocol === "ssh" && (
        <CredentialPicker
          label="Become (sudo)"
          value={p.become}
          options={p.becomeOptions}
          kinds={p.kinds}
          onChange={p.onBecome}
          hint="The password is sent only when the remote sudo prompt appears."
        />
      )}
      {p.protocol === "ssh" && (
        <CredentialPicker
          label="Certificate (Vault SSH CA)"
          value={p.certificate}
          options={p.certificateOptions}
          kinds={p.kinds}
          onChange={p.onCertificate}
          hint="Vault signs the public half of this connection's SSH key at each connect. Offers SSH sign references only."
        />
      )}
      {p.dropped && <p className="field-hint">A previous choice does not fit {p.protocol.toUpperCase()} and was cleared.</p>}
    </div>
  );
}

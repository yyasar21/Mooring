import type { CredentialMeta } from "../../lib/ipc";
import { PKCS11_MODULE_LABEL } from "../../lib/ipc";
import { Fingerprint } from "./fields";

/** The contract's copy (`a5-rust-core-r5.md`, UI contract): the PIN note and the SSH hint. */
export const PIN_NOTE = "PIN asked at connect, never stored.";
export const SSH_ADD_HINT = "Load the card into ssh-agent with ssh-add -s <module>, or choose the module so Mooring asks the PIN.";

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** The `SHA256:` Rust derived from `public_key` (`fields.fingerprint`, or the card-level value). */
export function smartCardFingerprint(meta: CredentialMeta | undefined): string {
  return meta ? meta.fingerprint ?? str(meta.fields.fingerprint) : "";
}

/** ADR-0027 §2: under the `smart_card` form fields. Nothing about the card is secret, and nothing secret is asked here. */
export function SmartCardNote({ meta }: { meta: CredentialMeta | undefined }) {
  const fp = smartCardFingerprint(meta);
  return (
    <section className="space-y-2" aria-label="Smart card">
      <p className="kind-note" role="note">
        <strong>{PIN_NOTE}</strong> When ssh-agent does not hold the card's key yet, Mooring asks the PIN once and hands it to the
        agent. There is never a password fallback. {SSH_ADD_HINT}
      </p>
      {fp ? (
        <dl className="prop-grid derived">
          <dt>Fingerprint</dt>
          <dd><Fingerprint value={fp} /></dd>
        </dl>
      ) : (
        <p className="field-hint">The SHA256 fingerprint of the public key is computed when you save.</p>
      )}
    </section>
  );
}

/** The detail card section: how the card signs in. The fingerprint is in the card's Credential section. */
export function SmartCardDetail({ meta }: { meta: CredentialMeta }) {
  const f = (k: string) => str(meta.fields[k]);
  const module = f("pkcs11_module");
  return (
    <section className="cred-detail-section sk-detail" aria-labelledby={`piv-${meta.id}`}>
      <h3 id={`piv-${meta.id}`} className="sk-heading">Smart card</h3>
      <p className="sk-signs">
        Signs through your ssh-agent. {PIN_NOTE} Smart-card logon over RDP needs Kerberos PKINIT (planned).
      </p>
      <dl className="prop-grid">
        <dt>Reader</dt>
        <dd>{f("reader_hint") || <span className="text-text-faint">any</span>}</dd>
        <dt>PKCS#11 module</dt>
        <dd>
          {module ? (PKCS11_MODULE_LABEL[module] ?? module) : <span className="text-text-faint">none: the key must already be in ssh-agent</span>}
        </dd>
        <dt>Public key</dt>
        <dd>{f("public_key") ? "Stored (pins the agent key)" : <span className="text-danger">missing: SSH cannot pick the card's key</span>}</dd>
        {f("domain") && <><dt>Domain</dt><dd className="mono select-text">{f("domain")}</dd></>}
      </dl>
      <p className="field-hint">{SSH_ADD_HINT}</p>
    </section>
  );
}

import type { CredentialMeta } from "../../lib/ipc";
import { SK_TYPE_LABEL, parseSkPublicLine } from "../../lib/credentials.sk";
import { Fingerprint } from "./fields";

/**
 * ADR-0024: what a security-key credential is and how it signs. Fingerprint and application are
 * the values Rust derived (`fields.fingerprint` / `fields.application`); never a key handle.
 */
export function SkKeyDetail({ meta }: { meta: CredentialMeta }) {
  const f = (k: string) => { const v = meta.fields[k]; return typeof v === "string" ? v : ""; };
  // The card above already shows `meta.fingerprint`; repeat the derived field only when it is missing there.
  const fingerprint = meta.fingerprint ? "" : f("fingerprint");
  const type = parseSkPublicLine(f("public_key")).key?.type;
  const helper = f("backend") === "helper";
  const resident = meta.fields.resident === true || meta.fields.resident === "true";
  return (
    <section className="cred-detail-section sk-detail" aria-labelledby={`sk-${meta.id}`}>
      <h3 id={`sk-${meta.id}`} className="sk-heading">Security key</h3>
      <p className="sk-signs" data-tone={helper ? "hot" : undefined}>
        {helper
          ? "Set to sign directly with ssh-sk-helper, which is turned off in this version. Edit it to sign through your ssh-agent."
          : "Signs through your ssh-agent. Touch the key when Mooring asks; there is never a password fallback."}
      </p>
      <dl className="prop-grid">
        {type && <><dt>Type</dt><dd>{SK_TYPE_LABEL[type]}</dd></>}
        {fingerprint && <><dt>Fingerprint</dt><dd><Fingerprint value={fingerprint} /></dd></>}
        {f("application") && <><dt>Application</dt><dd className="mono select-text">{f("application")}</dd></>}
        <dt>Resident</dt>
        <dd>{resident ? "Yes, stored on the key (ssh-add -K)" : "No, uses a key handle file (ssh-add <handle file>)"}</dd>
        <dt>Certificate</dt>
        <dd>{f("certificate") ? "OpenSSH certificate stored" : <span className="text-text-faint">none stored</span>}</dd>
      </dl>
    </section>
  );
}

// ADR-0024: the plain half of the "SSH security key (FIDO2)" form. The public key is pasted or
// opened from its .pub file (public data, read in the page); the key-handle file and its
// passphrase are ordinary secret inputs below this section. Rust parses and derives; this only
// checks the shape and previews the type, FIDO application and fingerprint.
import { useId, useRef, useState } from "react";
import type { CredentialMeta, FieldSchema, KindSchema } from "../../lib/ipc";
import { SK_TYPE_LABEL, parseSkPublicLine } from "../../lib/credentials.sk";
import { Fingerprint, PlainField } from "./fields";
import type { FormState, Problems } from "./formModel";

/** The cap of a .pub file read in the page (the schema allows 16 KiB). */
const MAX_PUB = 16 * 1024;

export const HELPER_LATER = "Direct security-key access (without ssh-agent) is coming later. Mooring signs through your ssh-agent.";

export function SkKeySection({ schema, kinds, s, meta, tried, problems, setValue, fingerprint }: {
  schema: KindSchema;
  kinds: KindSchema[];
  s: FormState;
  meta: CredentialMeta | undefined;
  tried: boolean;
  problems: Problems;
  setValue: (name: string, v: string) => void;
  /** Live `SHA256:` of the typed public key (null while it does not parse). */
  fingerprint: string | null;
}) {
  const id = useId();
  const file = useRef<HTMLInputElement>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const f = (name: string): FieldSchema | undefined => schema.fields.find((x) => x.name === name);
  const v = (name: string) => s.values[name] ?? "";
  const problem = (name: string) => (tried || v(name) ? problems[name] : undefined);
  const parsed = parseSkPublicLine(v("public_key")).key;
  const storedApp = typeof meta?.fields.application === "string" ? meta.fields.application : null;
  const helperStored = v("backend") === "helper";

  const plain = (name: string) => {
    const field = f(name);
    return field ? (
      <PlainField f={field} value={v(name)} onChange={(x) => { setValue(name, x); }} problem={problem(name)} options={[]} kinds={kinds} context={s.values} />
    ) : null;
  };

  const openPub = async (picked: File | undefined) => {
    setFileError(null);
    if (!picked) return;
    if (picked.size > MAX_PUB) {
      setFileError("That file is larger than a public key file can be.");
      return;
    }
    const text = await picked.text();
    // A private key never lands in a plain field (B-3): the handle file goes into the secret input.
    if (/PRIVATE KEY/.test(text)) {
      setFileError("That is the key handle file. Open the .pub file here, and paste the handle file under Secrets if you need it.");
      return;
    }
    setValue("public_key", text.trim());
  };

  return (
    <section className="sk-section" aria-labelledby={`${id}-h`}>
      <h3 id={`${id}-h`} className="sk-heading">Security key</h3>
      <div className="cred-grid">
        <div>{plain("username")}</div>
        <div className="col-span-full">
          {plain("public_key")}
          <div className="sk-pub-actions">
            <button type="button" className="btn" onClick={() => file.current?.click()}>Open .pub file…</button>
            <input
              ref={file}
              type="file"
              accept=".pub,text/plain"
              className="sr-only"
              tabIndex={-1}
              aria-label="Choose a .pub file"
              onChange={(e) => { void openPub(e.target.files?.[0]); e.target.value = ""; }}
            />
            {fileError && <span role="alert" className="field-problem text-[length:var(--fs-12)]">{fileError}</span>}
          </div>
          {parsed && (
            <dl className="sk-preview" aria-label="Key preview">
              <dt>Type</dt>
              <dd>{SK_TYPE_LABEL[parsed.type]}</dd>
              <dt>Application</dt>
              <dd className="mono">{parsed.application}</dd>
              {fingerprint && (
                <>
                  <dt>Fingerprint</dt>
                  <dd><Fingerprint value={fingerprint} /></dd>
                </>
              )}
            </dl>
          )}
          {!parsed && storedApp && <p className="field-hint">Application <span className="mono text-text">{storedApp}</span></p>}
        </div>

        <fieldset className="col-span-full min-w-0">
          <legend className="field-label">{f("backend")?.label ?? "Signing"}</legend>
          <div className="sk-backends">
            <label className="sk-backend">
              <input type="radio" name={`${id}-backend`} checked={!helperStored} onChange={() => { setValue("backend", "agent"); }} />
              <span>
                <span className="text-text">Through your ssh-agent</span>
                <span className="field-hint block">Add the key first: ssh-add -K for a resident key, or ssh-add with the key handle file.</span>
              </span>
            </label>
            <label className="sk-backend" data-disabled={!helperStored || undefined}>
              <input type="radio" name={`${id}-backend`} checked={helperStored} disabled={!helperStored} onChange={() => { setValue("backend", "helper"); }} />
              <span>
                <span className="text-text">Directly with ssh-sk-helper</span>
                <span className="field-hint block">{helperStored ? "Turned off in this version: connections with this credential are refused until you switch to ssh-agent." : HELPER_LATER}</span>
              </span>
            </label>
          </div>
        </fieldset>

        <div className="col-span-full">
          <label className="sk-check">
            <input
              type="checkbox"
              checked={v("resident") === "true"}
              onChange={(e) => { setValue("resident", e.target.checked ? "true" : "false"); }}
            />
            <span>
              <span className="text-text">{f("resident")?.label ?? "Resident key"}</span>
              <span className="field-hint block">
                Stored on the security key itself (made with ssh-keygen -O resident). A stored key handle file sets this for you.
              </span>
            </span>
          </label>
        </div>

        <div className="col-span-full">{plain("certificate")}</div>
      </div>
    </section>
  );
}

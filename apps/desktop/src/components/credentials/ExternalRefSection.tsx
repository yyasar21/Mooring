import { useEffect, useState } from "react";
import { HudLabel } from "@mooring/ui";
import { ipc, type CredentialMeta, type ExternalRefTest, type FieldSchema, type KindSchema, type SecretSource } from "../../lib/ipc";
import { describeCode, describeError } from "../../stores/errors";
import { useUi } from "../../stores/ui";
import { PlainField } from "./fields";
import { targetNames, type FormState } from "./formModel";

/** `credential_external_test` as one sentence plus the key names (never values). */
export function refTestSummary(t: ExternalRefTest): string {
  if (t.error) return `${describeCode(t.error)}${t.category ? ` (${t.category.replace(/_/g, " ")})` : ""}`;
  if (t.ok) return `The secret${t.version !== null ? ` (version ${t.version})` : ""} has every field the target kind needs.`;
  const parts = [
    t.missing.length > 0 ? `${t.missing.length} required name${t.missing.length === 1 ? " is" : "s are"} missing` : "",
    t.extra.length > 0 ? `${t.extra.length} extra key${t.extra.length === 1 ? "" : "s"} would be refused` : "",
  ].filter(Boolean);
  return `The secret${t.version !== null ? ` (version ${t.version})` : ""} was found but ${parts.join(" and ")}. Adjust the field map or the KV keys.`;
}

/** The ADR-0016 §2 half of the credential form: source, reference, pinned version, target kind and field map. */
export function ExternalRefSection({ schema, kinds, s, meta, tried, problems, setValue, setFieldMap }: {
  schema: KindSchema;
  kinds: KindSchema[];
  s: FormState;
  meta: CredentialMeta | undefined;
  tried: boolean;
  problems: Record<string, string>;
  setValue: (name: string, v: string) => void;
  setFieldMap: (m: Record<string, string>) => void;
}) {
  const [sources, setSources] = useState<SecretSource[] | null>(null);
  const [test, setTest] = useState<ExternalRefTest | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [newName, setNewName] = useState("");
  const setView = useUi((st) => st.setView);
  const field = (name: string) => schema.fields.find((f) => f.name === name) as FieldSchema;
  // Vault is the only provider that resolves (ADR-0016 §5); its fields show until another is picked.
  const vault = s.values.provider !== "onepassword" && s.values.provider !== "bitwarden";
  const names = targetNames(kinds, s.values.target_kind ?? "");
  const free = names.filter((n) => !(n in s.fieldMap));
  const show = (name: string) => (tried || s.values[name] ? problems[name] : undefined);

  useEffect(() => {
    let live = true;
    ipc.secretSourceList().then((list) => { if (live) setSources(list); }, () => { if (live) setSources([]); });
    return () => { live = false; };
  }, []);

  // The stored row changes under an edit; a stale verdict must not survive it.
  useEffect(() => { setTest(null); }, [meta?.updatedAt]);

  async function runTest() {
    if (!meta) return;
    setTesting(true);
    setTestError(null);
    try {
      setTest(await ipc.credentialExternalTest({ credentialId: meta.id }));
    } catch (e: unknown) {
      setTest(null);
      setTestError(describeError(e));
    } finally {
      setTesting(false);
    }
  }

  const sourceOptions = (sources ?? []).map((src) => ({ value: src.id, label: `${src.name} · ${src.address}` }));
  const sourceId = s.values.source ?? "";
  const unknownSource = sources !== null && sourceId !== "" && !sources.some((src) => src.id === sourceId);

  return (
    <section className="space-y-3">
      <HudLabel>Reference</HudLabel>
      <div className="cred-grid">
        <PlainField f={field("provider")} value={s.values.provider ?? ""} onChange={(v) => { setValue("provider", v); }} problem={show("provider")} options={field("provider").validation.options ?? []} kinds={kinds} context={s.values} />
        <PlainField f={field("target_kind")} value={s.values.target_kind ?? ""} onChange={(v) => { setValue("target_kind", v); setFieldMap({}); }} problem={show("target_kind")} options={field("target_kind").validation.options ?? []} kinds={kinds} context={s.values} />
        {vault && (
          <div className="min-w-0">
            <label className="field-label" htmlFor="ref-source">Secret source</label>
            <div className="flex gap-2">
              <select id="ref-source" className="field min-w-0 flex-1" value={sourceId} disabled={sources === null || sources.length === 0}
                aria-invalid={show("source") || unknownSource ? true : undefined} aria-describedby="ref-source-hint" onChange={(e) => { setValue("source", e.target.value); }}>
                <option value="">{sources === null ? "Loading…" : sources.length === 0 ? "No secret source yet" : "Choose…"}</option>
                {unknownSource && <option value={sourceId}>Unknown source {sourceId}</option>}
                {sourceOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <button type="button" className="btn" onClick={() => { setView("settings"); }}>Manage…</button>
            </div>
            <p id="ref-source-hint" className={`field-hint${show("source") || unknownSource ? " field-problem" : ""}`}>
              {show("source") ?? (unknownSource ? "This source was deleted. Choose another." : "Vault servers are set up in Settings → Secret sources.")}
            </p>
          </div>
        )}
        <div className={vault ? "col-span-full" : undefined}>
          <PlainField f={field("reference")} value={s.values.reference ?? ""} onChange={(v) => { setValue("reference", v); }} problem={show("reference")} options={[]} kinds={kinds} context={s.values} />
        </div>
        {vault && <PlainField f={field("version")} value={s.values.version ?? ""} onChange={(v) => { setValue("version", v); }} problem={show("version")} options={[]} kinds={kinds} context={s.values} />}
      </div>

      {vault && names.length > 0 && (
        <fieldset className="min-w-0">
          <legend className="field-label">Field map <span className="field-opt">optional</span></legend>
          <p className="field-hint mt-0">
            KV keys default to the target kind's own names ({names.join(", ")}). Map a name to a different key when the secret uses other names.
          </p>
          {Object.keys(s.fieldMap).length > 0 && (
            <div className="fieldmap-grid mt-2" role="group" aria-label="Field map">
              {Object.entries(s.fieldMap).map(([name, key]) => (
                <FieldMapRow key={name} name={name} value={key} onChange={(v) => { setFieldMap({ ...s.fieldMap, [name]: v }); }}
                  onRemove={() => { setFieldMap(Object.fromEntries(Object.entries(s.fieldMap).filter(([n]) => n !== name))); }} />
              ))}
            </div>
          )}
          {free.length > 0 && (
            <div className="mt-2 flex gap-2">
              <select aria-label="Target field to map" className="field flex-1" value={newName} onChange={(e) => { setNewName(e.target.value); }}>
                <option value="">Add a mapping…</option>
                {free.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
              <button type="button" className="btn" disabled={newName === ""} onClick={() => { setFieldMap({ ...s.fieldMap, [newName]: "" }); setNewName(""); }}>Map</button>
            </div>
          )}
          {tried && problems.field_map && <p className="field-hint field-problem">{problems.field_map}</p>}
        </fieldset>
      )}

      {vault && (
        <div className="kind-note space-y-2" role="note">
          <p>
            Only the reference is stored. At connect time Mooring signs in to the source, reads the secret, builds the target credential in
            memory and drops it after the handshake. Nothing is cached, so an unreachable source means no connection.
          </p>
          <div className="flex items-center gap-3">
            <button type="button" className="btn" disabled={!meta || testing} title={meta ? undefined : "Save the credential first"} onClick={() => void runTest()}>
              {testing ? "Testing…" : "Test reference"}
            </button>
            {!meta && <span className="field-hint">Available after the first save.</span>}
            {testError && <span role="alert" className="settings-err">{testError}</span>}
          </div>
          {test && (
            <div role="status" aria-label="Reference test">
              <p className={test.ok ? "settings-ok" : "settings-err"}>{refTestSummary(test)}</p>
              <ul className="ref-test mt-1">
                {test.present.map((n) => <li key={`p-${n}`} data-tone="present"><span className="m-micro">present</span><span className="mono">{n}</span></li>)}
                {test.missing.map((n) => <li key={`m-${n}`} data-tone="missing"><span className="m-micro">missing</span><span className="mono">{n}</span></li>)}
                {test.extra.map((n) => <li key={`e-${n}`} data-tone="extra"><span className="m-micro">extra</span><span className="mono">{n}</span></li>)}
              </ul>
            </div>
          )}
        </div>
      )}
      {!vault && (
        <p className="kind-note" role="note">
          Only the reference is stored. Resolving from 1Password or Bitwarden arrives in a later release; until then, connecting with it reports
          that the kind is not supported yet.
        </p>
      )}
    </section>
  );
}

function FieldMapRow({ name, value, onChange, onRemove }: { name: string; value: string; onChange: (v: string) => void; onRemove: () => void }) {
  return (
    <>
      <span className="mono text-[length:var(--fs-s)]">{name}</span>
      <input aria-label={`KV key for ${name}`} className="field mono" spellCheck={false} placeholder="key in the KV secret" value={value} onChange={(e) => { onChange(e.target.value); }} />
      <button type="button" className="btn btn-ghost" aria-label={`Remove mapping for ${name}`} onClick={onRemove}>Remove</button>
    </>
  );
}

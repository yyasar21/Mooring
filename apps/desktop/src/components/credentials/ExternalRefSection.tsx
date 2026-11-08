import { useEffect, useId, useState } from "react";
import { HudLabel } from "@mooring/ui";
import {
  ENGINE_LABEL, ENGINE_TARGET, SOURCE_KIND_LABEL, ipc,
  type CredentialMeta, type ExternalRefTest, type FieldSchema, type KindSchema, type SecretSource, type VaultEngine,
} from "../../lib/ipc";
import { engineOf, opNamesItemOnly } from "../../lib/validate.refs";
import { describeCode, describeError } from "../../stores/errors";
import { useUi } from "../../stores/ui";
import { PlainField } from "./fields";
import { REF_LISTS, targetNames, type FormState } from "./formModel";
import { EngineParams, EngineSelect } from "./RefEngineFields";
import { kindLabel } from "../../stores/credentials";

/** `credential_external_test` as one sentence plus the key names (never values). */
export function refTestSummary(t: ExternalRefTest, engine: VaultEngine = "kv2"): string {
  if (t.error) return `${describeCode(t.error)}${t.category ? ` (${t.category.replace(/_/g, " ")})` : ""}`;
  if (t.ok && engine !== "kv2") return `Vault issued ${ENGINE_LABEL[engine]} values with every field the target kind needs. Mooring revoked them at once.`;
  if (t.ok) return `The secret${t.version !== null ? ` (version ${t.version})` : ""} has every field the target kind needs.`;
  const parts = [
    t.missing.length > 0 ? `${t.missing.length} required name${t.missing.length === 1 ? " is" : "s are"} missing` : "",
    t.extra.length > 0 ? `${t.extra.length} extra key${t.extra.length === 1 ? "" : "s"} would be refused` : "",
  ].filter(Boolean);
  return `The secret${t.version !== null ? ` (version ${t.version})` : ""} was found but ${parts.join(" and ")}. Adjust the field map or the KV keys.`;
}

type Provider = "vault" | "onepassword" | "bitwarden";
const isProvider = (v: string | undefined): v is Provider => v === "vault" || v === "onepassword" || v === "bitwarden";

/** Reference input copy per provider and engine. */
function referenceCopy(provider: Provider, engine: VaultEngine): { placeholder: string; hint: string } {
  if (provider === "onepassword") return { placeholder: "op://Infra/prod-db/password", hint: "op://vault/item/[section/]field, or op://vault/item with a field map. Names or ids." };
  if (provider === "bitwarden") return { placeholder: "be8e0ad8-d545-4017-a55a-b02f014d4158", hint: "A secret id, or <project id>/<key>. A JSON object value is mapped like KV keys." };
  if (engine === "kv2") return { placeholder: "kv/prod/db", hint: "<mount>/<path> of a KV v2 secret." };
  return { placeholder: `${engine === "pki" ? "pki" : engine === "database" ? "database" : "ssh"}/${engine === "database" ? "readonly" : "ops"}`, hint: "<mount>/<role> of the role Mooring asks at connect." };
}

/** The ADR-0016 §2 / ADR-0026 half of the credential form: provider, source, engine, reference, target kind and field map. */
export function ExternalRefSection({ schema, kinds, s, meta, tried, problems, setValue, setFieldMap, update }: {
  schema: KindSchema;
  kinds: KindSchema[];
  s: FormState;
  meta: CredentialMeta | undefined;
  tried: boolean;
  problems: Record<string, string>;
  setValue: (name: string, v: string) => void;
  setFieldMap: (m: Record<string, string>) => void;
  /** Several fields at once (provider and engine changes reset what no longer applies). */
  update: (fn: (cur: FormState) => FormState) => void;
}) {
  const [sources, setSources] = useState<SecretSource[] | null>(null);
  const [test, setTest] = useState<ExternalRefTest | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const setView = useUi((st) => st.setView);
  const refId = useId();
  const field = (name: string) => schema.fields.find((f) => f.name === name) as FieldSchema;
  const provider: Provider = isProvider(s.values.provider) ? s.values.provider : "vault";
  const vault = provider === "vault";
  const engine = vault ? engineOf(s.values.engine) : "kv2";
  const fixedTarget = ENGINE_TARGET[engine];
  const dynamic = fixedTarget !== null;
  const names = targetNames(kinds, s.values.target_kind ?? "");
  const show = (name: string) => (tried || s.values[name] || (s.lists[name]?.length ?? 0) > 0 ? problems[name] : undefined);
  // KV, a whole 1Password item, and a Bitwarden JSON value map field names; dynamic engines do not.
  const mapsFields = vault ? !dynamic : provider === "bitwarden" || opNamesItemOnly(s.values.reference ?? "");
  const copy = referenceCopy(provider, engine);

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

  const changeProvider = (p: string) => {
    update((cur) => ({
      ...cur,
      values: { ...cur.values, provider: p, source: "", engine: "", ttl: "", common_name: "", username: "", ...(p === "vault" ? {} : { version: "" }) },
      lists: {},
      fieldMap: {},
    }));
  };
  const changeEngine = (e: VaultEngine) => {
    const target = ENGINE_TARGET[e];
    update((cur) => ({
      ...cur,
      values: {
        ...cur.values, engine: e === "kv2" ? "" : e, ttl: "", common_name: "", username: "",
        ...(target ? { target_kind: target, version: "" } : {}),
      },
      lists: {},
      fieldMap: target ? {} : cur.fieldMap,
    }));
  };

  const mine = (sources ?? []).filter((src) => src.kind === provider);
  const sourceId = s.values.source ?? "";
  const unknownSource = sources !== null && sourceId !== "" && !mine.some((src) => src.id === sourceId);

  return (
    <section className="space-y-3">
      <HudLabel>Reference</HudLabel>
      <div className="cred-grid">
        <PlainField f={field("provider")} value={s.values.provider ?? ""} onChange={changeProvider} problem={show("provider")} options={field("provider").validation.options ?? []} kinds={kinds} context={s.values} />
        <div className="min-w-0">
          <label className="field-label" htmlFor="ref-source">Secret source</label>
          <div className="flex gap-2">
            <select id="ref-source" className="field min-w-0 flex-1" value={sourceId} disabled={sources === null || mine.length === 0}
              aria-invalid={show("source") || unknownSource ? true : undefined} aria-describedby="ref-source-hint" onChange={(e) => { setValue("source", e.target.value); }}>
              <option value="">{sources === null ? "Loading…" : mine.length === 0 ? `No ${SOURCE_KIND_LABEL[provider]} source yet` : "Choose…"}</option>
              {unknownSource && <option value={sourceId}>Unknown source {sourceId}</option>}
              {mine.map((o) => <option key={o.id} value={o.id}>{`${o.name} · ${o.address}`}</option>)}
            </select>
            <button type="button" className="btn" onClick={() => { setView("settings"); }}>Manage…</button>
          </div>
          <p id="ref-source-hint" className={`field-hint${show("source") || unknownSource ? " field-problem" : ""}`}>
            {show("source") ?? (unknownSource ? "This source was deleted or is another provider. Choose another." : `${SOURCE_KIND_LABEL[provider]} servers are set up in Settings → Secret sources.`)}
          </p>
        </div>
        {vault && <EngineSelect value={engine} onChange={changeEngine} problem={show("engine")} kinds={kinds} />}
        {dynamic ? (
          <div className="min-w-0">
            <span className="field-label" id={`${refId}-target`}>Resolves to</span>
            <p className="field ref-fixed" aria-labelledby={`${refId}-target`}>{kindLabel(kinds, fixedTarget)}</p>
            <p className="field-hint">Fixed by the {ENGINE_LABEL[engine]} engine.</p>
          </div>
        ) : (
          <PlainField f={field("target_kind")} value={s.values.target_kind ?? ""} onChange={(v) => { setValue("target_kind", v); setFieldMap({}); }} problem={show("target_kind")} options={field("target_kind").validation.options ?? []} kinds={kinds} context={s.values} />
        )}
        <div className="col-span-full min-w-0">
          <label className="field-label" htmlFor={refId}>{dynamic ? "Role" : "Reference"}</label>
          <input id={refId} className="field mono" spellCheck={false} autoComplete="off" placeholder={copy.placeholder} value={s.values.reference ?? ""}
            aria-invalid={show("reference") ? true : undefined} aria-describedby={`${refId}-hint`} onChange={(e) => { setValue("reference", e.target.value); }} />
          <p id={`${refId}-hint`} className={`field-hint${show("reference") ? " field-problem" : ""}`}>{show("reference") ?? copy.hint}</p>
        </div>
        {vault && !dynamic && <PlainField f={field("version")} value={s.values.version ?? ""} onChange={(v) => { setValue("version", v); }} problem={show("version")} options={[]} kinds={kinds} context={s.values} />}
      </div>

      {dynamic && (
        <EngineParams engine={engine} values={s.values} lists={s.lists} show={show} setValue={setValue}
          setList={(name, v) => { if ((REF_LISTS as readonly string[]).includes(name)) update((cur) => ({ ...cur, lists: { ...cur.lists, [name]: v } })); }} />
      )}

      {mapsFields && names.length > 0 && <FieldMapEditor names={names} map={s.fieldMap} setFieldMap={setFieldMap} problem={tried ? problems.field_map : undefined} provider={provider} />}

      <div className="kind-note space-y-2" role="note">
        <p>
          {dynamic
            ? "Only the role and its parameters are stored. Each connect asks Vault for fresh values; nothing is cached."
            : `Only the reference is stored. At connect time Mooring signs in to the source, reads the secret, builds the target credential in
            memory and drops it after the handshake. Nothing is cached, so an unreachable source means no connection.`}
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
            <p className={test.ok ? "settings-ok" : "settings-err"}>{refTestSummary(test, engine)}</p>
            <ul className="ref-test mt-1">
              {test.present.map((n) => <li key={`p-${n}`} data-tone="present"><span className="ref-test-tag">present</span><span className="mono">{n}</span></li>)}
              {test.missing.map((n) => <li key={`m-${n}`} data-tone="missing"><span className="ref-test-tag">missing</span><span className="mono">{n}</span></li>)}
              {test.extra.map((n) => <li key={`e-${n}`} data-tone="extra"><span className="ref-test-tag">extra</span><span className="mono">{n}</span></li>)}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

/** ADR-0016 field map, reused for 1Password items and Bitwarden JSON values (ADR-0026 §3–§4). */
function FieldMapEditor({ names, map, setFieldMap, problem, provider }: {
  names: string[];
  map: Record<string, string>;
  setFieldMap: (m: Record<string, string>) => void;
  problem: string | undefined;
  provider: Provider;
}) {
  const [newName, setNewName] = useState("");
  const free = names.filter((n) => !(n in map));
  const keyWord = provider === "onepassword" ? "item field" : provider === "bitwarden" ? "JSON key" : "KV key";
  return (
    <fieldset className="min-w-0">
      <legend className="field-label">Field map <span className="field-opt">optional</span></legend>
      <p className="field-hint mt-0">
        {provider === "onepassword" ? "Item fields" : provider === "bitwarden" ? "Keys of the JSON value" : "KV keys"} default to the target kind's own names ({names.join(", ")}). Map a name to a different {keyWord} when the secret uses other names.
      </p>
      {Object.keys(map).length > 0 && (
        <div className="fieldmap-grid mt-2" role="group" aria-label="Field map">
          {Object.entries(map).map(([name, key]) => (
            <FieldMapRow key={name} name={name} value={key} keyWord={keyWord} onChange={(v) => { setFieldMap({ ...map, [name]: v }); }}
              onRemove={() => { setFieldMap(Object.fromEntries(Object.entries(map).filter(([n]) => n !== name))); }} />
          ))}
        </div>
      )}
      {free.length > 0 && (
        <div className="mt-2 flex gap-2">
          <select aria-label="Target field to map" className="field flex-1" value={newName} onChange={(e) => { setNewName(e.target.value); }}>
            <option value="">Add a mapping…</option>
            {free.map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
          <button type="button" className="btn" disabled={newName === ""} onClick={() => { setFieldMap({ ...map, [newName]: "" }); setNewName(""); }}>Map</button>
        </div>
      )}
      {problem && <p className="field-hint field-problem">{problem}</p>}
    </fieldset>
  );
}

function FieldMapRow({ name, value, keyWord, onChange, onRemove }: { name: string; value: string; keyWord: string; onChange: (v: string) => void; onRemove: () => void }) {
  return (
    <>
      <span className="mono text-[length:var(--fs-13)]">{name}</span>
      <input aria-label={`${keyWord === "KV key" ? "KV key" : keyWord.charAt(0).toUpperCase() + keyWord.slice(1)} for ${name}`} className="field mono" spellCheck={false} placeholder={keyWord} value={value} onChange={(e) => { onChange(e.target.value); }} />
      <button type="button" className="btn btn-ghost" aria-label={`Remove mapping for ${name}`} onClick={onRemove}>Remove</button>
    </>
  );
}

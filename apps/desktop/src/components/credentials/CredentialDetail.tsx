import { useEffect, useState, type ReactNode } from "react";
import { HudLabel } from "@mooring/ui";
import { ipc, type CredentialMeta, type CredentialRole, type ExternalRefTest, type KindSchema, type SecretSource, type SecretSourceTest } from "../../lib/ipc";
import { PROTOCOL_LABEL, accountSummary, schemaFor } from "../../lib/credentials";
import { fmtStamp } from "../../lib/format";
import { kindLabel } from "../../stores/credentials";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { openSettingsCard } from "../SyncBanner";
import { testText } from "../settings/SecretSourcesCard";
import { refTestSummary } from "./ExternalRefSection";
import { Fingerprint, KindBadge, MatrixStrip } from "./fields";
import { APPROLE_HINT, KIND_BLURB, PROVIDERS } from "./kindMeta";

const ROLE_TAG: Record<CredentialRole, string> = { primary: "", gateway: "gateway", become: "become" };

/**
 * Read-only card for one credential: what it is, where it can sign in, who uses it. Shown after a
 * save and when a row is picked; Edit opens the schema-driven form. Never a secret value, only the
 * names of the secrets that are stored.
 */
export function CredentialDetail({ meta, kinds, onEdit, onDelete }: {
  meta: CredentialMeta;
  kinds: KindSchema[];
  onEdit: () => void;
  onDelete: () => Promise<boolean>;
}) {
  const schema = schemaFor(kinds, meta.kind);
  const connections = useTree((s) => s.connections);
  const folders = useTree((s) => s.folders);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const usedConns = connections.filter((c) => c.credentialId === meta.id || c.gatewayCredentialId === meta.id || c.becomeCredentialId === meta.id);
  const usedFolders = folders.filter((f) => f.defaultCredentialId === meta.id);
  const account = accountSummary(meta);
  const secretLabels = meta.secretNames.map((n) => schema?.fields.find((f) => f.name === n)?.label ?? (n === "otp_seed" ? "TOTP seed" : n));
  // A reference signs in wherever the kind it resolves to does (credentialValidFor follows target_kind too).
  const target = meta.kind === "external_ref" && typeof meta.fields.target_kind === "string" ? schemaFor(kinds, meta.fields.target_kind as CredentialMeta["kind"]) : undefined;
  const protocols = (target ?? schema)?.protocols.flatMap((p) => p.roles.map((r) => ({ key: `${p.protocol}-${r}`, label: PROTOCOL_LABEL[p.protocol], role: r }))) ?? [];
  const consumerOnly = (schema?.consumers?.length ?? 0) > 0;

  return (
    <article className="cred-editor" aria-label={`${meta.name} details`}>
      <header className="cred-editor-head">
        <KindBadge kind={meta.kind} kinds={kinds} decorative />
        <div className="min-w-0 flex-1">
          <h2 className="m-display truncate text-[length:var(--fs-l)]">{meta.name}</h2>
          <p className="truncate text-[length:var(--fs-xs)] text-text-muted">{kindLabel(kinds, meta.kind)} · {KIND_BLURB[meta.kind]}</p>
        </div>
        {schema && <MatrixStrip schema={schema} />}
      </header>

      <div className="cred-editor-body">
        <div className="flex flex-wrap items-center gap-2">
          {meta.kind === "external_ref" && <RefTest id={meta.id} updatedAt={meta.updatedAt} />}
          {meta.kind === "vault_approle" && <ApproleTest id={meta.id} />}
          <button type="button" className="btn btn-primary" onClick={onEdit}>Edit</button>
          {confirm ? (
            <>
              <button
                type="button"
                className="btn btn-danger"
                disabled={busy}
                onClick={() => {
                  setBusy(true);
                  void onDelete().then((ok) => {
                    setBusy(false);
                    setConfirm(false);
                    if (!ok) setError("Could not delete the credential.");
                  });
                }}
              >
                Confirm delete
              </button>
              <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => { setConfirm(false); }}>Keep</button>
            </>
          ) : (
            <button type="button" className="btn btn-ghost btn-danger" onClick={() => { setConfirm(true); setError(null); }}>Delete</button>
          )}
          {error && <span role="alert" className="text-[length:var(--fs-s)] text-danger">{error}</span>}
        </div>
        {confirm && usedConns.length + usedFolders.length > 0 && (
          <p className="kind-note" role="note">
            {usedConns.length + usedFolders.length} connection{usedConns.length + usedFolders.length === 1 ? "" : "s"} or folder
            {usedConns.length + usedFolders.length === 1 ? "" : "s"} still reference this credential; they will ask at connect or fall
            back to the folder default.
          </p>
        )}

        <section className="cred-detail-section m-hud">
          <HudLabel>Credential</HudLabel>
          <dl className="prop-grid">
            <Prop k="Kind">{kindLabel(kinds, meta.kind)}</Prop>
            <Prop k="Account" mono>{account || <span className="text-text-faint">none</span>}</Prop>
            {meta.fingerprint && <Prop k="Fingerprint"><Fingerprint value={meta.fingerprint} /></Prop>}
            <Prop k="Secrets">
              {secretLabels.length > 0 ? `${secretLabels.join(", ")} (sealed)` : <span className="text-text-faint">none stored</span>}
            </Prop>
            <Prop k="Updated" mono>{fmtStamp(meta.updatedAt)}</Prop>
            <Prop k="Used by">
              <span className="tnum">{usedConns.length}</span> connection{usedConns.length === 1 ? "" : "s"}
              {usedFolders.length > 0 && <>, <span className="tnum">{usedFolders.length}</span> folder default{usedFolders.length === 1 ? "" : "s"}</>}
            </Prop>
          </dl>
        </section>

        <section className="cred-detail-section m-hud">
          <HudLabel>Signs in to</HudLabel>
          {protocols.length > 0 ? (
            <ul className="proto-chips" aria-label="Protocols">
              {protocols.map((p) => (
                <li key={p.key} className="proto-chip" data-role={p.role}>
                  {p.label}
                  {ROLE_TAG[p.role] && <span className="m-micro">{ROLE_TAG[p.role]}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[length:var(--fs-s)] text-text-muted">
              {consumerOnly ? "No connection. This kind is consumed by another part of Mooring (below)." : "No protocol supports this kind yet."}
            </p>
          )}
        </section>

        {meta.kind === "external_ref" && <ReferenceSection meta={meta} kinds={kinds} />}
        {meta.kind === "vault_approle" && <ApproleSection meta={meta} />}
        {meta.kind === "s3_access_key" && (
          <section className="kind-note flex items-center gap-3" role="note">
            <span className="flex-1">This access key is for vault sync only. Pick it in Settings → Vault sync; it never signs in to a connection.</span>
            <button type="button" className="btn" onClick={() => { openSettingsCard("sync-title"); }}>Open Vault sync</button>
          </section>
        )}
      </div>
    </article>
  );
}

/** Source and path of a Secret manager reference: where the secret lives, never what it holds. */
function ReferenceSection({ meta, kinds }: { meta: CredentialMeta; kinds: KindSchema[] }) {
  const sources = useSecretSources();
  const f = (k: string) => { const v = meta.fields[k]; return typeof v === "string" ? v : ""; };
  const provider = PROVIDERS.find((p) => p.value === f("provider"))?.label ?? f("provider");
  const source = sources?.find((s) => s.id === f("source"));
  const vault = f("provider") === "vault";
  const version = meta.fields.version;
  const map = meta.fields.field_map;
  const target = f("target_kind");
  return (
    <section className="cred-detail-section m-hud">
      <HudLabel>Reference</HudLabel>
      <dl className="prop-grid">
        <Prop k="Provider">{provider}</Prop>
        {vault && (
          <Prop k="Source">
            {sources === null ? "Loading…" : source ? <>{source.name} <span className="mono text-text-faint">{source.address}</span></> : <span className="text-danger">Unknown source — choose another in Edit</span>}
          </Prop>
        )}
        <Prop k="Path" mono>{f("reference")}</Prop>
        <Prop k="Resolves to">{target ? kindLabel(kinds, target as CredentialMeta["kind"]) : <span className="text-text-faint">not set</span>}</Prop>
        {vault && <Prop k="Version" mono>{typeof version === "number" ? version : <span className="text-text-faint">latest</span>}</Prop>}
        {map && typeof map === "object" && Object.keys(map).length > 0 && (
          <Prop k="Field map" mono>{Object.entries(map).map(([n, k]) => `${n} ← ${String(k)}`).join(", ")}</Prop>
        )}
      </dl>
      {vault && (
        <p className="field-hint mt-2">
          At connect time Mooring signs in to the source, reads the secret and drops it after the handshake. Sources are managed in{" "}
          <button type="button" className="cred-link underline" onClick={() => { openSettingsCard("sources-title"); }}>Settings → Secret sources</button>.
        </p>
      )}
    </section>
  );
}

/** The relationship an AppRole lives in: the secret sources that sign in with it, or how to create one. */
function ApproleSection({ meta }: { meta: CredentialMeta }) {
  const sources = useSecretSources();
  const using = sources?.filter((s) => s.credentialId === meta.id) ?? [];
  return (
    <section className="cred-detail-section m-hud">
      <HudLabel>Secret sources</HudLabel>
      {using.length > 0 ? (
        <ul className="space-y-1" aria-label="Secret sources signing in with this AppRole">
          {using.map((s) => (
            <li key={s.id} className="flex items-baseline gap-2 text-[length:var(--fs-s)]">
              <span className="text-text">{s.name}</span>
              <span className="mono truncate text-text-faint">{s.address}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[length:var(--fs-s)] text-text-muted">{sources === null ? "Loading…" : "No secret source signs in with this AppRole yet."}</p>
      )}
      <div className="kind-note mt-3 flex items-center gap-3" role="note">
        <span className="flex-1">A Vault AppRole never signs in to a connection. {APPROLE_HINT}</span>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => { openSettingsCard("sources-title", { kind: "add-secret-source", credentialId: meta.id }); }}
        >
          Create secret source
        </button>
      </div>
    </section>
  );
}

/** `credential_external_test` from the card: names only, never values. */
function RefTest({ id, updatedAt }: { id: string; updatedAt: string }) {
  const [test, setTest] = useState<ExternalRefTest | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { setTest(null); setErr(null); }, [id, updatedAt]);
  const run = async () => {
    setBusy(true);
    try {
      setTest(await ipc.credentialExternalTest({ credentialId: id }));
      setErr(null);
    } catch (e: unknown) {
      setTest(null);
      setErr(describeError(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <button type="button" className="btn" disabled={busy} onClick={() => void run()}>{busy ? "Testing…" : "Test"}</button>
      {err && <span role="alert" className="settings-err">{err}</span>}
      {test && <span role="status" aria-label="Reference test" className={test.ok ? "settings-ok" : "settings-err"}>{refTestSummary(test)}</span>}
    </>
  );
}

/** Test = sign in every secret source that uses this AppRole (`secret_source_test`). */
function ApproleTest({ id }: { id: string }) {
  const sources = useSecretSources();
  const using = sources?.filter((s) => s.credentialId === id) ?? [];
  const [results, setResults] = useState<{ name: string; test: SecretSourceTest }[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      setResults(await Promise.all(using.map(async (s) => ({ name: s.name, test: await ipc.secretSourceTest({ id: s.id }) }))));
      setErr(null);
    } catch (e: unknown) {
      setResults(null);
      setErr(describeError(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <button type="button" className="btn" disabled={busy || using.length === 0} title={using.length === 0 ? "No secret source uses this AppRole yet" : undefined} onClick={() => void run()}>
        {busy ? "Testing…" : "Test"}
      </button>
      {err && <span role="alert" className="settings-err">{err}</span>}
      {results?.map((r) => (
        <span key={r.name} role="status" className={r.test.ok ? "settings-ok" : "settings-err"}>{r.name}: {testText(r.test)}</span>
      ))}
    </>
  );
}

function useSecretSources(): SecretSource[] | null {
  const [sources, setSources] = useState<SecretSource[] | null>(null);
  useEffect(() => {
    let live = true;
    ipc.secretSourceList().then((l) => { if (live) setSources(l); }, () => { if (live) setSources([]); });
    return () => { live = false; };
  }, []);
  return sources;
}

function Prop({ k, mono, children }: { k: string; mono?: boolean; children: ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd className={mono ? "mono select-text" : ""}>{children}</dd>
    </>
  );
}

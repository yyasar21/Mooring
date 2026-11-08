import { useEffect, useState, type ReactNode } from "react";
import { SectionPanel, SectionTabs } from "../SectionTabs";
import { CredentialAuditPanel, UsedByPanel } from "./CredentialUsage";
import { HudLabel } from "@mooring/ui";
import { ENGINE_LABEL, SOURCE_KIND_LABEL, ipc, type CredentialMeta, type CredentialRole, type ExternalRefTest, type KindSchema, type SecretSource, type SecretSourceTest } from "../../lib/ipc";
import { engineOf, roleOf } from "../../lib/validate.refs";
import { useCredentials } from "../../stores/credentials";
import { PROTOCOL_LABEL, accountSummary, schemaFor } from "../../lib/credentials";
import { fmtStamp } from "../../lib/format";
import { kindLabel } from "../../stores/credentials";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { openSettingsCard } from "../SyncBanner";
import { testText } from "../settings/SecretSourcesCard";
import { refTestSummary } from "./ExternalRefSection";
import { TOOL_CHANGED } from "../../stores/errors";
import { Fingerprint, KindBadge, MatrixStrip } from "./fields";
import { SkKeyDetail } from "./SkKeyDetail";
import { SmartCardDetail } from "./SmartCard";
import { APPROLE_HINT, BWS_TOKEN_HINT, KIND_BLURB, PROVIDERS } from "./kindMeta";

const ROLE_TAG: Record<CredentialRole, string> = { primary: "", gateway: "gateway", become: "become", certificate: "certificate" };
/** Kinds that only sign a secret source in: the sources that use them, and a Test. */
const LOGIN_ONLY = new Set<CredentialMeta["kind"]>(["vault_approle", "bitwarden_access_token"]);

type DetailTab = "overview" | "usedby" | "audit";
const TABS: readonly DetailTab[] = ["overview", "usedby", "audit"];

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
  // L2: Overview | Used by | Audit. The view remounts this card per credential, so it opens on Overview.
  const [tab, setTab] = useState<DetailTab>("overview");
  const usedConns = connections.filter((c) => c.credentialId === meta.id || c.gatewayCredentialId === meta.id || c.becomeCredentialId === meta.id || c.certificateCredentialId === meta.id);
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
          <h2 className="m-display truncate text-[length:var(--fs-16)]">{meta.name}</h2>
          <p className="truncate text-[length:var(--fs-12)] text-text-muted">{kindLabel(kinds, meta.kind)} · {KIND_BLURB[meta.kind]}</p>
        </div>
        {schema && <MatrixStrip schema={schema} />}
      </header>

      <div className="cred-detail-actions">
        <div className="flex flex-wrap items-center gap-2">
          {meta.kind === "external_ref" && <RefTest id={meta.id} updatedAt={meta.updatedAt} engine={engineOf(meta.fields.engine)} />}
          {LOGIN_ONLY.has(meta.kind) && <ApproleTest id={meta.id} />}
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
          {error && <span role="alert" className="text-[length:var(--fs-13)] text-danger">{error}</span>}
        </div>
        {confirm && usedConns.length + usedFolders.length > 0 && (
          <p className="kind-note" role="note">
            {usedConns.length + usedFolders.length} connection{usedConns.length + usedFolders.length === 1 ? "" : "s"} or folder
            {usedConns.length + usedFolders.length === 1 ? "" : "s"} still reference this credential; they will ask at connect or fall
            back to the folder default.
          </p>
        )}
      </div>

      <SectionTabs
        base={`cred-${meta.id}`}
        label="Credential sections"
        tabs={TABS}
        labels={{ overview: "Overview", usedby: `Used by (${String(usedConns.length + usedFolders.length)})`, audit: "Audit" }}
        value={tab}
        onChange={setTab}
      />
      {tab === "usedby" && <SectionPanel base={`cred-${meta.id}`} tab="usedby" className="cred-tab"><UsedByPanel meta={meta} /></SectionPanel>}
      {tab === "audit" && <SectionPanel base={`cred-${meta.id}`} tab="audit" className="cred-tab"><CredentialAuditPanel meta={meta} /></SectionPanel>}
      {tab === "overview" && (
      <SectionPanel base={`cred-${meta.id}`} tab="overview" className="cred-editor-body">
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
            <p className="text-[length:var(--fs-13)] text-text-muted">
              {consumerOnly ? "No connection. This kind is consumed by another part of Mooring (below)." : "No protocol supports this kind yet."}
            </p>
          )}
        </section>

        {meta.kind === "external_ref" && <ReferenceSection meta={meta} kinds={kinds} />}
        {LOGIN_ONLY.has(meta.kind) && <ApproleSection meta={meta} />}
        {meta.kind === "ssh_sk_key" && <SkKeyDetail meta={meta} />}
        {meta.kind === "smart_card" && <SmartCardDetail meta={meta} />}
        {(meta.kind === "ssh_key" || meta.kind === "ssh_sk_key") && <CertificateSection id={meta.id} />}
        {meta.kind === "s3_access_key" && (
          <section className="kind-note flex items-center gap-3" role="note">
            <span className="flex-1">This access key is for vault sync only. Pick it in Settings → Vault sync; it never signs in to a connection.</span>
            <button type="button" className="btn" onClick={() => { openSettingsCard("sync-title"); }}>Open Vault sync</button>
          </section>
        )}
      </SectionPanel>
      )}
    </article>
  );
}

/** Source and path of a Secret manager reference: where the secret lives, never what it holds. */
function ReferenceSection({ meta, kinds }: { meta: CredentialMeta; kinds: KindSchema[] }) {
  const sources = useSecretSources();
  const f = (k: string) => { const v = meta.fields[k]; return typeof v === "string" ? v : ""; };
  const list = (k: string) => { const v = meta.fields[k]; return Array.isArray(v) ? v : []; };
  const provider = PROVIDERS.find((p) => p.value === f("provider"))?.label ?? f("provider");
  const source = sources?.find((s) => s.id === f("source"));
  const vault = f("provider") === "vault";
  const engine = vault ? engineOf(meta.fields.engine) : "kv2";
  const dynamic = engine !== "kv2";
  const version = meta.fields.version;
  const ttl = meta.fields.ttl;
  const map = meta.fields.field_map;
  const target = f("target_kind");
  return (
    <section className="cred-detail-section m-hud">
      <HudLabel>Reference</HudLabel>
      <dl className="prop-grid">
        <Prop k="Provider">{provider}</Prop>
        <Prop k="Source">
          {sources === null ? "Loading…" : source ? <>{source.name} <span className="mono text-text-faint">{source.address}</span></> : <span className="text-danger">Unknown source — choose another in Edit</span>}
        </Prop>
        {vault && <Prop k="Engine">{ENGINE_LABEL[engine]}</Prop>}
        <Prop k={dynamic ? "Role" : "Path"} mono>{f("reference")}</Prop>
        <Prop k="Resolves to">{target ? kindLabel(kinds, target as CredentialMeta["kind"]) : <span className="text-text-faint">not set</span>}</Prop>
        {vault && !dynamic && <Prop k="Version" mono>{typeof version === "number" ? version : <span className="text-text-faint">latest</span>}</Prop>}
        {list("principals").length > 0 && <Prop k="Principals" mono>{list("principals").join(", ")}</Prop>}
        {f("common_name") && <Prop k="Common name" mono>{f("common_name")}</Prop>}
        {list("alt_names").length > 0 && <Prop k="Alt names" mono>{list("alt_names").join(", ")}</Prop>}
        {f("username") && <Prop k="Login" mono>{f("username")}</Prop>}
        {(engine === "ssh_sign" || engine === "pki") && <Prop k="TTL" mono>{typeof ttl === "number" ? `${ttl} s` : <span className="text-text-faint">role default</span>}</Prop>}
        {engine === "database" && <Prop k="Lease">Renewed while the session is open, revoked when it closes</Prop>}
        {map && typeof map === "object" && Object.keys(map).length > 0 && (
          <Prop k="Field map" mono>{Object.entries(map).map(([n, k]) => `${n} ← ${String(k)}`).join(", ")}</Prop>
        )}
      </dl>
      <p className="field-hint mt-2">
        {engine === "pki"
          ? "PKI can only be tested for now: no connection signs in with an X.509 certificate from Vault yet. "
          : engine === "ssh_sign"
            ? "Attach this reference to an SSH connection as its certificate; Vault signs the connection's SSH key at each connect. "
            : `At connect time Mooring signs in to the ${source ? SOURCE_KIND_LABEL[source.kind] : "secret"} source, ${dynamic ? "asks for fresh values" : "reads the secret"} and drops it after the handshake. `}
        Sources are managed in{" "}
        <button type="button" className="cred-link underline" onClick={() => { openSettingsCard("sources-title"); }}>Settings → Secret sources</button>.
      </p>
    </section>
  );
}

/**
 * ADR-0026 §1: an SSH key that a connection certifies with a Vault `ssh_sign` reference
 * (secondary role `certificate`). One line per connection; the role name, never a secret.
 */
function CertificateSection({ id }: { id: string }) {
  const connections = useTree((s) => s.connections);
  const creds = useCredentials((s) => s.items);
  const rows = connections
    .filter((c) => c.protocol === "ssh" && (c.effectiveCredentialId ?? c.credentialId) === id && c.certificateCredentialId)
    .map((c) => ({ c, ref: creds.find((x) => x.id === c.certificateCredentialId) }));
  if (rows.length === 0) return null;
  return (
    <section className="cred-detail-section" aria-label="Certificate">
      <ul className="cert-roles">
        {rows.map(({ c, ref }) => {
          const role = ref && typeof ref.fields.reference === "string" ? roleOf(ref.fields.reference) : null;
          return (
            <li key={c.id}>
              <span className="text-text-muted">Certificate: </span>
              {role ? <>signed by Vault role <span className="mono">{role}</span> at connect</> : "the certificate reference was deleted"}
              <span className="text-text-muted"> · {c.name}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** The relationship an AppRole lives in: the secret sources that sign in with it, or how to create one. */
function ApproleSection({ meta }: { meta: CredentialMeta }) {
  const sources = useSecretSources();
  const bws = meta.kind === "bitwarden_access_token";
  const what = bws ? "access token" : "AppRole";
  const using = sources?.filter((s) => s.credentialId === meta.id) ?? [];
  return (
    <section className="cred-detail-section m-hud">
      <HudLabel>Secret sources</HudLabel>
      {using.length > 0 ? (
        <ul className="space-y-1" aria-label={`Secret sources signing in with this ${what}`}>
          {using.map((s) => (
            <li key={s.id} className="flex items-baseline gap-2 text-[length:var(--fs-13)]">
              <span className="text-text">{s.name}</span>
              <span className="mono truncate text-text-faint">{s.address}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[length:var(--fs-13)] text-text-muted">{sources === null ? "Loading…" : `No secret source signs in with this ${what} yet.`}</p>
      )}
      <div className="kind-note mt-3 flex items-center gap-3" role="note">
        <span className="flex-1">{bws ? `A Bitwarden access token never signs in to a connection. ${BWS_TOKEN_HINT}` : `A Vault AppRole never signs in to a connection. ${APPROLE_HINT}`}</span>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => { openSettingsCard("sources-title", { kind: "add-secret-source", credentialId: meta.id, ...(bws ? { sourceKind: "bitwarden" as const } : {}) }); }}
        >
          Create secret source
        </button>
      </div>
    </section>
  );
}

/** L-50: the bws binary changed; the next step is to test (and so re-trust) the source. */
function ToolChangedNote() {
  return (
    <div className="bws-missing" role="note" aria-label="bws changed">
      <strong>{TOOL_CHANGED.title}</strong>. {TOOL_CHANGED.next}{" "}
      <button type="button" className="btn btn-sm" onClick={() => { openSettingsCard("sources-title"); }}>Open Secret sources</button>
    </div>
  );
}

/** `credential_external_test` from the card: names only, never values. */
function RefTest({ id, updatedAt, engine }: { id: string; updatedAt: string; engine: ReturnType<typeof engineOf> }) {
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
      {test && <span role="status" aria-label="Reference test" className={test.ok ? "settings-ok" : "settings-err"}>{refTestSummary(test, engine)}</span>}
      {test?.error === "secret.tool_changed" && <ToolChangedNote />}
    </>
  );
}

/** Test = sign in every secret source that uses this AppRole (`secret_source_test`). */
function ApproleTest({ id }: { id: string }) {
  const sources = useSecretSources();
  const using = sources?.filter((s) => s.credentialId === id) ?? [];
  const [results, setResults] = useState<{ name: string; kind: SecretSource["kind"]; test: SecretSourceTest }[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      setResults(await Promise.all(using.map(async (s) => ({ name: s.name, kind: s.kind, test: await ipc.secretSourceTest({ id: s.id }) }))));
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
      <button type="button" className="btn" disabled={busy || using.length === 0} title={using.length === 0 ? "No secret source uses this credential yet" : undefined} onClick={() => void run()}>
        {busy ? "Testing…" : "Test"}
      </button>
      {err && <span role="alert" className="settings-err">{err}</span>}
      {results?.map((r) => (
        <span key={r.name} role="status" className={r.test.ok ? "settings-ok" : "settings-err"}>{r.name}: {testText(r.test, r.kind)}</span>
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

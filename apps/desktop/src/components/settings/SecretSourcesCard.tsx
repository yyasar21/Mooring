import { useEffect, useState } from "react";
import { SOURCE_KIND_LABEL, ipc, type SecretSource, type SecretSourceKind, type SecretSourceTest } from "../../lib/ipc";
import { useCredentials } from "../../stores/credentials";
import { useToasts } from "../../stores/toast";
import { useUi } from "../../stores/ui";
import { describeCode, describeError } from "../../stores/errors";
import { SecretSourceDialog } from "./SecretSourceDialog";
import { SettingsCard } from "./Toggle";
import { useOidcLogin, type OidcPhase } from "./useOidcLogin";
import { BwsPathList } from "./SourceProviderFields";

const METHOD_LABEL = { token: "Token", approle: "AppRole", oidc: "OIDC" } as const;

export function ttlText(seconds: number | null): string {
  if (seconds === null) return "no TTL";
  if (seconds < 90) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  const h = seconds / 3600;
  return `${Number.isInteger(h) ? h : h.toFixed(1)} h`;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/**
 * One line for a `secret_source_test` result: method, TTL, renewable, policies (Vault), or the
 * number of vaults (1Password) / projects (Bitwarden); or the error and its category. Names and
 * counts only, never a value.
 */
export function testText(t: SecretSourceTest, kind: SecretSourceKind = "vault"): string {
  const why = t.category ? ` (${t.category.replace(/_/g, " ")})` : "";
  const reason = (t.error ? describeCode(t.error) : "no reason given").replace(/\.$/, "");
  if (kind === "onepassword") {
    return t.ok ? `Connect answered: the token sees ${plural(t.policiesCount, "vault", "vaults")}.` : `1Password Connect test failed${why}: ${reason}.`;
  }
  if (kind === "bitwarden") {
    return t.ok ? `bws ran: the access token sees ${plural(t.policiesCount, "project", "projects")}.` : `Bitwarden test failed${why}: ${reason}.`;
  }
  if (t.ok) return `Signed in with ${METHOD_LABEL[t.method]}: token TTL ${ttlText(t.ttlSeconds)}, ${t.renewable ? "renewable" : "not renewable"}, ${t.policiesCount} polic${t.policiesCount === 1 ? "y" : "ies"}.`;
  return `Sign-in with ${METHOD_LABEL[t.method]} failed${why}: ${reason}.`;
}

function oidcText(p: OidcPhase, id: string): { text: string; tone: "ok" | "err" | "note" } | null {
  if (p.kind === "idle" || p.sourceId !== id) return null;
  if (p.kind === "waiting") return { text: "Sign-in window open. Finish signing in with your identity provider; this closes on its own.", tone: "note" };
  if (p.kind === "testing") return { text: "Signed in. Checking the token…", tone: "note" };
  if (p.kind === "failed") return { text: p.reason, tone: "err" };
  return { text: testText(p.test), tone: p.test.ok ? "ok" : "err" };
}

/** Settings → Secret sources (ADR-0016): the Vault / OpenBao servers that external references resolve from. */
export function SecretSourcesCard() {
  const [rows, setRows] = useState<SecretSource[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [tests, setTests] = useState<Record<string, SecretSourceTest>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ source?: SecretSource; credentialId?: string | null; kind?: SecretSourceKind } | null>(null);
  // The source just saved stays highlighted in the list (U0), like a selected row elsewhere.
  const [selected, setSelected] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const creds = useCredentials((s) => s.items);
  const refs = creds.filter((c) => c.kind === "external_ref");
  const { phase, begin, clear } = useOidcLogin();

  const reload = async () => {
    try {
      setRows(await ipc.secretSourceList());
      setError(null);
    } catch (e: unknown) {
      setError(describeError(e));
    }
  };
  useEffect(() => { void reload(); }, []);
  // An AppRole's "Create secret source" (U0) lands here: open the form with that credential chosen.
  useEffect(() => {
    const intent = useUi.getState().takeSettingsIntent();
    if (intent?.kind === "add-secret-source") setEditing({ credentialId: intent.credentialId, ...(intent.sourceKind ? { kind: intent.sourceKind } : {}) });
  }, []);
  useEffect(() => {
    if (!selected || !rows?.some((r) => r.id === selected)) return;
    const el = document.getElementById(`source-${selected}`);
    // jsdom has no scrollIntoView; the guard keeps tests quiet without hiding a real failure.
    if (el && "scrollIntoView" in el) el.scrollIntoView({ block: "nearest" });
  }, [selected, rows]);

  const run = async (id: string, fn: () => Promise<void>) => {
    setBusy(id);
    setStatus(null);
    try {
      await fn();
      setError(null);
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(null);
    }
  };
  const forget = (id: string) => { setTests((t) => Object.fromEntries(Object.entries(t).filter(([k]) => k !== id))); };
  const test = (id: string) => run(id, async () => {
    clear();
    const r = await ipc.secretSourceTest({ id });
    setTests((t) => ({ ...t, [id]: r }));
  });
  const revoke = (s: SecretSource) => run(s.id, async () => {
    await ipc.secretSourceRevoke({ id: s.id });
    clear();
    forget(s.id);
    setStatus(s.authMethod === "token" ? `Forgot the cached token of ${s.name}.` : `Revoked and forgot the token of ${s.name}. The next use signs in again.`);
  });
  const remove = (s: SecretSource) => run(s.id, async () => {
    await ipc.secretSourceDelete({ id: s.id });
    setConfirm(null);
    setStatus(`Deleted ${s.name}.`);
    await reload();
  });

  return (
    <SettingsCard title="Secret sources" kicker="External secrets" labelledBy="sources-title">
      <div className="settings-body">
        <p className="field-hint mt-0">
          Vault or OpenBao, 1Password Connect and Bitwarden Secrets Manager servers that "Secret manager reference" credentials resolve
          from at connect time. Secrets are fetched for the handshake only and never cached; sign-ins live in memory and end when the vault locks.
        </p>
        {error && <p role="alert" className="settings-err">{error}</p>}
        {status && <p role="status" className="settings-ok">{status}</p>}
        {rows === null ? (
          <p className="field-hint" role="status">Loading…</p>
        ) : rows.length === 0 ? (
          <div className="trust-empty">
            <span className="m-micro">No secret sources</span>
            <span className="field-hint">Add a server, then create a credential of kind "Secret manager reference" that points at it.</span>
          </div>
        ) : (
          <ul className="trust-list" aria-label="Secret sources">
            {rows.map((s) => {
              const cred = s.credentialId ? creds.find((c) => c.id === s.credentialId) : null;
              const used = refs.filter((r) => r.fields.source === s.id).length;
              const t = tests[s.id];
              const o = oidcText(phase, s.id);
              const isBusy = busy === s.id;
              return (
                <li key={s.id} id={`source-${s.id}`} className="source-row" aria-label={s.name} aria-current={s.id === selected || undefined} data-selected={s.id === selected || undefined}>
                  <div className="min-w-0">
                    <p className="trust-target">
                      <span className="text-text">{s.name}</span>
                      <span className="source-kind">{SOURCE_KIND_LABEL[s.kind]}</span>
                      {s.kind === "vault" && <span className="trust-names">{METHOD_LABEL[s.authMethod]}</span>}
                      {s.options.allowHttp && <span className="trust-names text-danger">http</span>}
                    </p>
                    <p className="trust-fp mono select-text">{s.address}{s.namespace ? ` · ns ${s.namespace}` : ""}</p>
                    <p className="field-hint">
                      {s.authMethod === "oidc" ? `Role ${s.oidcRole ?? ""} on ${s.authMount}` : cred ? `Signs in with ${cred.name}` : "Login credential missing"}
                      {` · used by ${used} reference${used === 1 ? "" : "s"}`}
                    </p>
                    {s.kind === "bitwarden" && <p className="field-hint">bws: <span className="mono">{s.options.bwsPath ?? "first one found"}</span> · own TLS, not pinned by Mooring</p>}
                    {t && !o && <p role="status" className={t.ok ? "settings-ok" : "settings-err"}>{testText(t, s.kind)}</p>}
                    {t?.error === "secret.tool_missing" && (
                      <div className="bws-missing" role="note">
                        bws was not found{s.options.bwsPath ? ` at ${s.options.bwsPath}` : " at any of these locations"}. Install the Bitwarden
                        Secrets Manager CLI there, then test again.
                        {!s.options.bwsPath && <BwsPathList chosen={null} />}
                      </div>
                    )}
                    {o && <p role={o.tone === "err" ? "alert" : "status"} className={o.tone === "ok" ? "settings-ok" : o.tone === "err" ? "settings-err" : "field-hint"}>{o.text}</p>}
                  </div>
                  <div className="source-actions">
                    {s.authMethod === "oidc" && (
                      <button type="button" className="btn btn-primary" disabled={isBusy || (phase.kind === "waiting" && phase.sourceId === s.id)} onClick={() => void begin(s.id)}>Sign in…</button>
                    )}
                    <button type="button" className="btn" disabled={isBusy} onClick={() => void test(s.id)}>Test</button>
                    <button type="button" className="btn btn-ghost" disabled={isBusy} title="Revoke (AppRole, OIDC) or forget (token) the cached sign-in" onClick={() => void revoke(s)}>
                      {s.authMethod === "token" ? "Forget" : "Revoke"}
                    </button>
                    <button type="button" className="btn btn-ghost" disabled={isBusy} onClick={() => { setEditing({ source: s }); }}>Edit…</button>
                    {confirm === s.id ? (
                      <button type="button" className="btn btn-danger" disabled={isBusy} onClick={() => void remove(s)}>Confirm delete</button>
                    ) : (
                      <button type="button" className="btn btn-ghost btn-danger" disabled={isBusy} aria-label={`Delete ${s.name}`} onClick={() => { setConfirm(s.id); setStatus(null); }}>Delete</button>
                    )}
                  </div>
                  {confirm === s.id && used > 0 && (
                    <p className="settings-warn" role="note">
                      {used} credential{used === 1 ? "" : "s"} still reference this source, so Mooring will refuse the deletion. Point them at another
                      source or delete them first.
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        <div className="settings-foot">
          <span className="field-hint flex-1">OIDC sign-ins open an isolated window; the redirect is intercepted, no port is opened.</span>
          <button type="button" className="btn btn-primary" onClick={() => { setEditing({}); }}>Add source…</button>
        </div>
      </div>
      {editing && (
        <SecretSourceDialog source={editing.source} initialCredentialId={editing.credentialId ?? null} initialKind={editing.kind ?? "vault"} onClose={() => { setEditing(null); }}
          onSaved={(s) => {
            setEditing(null);
            setSelected(s.id);
            useToasts.getState().push("Secret source saved", { detail: s.name });
            forget(s.id);
            setStatus(editing.source ? `Saved ${s.name}. The cached token was forgotten.` : `Added ${s.name}.`);
            void reload();
          }} />
      )}
    </SettingsCard>
  );
}

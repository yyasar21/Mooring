import { useEffect, useState } from "react";
import { ipc, type SecretSource, type SecretSourceTest } from "../../lib/ipc";
import { useCredentials } from "../../stores/credentials";
import { describeCode, describeError } from "../../stores/errors";
import { SecretSourceDialog } from "./SecretSourceDialog";
import { SettingsCard } from "./Toggle";
import { useOidcLogin, type OidcPhase } from "./useOidcLogin";

const METHOD_LABEL = { token: "Token", approle: "AppRole", oidc: "OIDC" } as const;

export function ttlText(seconds: number | null): string {
  if (seconds === null) return "no TTL";
  if (seconds < 90) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  const h = seconds / 3600;
  return `${Number.isInteger(h) ? h : h.toFixed(1)} h`;
}

/** One line for a `secret_source_test` result: method, TTL, renewable, policies; or the error and its category. */
export function testText(t: SecretSourceTest): string {
  if (t.ok) return `Signed in with ${METHOD_LABEL[t.method]}: token TTL ${ttlText(t.ttlSeconds)}, ${t.renewable ? "renewable" : "not renewable"}, ${t.policiesCount} polic${t.policiesCount === 1 ? "y" : "ies"}.`;
  const why = t.category ? ` (${t.category.replace(/_/g, " ")})` : "";
  return `Sign-in with ${METHOD_LABEL[t.method]} failed${why}: ${t.error ? describeCode(t.error) : "no reason given"}.`;
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
  const [editing, setEditing] = useState<{ source?: SecretSource } | null>(null);
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
          Vault or OpenBao servers that "Secret manager reference" credentials resolve from at connect time. Secrets are fetched for the
          handshake only and never cached; the sign-in token lives in memory and is revoked when the vault locks.
        </p>
        {error && <p role="alert" className="settings-err">{error}</p>}
        {status && <p role="status" className="settings-ok">{status}</p>}
        {rows === null ? (
          <p className="field-hint" role="status">Loading…</p>
        ) : rows.length === 0 ? (
          <div className="trust-empty">
            <span className="m-micro">No secret sources</span>
            <span className="field-hint">Add a Vault server, then create a credential of kind "Secret manager reference" that points at it.</span>
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
                <li key={s.id} className="source-row" aria-label={s.name}>
                  <div className="min-w-0 flex-1">
                    <p className="trust-target">
                      <span className="text-text">{s.name}</span>
                      <span className="trust-names">{METHOD_LABEL[s.authMethod]}</span>
                      {s.options.allowHttp && <span className="trust-names text-danger">http</span>}
                    </p>
                    <p className="trust-fp mono select-text">{s.address}{s.namespace ? ` · ns ${s.namespace}` : ""}</p>
                    <p className="field-hint">
                      {s.authMethod === "oidc" ? `Role ${s.oidcRole ?? ""} on ${s.authMount}` : cred ? `Signs in with ${cred.name}` : "Login credential missing"}
                      {` · used by ${used} reference${used === 1 ? "" : "s"}`}
                    </p>
                    {t && !o && <p role="status" className={t.ok ? "settings-ok" : "settings-err"}>{testText(t)}</p>}
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
                    <p className="settings-warn col-span-full" role="note">
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
        <SecretSourceDialog source={editing.source} onClose={() => { setEditing(null); }}
          onSaved={(s) => {
            setEditing(null);
            forget(s.id);
            setStatus(editing.source ? `Saved ${s.name}. The cached token was forgotten.` : `Added ${s.name}.`);
            void reload();
          }} />
      )}
    </SettingsCard>
  );
}

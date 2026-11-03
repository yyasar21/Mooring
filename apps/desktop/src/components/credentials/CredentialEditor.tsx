import { useEffect, useMemo, useRef, useState } from "react";
import { HudLabel } from "@mooring/ui";
import type { CredentialKind, CredentialMeta, KindSchema } from "../../lib/ipc";
import { OTP_SEED_SCHEMA, detectKind, looksLikeDomainAccount } from "../../lib/credentials";
import { useCredentials } from "../../stores/credentials";
import {
  OTP_SEED,
  accountField,
  buildCreateSecrets,
  buildFields,
  buildReplace,
  enumOptions,
  initialState,
  plainFields,
  secretFields,
  validate,
  wipeSecrets,
  withAccount,
  withSecretTyped,
  type FormState,
  type SecretMode,
} from "./formModel";
import { AccountField, DerivedReadout, KindBadge, MatrixStrip, OtpSection, PlainField, SecretField } from "./fields";
import { KIND_BLURB, PROVIDERS } from "./kindMeta";
import { usePublicKeyFingerprint } from "./usePublicKeyFingerprint";

export interface Seed {
  name?: string;
  account?: string;
  /** A pasted blob that picked this kind; it goes straight into `field`'s input. */
  paste?: { field: string; text: string };
}

/**
 * Create or edit one credential. The form is generated from the served KindSchema. Secrets are
 * write-only: inputs are uncontrolled, read once on submit and wiped before the IPC call returns.
 */
export function CredentialEditor({
  schema,
  kinds,
  meta,
  seed,
  onDone,
  onCancel,
  onSwitchKind,
}: {
  schema: KindSchema;
  kinds: KindSchema[];
  meta?: CredentialMeta;
  seed?: Seed;
  onDone: (saved: CredentialMeta) => void;
  onCancel: () => void;
  /** New credentials only: a paste detected another kind; reopen the form as that kind. */
  onSwitchKind: (kind: CredentialKind, seed: Seed) => void;
}) {
  const editing = meta !== undefined;
  const [s, setS] = useState<FormState>(() => {
    let st = initialState(schema, meta);
    if (seed?.name) st = { ...st, name: seed.name };
    if (seed?.account) st = withAccount(st, schema, seed.account);
    return st;
  });
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputs = useRef(new Map<string, HTMLInputElement | HTMLTextAreaElement>());
  const register = (name: string, el: HTMLInputElement | HTMLTextAreaElement | null) => {
    if (el) inputs.current.set(name, el);
    else inputs.current.delete(name);
  };
  const read = (name: string) => inputs.current.get(name)?.value ?? "";

  const problems = useMemo(() => validate(schema, s, meta), [schema, s, meta]);
  const acct = accountField(schema);
  const pubFp = usePublicKeyFingerprint(s.values.public_key ?? "");

  // A blob pasted on the picker lands in its field once the input exists, then is forgotten.
  const pasted = useRef(seed?.paste);
  useEffect(() => {
    const p = pasted.current;
    pasted.current = undefined;
    const el = p ? inputs.current.get(p.field) : undefined;
    const f = schema.fields.find((x) => x.name === p?.field);
    if (!p || !el || !f) return;
    el.value = p.text;
    setS((cur) => withSecretTyped(cur, f, p.text));
    el.focus();
  }, [schema]);

  const set = (patch: Partial<FormState>) => { setS((cur) => ({ ...cur, ...patch })); };
  const setValue = (name: string, v: string) => { setS((cur) => ({ ...cur, values: { ...cur.values, [name]: v } })); };
  const setMode = (name: string, m: SecretMode) => {
    setS((cur) => {
      const next = { ...cur, mode: { ...cur.mode, [name]: m } };
      return m === "replace" ? next : { ...next, secretInfo: { ...next.secretInfo, [name]: { filled: false, bytes: 0, problem: null } } };
    });
  };

  /** New credentials: a key, certificate or kubeconfig pasted anywhere picks its own kind. */
  const onPaste = (text: string): boolean => {
    if (editing) return false;
    const d = detectKind(text);
    if (!d || d.kind === schema.kind) return false;
    onSwitchKind(d.kind, { name: s.name, paste: { field: d.field, text } });
    return true;
  };

  function wipeInputs() {
    for (const el of inputs.current.values()) el.value = "";
  }

  async function submit() {
    setTried(true);
    if (Object.keys(problems).length > 0) return;
    const store = useCredentials.getState();
    const fields = buildFields(schema, s);
    const name = s.name.trim();
    setBusy(true);
    let saved: CredentialMeta | null = null;
    if (meta) {
      const { set: setSecrets, clear } = buildReplace(schema, s, meta, read);
      wipeInputs();
      setS((cur) => wipeSecrets(cur));
      // Secrets first: if a replacement is refused, the plain fields are left as they were.
      const ok = (await store.replaceSecrets(meta.id, setSecrets, clear)) && (await store.updateFields(meta.id, name, fields));
      saved = ok ? (useCredentials.getState().items.find((c) => c.id === meta.id) ?? null) : null;
    } else {
      const secrets = buildCreateSecrets(schema, s, read);
      wipeInputs();
      setS((cur) => wipeSecrets(cur));
      saved = await store.create({ name, kind: schema.kind, fields, secrets });
    }
    setBusy(false);
    if (saved) onDone(saved);
    else setError(useCredentials.getState().error ?? "Could not save the credential.");
  }

  const show = (name: string) => (tried ? problems[name] : undefined);
  const provider = PROVIDERS.find((p) => p.value === s.values.provider);
  const legacyAccount = editing && schema.kind === "user_password" && looksLikeDomainAccount(s.values.username ?? "");

  return (
    <form
      className="cred-editor"
      autoComplete="off"
      aria-label={editing ? `Edit ${meta.name}` : `New ${schema.label}`}
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <header className="cred-editor-head">
        <KindBadge kind={schema.kind} kinds={kinds} decorative />
        <div className="min-w-0 flex-1">
          <h2 className="m-display truncate text-[length:var(--fs-l)]">{editing ? meta.name : `New ${schema.label}`}</h2>
          <p className="truncate text-[length:var(--fs-xs)] text-text-muted">{KIND_BLURB[schema.kind]}</p>
        </div>
        <MatrixStrip schema={schema} />
      </header>

      <div className="cred-editor-body">
        <div className="max-w-[520px]">
          <label className="field-label" htmlFor="cred-name">Name</label>
          <input
            id="cred-name"
            className="field"
            maxLength={200}
            value={s.name}
            aria-invalid={show("name") ? true : undefined}
            onChange={(e) => { set({ name: e.target.value }); }}
          />
          {show("name") && <p className="field-hint field-problem">{show("name")}</p>}
        </div>

        {schema.kind === "prompt" && (
          <p className="kind-note" role="note">
            Nothing secret is stored. When a connection that uses this credential opens, Mooring asks for the account and
            password and passes them to the handshake only. Fill in a username or domain here to pre-fill that question;
            a connection can override both.
          </p>
        )}
        {schema.kind === "external_ref" && (
          <p className="kind-note" role="note">
            Only the reference is stored. Resolving it from {provider?.label ?? "the provider"} arrives in a later release;
            until then, connecting with it reports that the kind is not supported yet.
          </p>
        )}
        {legacyAccount && (
          <div className="kind-note flex items-center gap-3" role="note">
            <span className="flex-1">
              This username looks like a domain account. It is sent exactly as typed. A domain account lets Mooring send
              the user and domain separately, which NLA and NTLM expect.
            </span>
            <button
              type="button"
              className="btn"
              onClick={() => { onSwitchKind("domain_user", { name: `${s.name} (domain)`, account: s.values.username ?? "" }); }}
            >
              Convert to domain user
            </button>
          </div>
        )}

        {(acct || plainFields(schema).length > 0) && <section className="space-y-3">
          <HudLabel>{acct || schema.fields.some((f) => !f.secret && /^(username|user|upn)$/.test(f.name)) ? "Account" : "Settings"}</HudLabel>
          <div className="cred-grid">
            {acct && (
              <div className="col-span-full">
                <AccountField
                  f={acct}
                  value={s.account}
                  onChange={(v) => { setS((cur) => withAccount(cur, schema, v)); }}
                  problem={problems[acct.name]}
                  showProblem={tried || s.account.trim() !== ""}
                />
              </div>
            )}
            {plainFields(schema).map((f) => (
              <div key={f.name} className={f.multiline ? "col-span-full" : undefined}>
                <PlainField
                  f={f}
                  value={s.values[f.name] ?? ""}
                  onChange={(v) => { setValue(f.name, v); }}
                  problem={tried || s.values[f.name] ? problems[f.name] : undefined}
                  options={enumOptions(f, s, meta)}
                  kinds={kinds}
                  context={s.values}
                />
                {f.name === "public_key" && pubFp && (
                  <p className="field-hint">Public key fingerprint <span className="mono text-text">{pubFp}</span></p>
                )}
              </div>
            ))}
          </div>
        </section>}

        {secretFields(schema).length > 0 && (
          <section className="space-y-3">
            <HudLabel>Secrets</HudLabel>
            <p className="text-[length:var(--fs-xs)] text-text-faint">
              Sealed one by one in the vault. Mooring never shows them again; you can replace or clear them.
            </p>
            {secretFields(schema).map((f) => (
              <SecretField
                key={f.name}
                f={f}
                editing={editing}
                stored={meta?.secretNames.includes(f.name) ?? false}
                mode={s.mode[f.name] ?? "keep"}
                onMode={(m) => { setMode(f.name, m); }}
                info={s.secretInfo[f.name]}
                onTyped={(v) => { setS((cur) => withSecretTyped(cur, f, v)); }}
                {...(f.multiline ? { onPaste } : {})}
                register={register}
                showProblem={tried}
              />
            ))}
            <DerivedReadout meta={meta} />
            {!editing && (schema.kind === "ssh_key" || schema.kind === "x509") && (
              <p className="field-hint">The SHA256 fingerprint is computed when you save.</p>
            )}
          </section>
        )}

        {schema.supportsOtp && (
          <OtpSection
            on={s.otpOn}
            onToggle={(on) => { set({ otpOn: on }); }}
            settings={s.otp}
            onSettings={(otp) => { set({ otp }); }}
            editing={editing}
            stored={meta?.secretNames.includes(OTP_SEED) ?? false}
            mode={s.mode[OTP_SEED] ?? "keep"}
            onMode={(m) => { setMode(OTP_SEED, m); }}
            info={s.secretInfo[OTP_SEED]}
            onTyped={(v) => { setS((cur) => withSecretTyped(cur, OTP_SEED_SCHEMA, v)); }}
            register={register}
            showProblem={tried}
          />
        )}
      </div>

      <footer className="cred-editor-foot">
        <p role="alert" className="min-w-0 flex-1 truncate text-[length:var(--fs-s)] text-danger">
          {error ?? (tried && Object.keys(problems).length > 0 ? "Fix the highlighted fields." : "")}
        </p>
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {editing ? "Save credential" : "Create credential"}
        </button>
      </footer>
    </form>
  );
}

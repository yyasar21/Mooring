// Field renderers for the schema-driven credential form. Each renders from a FieldSchema; none
// knows which kind it belongs to. Secret inputs are uncontrolled: their value lives only in the
// DOM element until submit, and React state learns only "filled / bytes / problem".
import { useId } from "react";
import type { CredentialKind, CredentialMeta, FieldSchema, KindSchema, OtpSettings } from "../../lib/ipc";
import { CREDENTIAL_KINDS } from "../../lib/ipc";
import { OTP_SEED_SCHEMA, formatBytes, isAccountError, parseAccount } from "../../lib/credentials";
import { kindLabel } from "../../stores/credentials";
import { KIND_CODE, MATRIX, PROVIDERS } from "./kindMeta";
import type { SecretInfo, SecretMode } from "./formModel";

export type Register = (name: string, el: HTMLInputElement | HTMLTextAreaElement | null) => void;

// ---------- badges and readouts ----------

/** Bevelled kind code. `decorative` when the kind's label is already in the surrounding text. */
export function KindBadge({ kind, kinds, decorative = false }: { kind: CredentialKind; kinds: KindSchema[]; decorative?: boolean }) {
  return decorative ? (
    <span className="kind-badge" aria-hidden>
      {KIND_CODE[kind]}
    </span>
  ) : (
    <span className="kind-badge" title={kindLabel(kinds, kind)} role="img" aria-label={kindLabel(kinds, kind)}>
      {KIND_CODE[kind]}
    </span>
  );
}

/** Six protocol cells: lit = valid sign-in, outlined = secondary role only, dim = not usable. */
export function MatrixStrip({ schema }: { schema: KindSchema }) {
  return (
    <span className="matrix-strip" aria-hidden>
      {MATRIX.map(({ protocol, code }) => {
        const roles = schema.protocols.find((p) => p.protocol === protocol)?.roles ?? [];
        const state = roles.includes("primary") ? "primary" : roles.length > 0 ? "role" : "none";
        return (
          <span key={protocol} className="matrix-cell" data-state={state}>
            {code}
          </span>
        );
      })}
    </span>
  );
}

export function Fingerprint({ value }: { value: string }) {
  const [algo, rest] = value.includes(":") ? [value.slice(0, value.indexOf(":") + 1), value.slice(value.indexOf(":") + 1)] : ["", value];
  return (
    <span className="fp mono select-text" title={value}>
      <span className="text-text-faint">{algo}</span>
      {rest}
    </span>
  );
}

// ---------- plain fields ----------

const OPTION_LABEL: Record<string, string> = {
  netbios: "NetBIOS",
  upn: "UPN",
  vault: "Vault",
  onepassword: "1Password",
  bitwarden: "Bitwarden",
};

function optionLabel(v: string, kinds: KindSchema[]): string {
  if ((CREDENTIAL_KINDS as readonly string[]).includes(v)) return kindLabel(kinds, v as CredentialKind);
  return OPTION_LABEL[v] ?? v;
}

export function PlainField({
  f,
  value,
  onChange,
  problem,
  options,
  kinds,
  context,
}: {
  f: FieldSchema;
  value: string;
  onChange: (v: string) => void;
  problem: string | undefined;
  options: string[];
  kinds: KindSchema[];
  /** Values of sibling fields, for placeholders that depend on them (provider → reference). */
  context: Record<string, string>;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const provider = f.name === "reference" ? PROVIDERS.find((p) => p.value === context.provider) : undefined;
  const placeholder = provider?.placeholder ?? f.placeholder;
  const hint = problem ?? provider?.hint;
  const label = (
    <label className="field-label" htmlFor={id}>
      {f.label}
      {!f.required && <span className="field-opt">optional</span>}
    </label>
  );

  if (f.validation.format === "enum") {
    // Fixed small choices are a segmented control; derived lists (contexts) are always a select.
    const fixed = (f.validation.options?.length ?? 0) > 0;
    if (fixed && options.length <= 4) {
      return (
        <fieldset className="min-w-0">
          <legend className="field-label">{f.label}</legend>
          <div className="segmented" role="radiogroup" aria-label={f.label}>
            {options.map((o) => (
              <label key={o} className="seg-opt" data-on={value === o || undefined}>
                <input type="radio" name={`${id}-${f.name}`} value={o} checked={value === o} onChange={() => { onChange(o); }} />
                {optionLabel(o, kinds)}
              </label>
            ))}
          </div>
          {problem && <p className="field-hint field-problem">{problem}</p>}
        </fieldset>
      );
    }
    return (
      <div className="min-w-0">
        {label}
        <select
          id={id}
          className="field"
          value={value}
          disabled={options.length === 0}
          aria-invalid={problem ? true : undefined}
          aria-describedby={hintId}
          onChange={(e) => { onChange(e.target.value); }}
        >
          <option value="">{options.length === 0 ? "Paste a kubeconfig to list its contexts" : f.required ? "Choose…" : "Default"}</option>
          {options.map((o) => <option key={o} value={o}>{optionLabel(o, kinds)}</option>)}
        </select>
        <p id={hintId} className={`field-hint${problem ? " field-problem" : ""}`}>
          {problem ?? (options.length > 0 && f.name === "context" ? `${options.length} context${options.length === 1 ? "" : "s"} in this kubeconfig.` : "")}
        </p>
      </div>
    );
  }

  const common = {
    id,
    className: `field${f.validation.format === "text" && !f.multiline ? "" : " mono"}`,
    spellCheck: false,
    autoComplete: "off",
    placeholder,
    value,
    "aria-invalid": problem ? true : undefined,
    "aria-describedby": hintId,
  } as const;
  return (
    <div className="min-w-0">
      {label}
      {f.multiline ? (
        <textarea {...common} className={`${common.className} field-area`} rows={4} onChange={(e) => { onChange(e.target.value); }} />
      ) : (
        <input {...common} onChange={(e) => { onChange(e.target.value); }} />
      )}
      <p id={hintId} className={`field-hint${problem ? " field-problem" : ""}`}>{hint}</p>
    </div>
  );
}

// ---------- account field: one input, live split ----------

export function AccountField({
  f,
  value,
  onChange,
  problem,
  showProblem,
}: {
  f: FieldSchema;
  value: string;
  onChange: (v: string) => void;
  problem: string | undefined;
  showProblem: boolean;
}) {
  const id = useId();
  const parsed = value.trim() ? parseAccount(value) : null;
  const ok = parsed && !isAccountError(parsed) ? parsed : null;
  return (
    <div className="min-w-0">
      <label className="field-label" htmlFor={id}>{f.label}</label>
      <input
        id={id}
        className="field mono"
        spellCheck={false}
        autoComplete="off"
        placeholder={f.placeholder}
        value={value}
        aria-invalid={showProblem && problem ? true : undefined}
        aria-describedby={`${id}-split`}
        onChange={(e) => { onChange(e.target.value); }}
      />
      <div id={`${id}-split`} className="account-split" role="status" aria-live="polite" data-ok={ok ? true : undefined}>
        {ok ? (
          <>
            <span className="split-cell"><span className="m-micro">User</span><span className="mono">{ok.user}</span></span>
            <span className="split-cell"><span className="m-micro">Domain</span><span className="mono">{ok.domain}</span></span>
            <span className="split-cell"><span className="m-micro">Form</span><span>{ok.form === "netbios" ? "NetBIOS" : "UPN"}</span></span>
          </>
        ) : (
          <span className={showProblem && problem ? "text-hot" : "text-text-faint"}>
            {value.trim() && problem ? problem : "Type DOMAIN\\user or user@domain to see how Mooring splits it."}
          </span>
        )}
      </div>
    </div>
  );
}

// ---------- secret field: write-only ----------

export function SecretField({
  f,
  editing,
  stored,
  mode,
  onMode,
  info,
  onTyped,
  onPaste,
  register,
  showProblem,
}: {
  f: FieldSchema;
  editing: boolean;
  stored: boolean;
  mode: SecretMode;
  onMode: (m: SecretMode) => void;
  info: SecretInfo | undefined;
  onTyped: (value: string) => void;
  onPaste?: (text: string) => boolean;
  register: Register;
  showProblem: boolean;
}) {
  const id = useId();
  const open = !editing || mode === "replace";
  const counter = f.validation.maxBytes <= 64;
  const over = (info?.bytes ?? 0) > f.validation.maxBytes;
  const problem = showProblem || over ? info?.problem : null;
  const ref = (el: HTMLInputElement | HTMLTextAreaElement | null) => { register(f.name, el); };
  const props = {
    id,
    ref,
    className: "field mono",
    autoComplete: "new-password",
    spellCheck: false,
    placeholder: editing ? `New ${f.label.toLowerCase()}` : f.placeholder,
    "aria-invalid": problem ? true : undefined,
    "aria-describedby": `${id}-hint`,
    "data-secret": "",
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => { onTyped(e.target.value); },
    onPaste: (e: React.ClipboardEvent) => {
      if (onPaste?.(e.clipboardData.getData("text"))) e.preventDefault();
    },
  };

  return (
    <div className="secret-field min-w-0" data-mode={editing ? mode : "new"}>
      <div className="flex items-baseline gap-2">
        <label className="field-label flex-1" htmlFor={open ? id : undefined} id={`${id}-label`}>
          {f.label}
          {!f.required && <span className="field-opt">optional</span>}
        </label>
        {counter && open && (
          <span className="byte-counter tnum" data-over={over || undefined} aria-live="polite">
            {info?.bytes ?? 0} / {f.validation.maxBytes} bytes
          </span>
        )}
      </div>
      {editing && (
        <div className="secret-state" aria-labelledby={`${id}-label`} role="group">
          <span className="secret-chip" data-on={stored && mode !== "clear" ? true : undefined}>
            {mode === "clear" ? "Will be cleared" : mode === "replace" ? (stored ? "Replacing" : "Setting") : stored ? "Stored" : "Not set"}
          </span>
          {mode !== "replace" && (
            <button
              type="button"
              className="btn btn-ghost"
              aria-label={`${stored ? "Replace" : "Set"} ${f.label.toLowerCase()}`}
              onClick={() => { onMode("replace"); }}
            >
              {stored ? "Replace" : "Set"}
            </button>
          )}
          {stored && mode === "keep" && !f.required && (
            <button
              type="button"
              className="btn btn-ghost btn-danger"
              aria-label={`Clear ${f.label.toLowerCase()}`}
              onClick={() => { onMode("clear"); }}
            >
              Clear
            </button>
          )}
          {mode !== "keep" && (
            <button type="button" className="btn btn-ghost" aria-label={`${stored ? "Keep stored" : "Leave unset"} ${f.label.toLowerCase()}`} onClick={() => { onMode("keep"); }}>
              {stored ? "Keep stored" : "Leave unset"}
            </button>
          )}
        </div>
      )}
      {open &&
        (f.multiline ? (
          <textarea {...props} rows={5} className="field mono field-area field-masked" />
        ) : (
          <input {...props} type="password" />
        ))}
      <p id={`${id}-hint`} className={`field-hint${problem ? " field-problem" : ""}`}>
        {problem ??
          (open
            ? f.multiline
              ? `Paste the ${f.label.toLowerCase()}. Up to ${formatBytes(f.validation.maxBytes)}; it is sealed and never shown again.`
              : counter
                ? "Longer input is rejected, not truncated."
                : ""
            : "")}
      </p>
    </div>
  );
}

// ---------- TOTP ----------

export function OtpSection({
  on,
  onToggle,
  settings,
  onSettings,
  editing,
  stored,
  mode,
  onMode,
  info,
  onTyped,
  register,
  showProblem,
}: {
  on: boolean;
  onToggle: (on: boolean) => void;
  settings: OtpSettings;
  onSettings: (s: OtpSettings) => void;
  editing: boolean;
  stored: boolean;
  mode: SecretMode;
  onMode: (m: SecretMode) => void;
  info: SecretInfo | undefined;
  onTyped: (v: string) => void;
  register: Register;
  showProblem: boolean;
}) {
  const id = useId();
  return (
    <section className="otp-section m-hud" data-tone={on ? "hot" : undefined} aria-labelledby={`${id}-h`}>
      <label className="flex items-center gap-2.5" id={`${id}-h`}>
        <input type="checkbox" className="check" checked={on} onChange={(e) => { onToggle(e.target.checked); }} />
        <span className="m-display text-[length:var(--fs-s)]">Second factor (TOTP)</span>
        {stored && on && <span className="secret-chip ml-auto" data-on>Seed stored</span>}
      </label>
      {on && (
        <div className="mt-3 space-y-3">
          <p className="otp-warning" role="note">
            Keeping the TOTP seed next to the password turns two factors into one: anyone who opens this vault can sign in.
            Prefer an authenticator on another device. Attaching a seed is recorded in the audit log.
          </p>
          <SecretField
            f={{ ...OTP_SEED_SCHEMA, required: true }}
            editing={editing && stored}
            stored={stored}
            mode={editing && stored ? mode : "replace"}
            onMode={onMode}
            info={info}
            onTyped={onTyped}
            register={register}
            showProblem={showProblem}
          />
          <div className="grid grid-cols-3 gap-3">
            <OtpSelect label="Digits" value={String(settings.digits)} options={["6", "8"]} onChange={(v) => { onSettings({ ...settings, digits: v === "8" ? 8 : 6 }); }} />
            <OtpSelect label="Period" value={String(settings.period)} options={["30", "60"]} suffix="s" onChange={(v) => { onSettings({ ...settings, period: v === "60" ? 60 : 30 }); }} />
            <OtpSelect
              label="Algorithm"
              value={settings.algorithm}
              options={["sha1", "sha256", "sha512"]}
              onChange={(v) => { onSettings({ ...settings, algorithm: v === "sha256" || v === "sha512" ? v : "sha1" }); }}
            />
          </div>
        </div>
      )}
    </section>
  );
}

function OtpSelect({ label, value, options, suffix = "", onChange }: { label: string; value: string; options: string[]; suffix?: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <div>
      <label className="field-label" htmlFor={id}>{label}</label>
      <select id={id} className="field" value={value} onChange={(e) => { onChange(e.target.value); }}>
        {options.map((o) => <option key={o} value={o}>{o.toUpperCase()}{suffix}</option>)}
      </select>
    </div>
  );
}

/** Derived, non-secret facts about a stored credential (fingerprint, kubeconfig contexts). */
export function DerivedReadout({ meta }: { meta: CredentialMeta | undefined }) {
  if (!meta) return null;
  const contexts = meta.fields.contexts;
  if (!meta.fingerprint && !Array.isArray(contexts)) return null;
  return (
    <dl className="prop-grid derived">
      {meta.fingerprint && (
        <>
          <dt>Fingerprint</dt>
          <dd><Fingerprint value={meta.fingerprint} /></dd>
        </>
      )}
      {Array.isArray(contexts) && (
        <>
          <dt>Contexts</dt>
          <dd className="mono">{contexts.length ? contexts.join(", ") : "none"}</dd>
        </>
      )}
    </dl>
  );
}

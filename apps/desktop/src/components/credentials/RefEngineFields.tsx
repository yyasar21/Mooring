import { useId, useState } from "react";
import { ENGINE_CAPS, ENGINE_LABEL, ENGINE_TARGET, VAULT_ENGINES, type KindSchema, type VaultEngine } from "../../lib/ipc";
import { kindLabel } from "../../stores/credentials";

/** What each Vault engine does, in one line under the selector (ADR-0026 §1). */
export const ENGINE_HINT: Readonly<Record<VaultEngine, string>> = {
  kv2: "A stored secret in a KV v2 mount, read at every connect.",
  database: "Vault creates a database user and password for each connect. The lease lives as long as the session.",
  ssh_sign: "Vault signs the public half of an SSH key with its SSH CA. Attach it to an SSH connection as its certificate.",
  ssh_otp: "Vault issues a one-time password for one login on one host. The first use consumes it.",
  pki: "Vault issues an X.509 certificate and key for the common name.",
};

/** The engine selector: a native select with full names (not codes). */
export function EngineSelect({ value, onChange, problem, kinds }: {
  value: VaultEngine;
  onChange: (e: VaultEngine) => void;
  problem: string | undefined;
  kinds: KindSchema[];
}) {
  const id = useId();
  return (
    <div className="min-w-0">
      <label className="field-label" htmlFor={id}>Vault engine</label>
      <select id={id} className="field" value={value} aria-describedby={`${id}-hint`} aria-invalid={problem ? true : undefined}
        onChange={(e) => { onChange(e.target.value as VaultEngine); }}>
        {VAULT_ENGINES.map((e) => {
          const target = ENGINE_TARGET[e];
          return <option key={e} value={e}>{ENGINE_LABEL[e]}{target ? ` → ${kindLabel(kinds, target)}` : ""}</option>;
        })}
      </select>
      <p id={`${id}-hint`} className={`field-hint${problem ? " field-problem" : ""}`}>{problem ?? ENGINE_HINT[value]}</p>
    </div>
  );
}

/** A short text input with a label, an optional tag and a hint line. */
export function TextParam({ label, value, onChange, problem, hint, placeholder, optional, mono, inputMode }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  problem: string | undefined;
  hint: string;
  placeholder: string;
  optional?: boolean;
  mono?: boolean;
  inputMode?: "numeric";
}) {
  const id = useId();
  return (
    <div className="min-w-0">
      <label className="field-label" htmlFor={id}>{label}{optional && <span className="field-opt">optional</span>}</label>
      <input id={id} className={`field${mono ? " mono" : ""}`} spellCheck={false} autoComplete="off" placeholder={placeholder} value={value}
        inputMode={inputMode} aria-invalid={problem ? true : undefined} aria-describedby={`${id}-hint`} onChange={(e) => { onChange(e.target.value); }} />
      <p id={`${id}-hint`} className={`field-hint${problem ? " field-problem" : ""}`}>{problem ?? hint}</p>
    </div>
  );
}

/**
 * A list of names as removable chips (`principals`, `alt_names`): Enter or comma adds, Backspace on
 * an empty input removes the last one. At most `ENGINE_CAPS.names` entries.
 */
export function ChipsField({ label, noun, values, onChange, problem, hint, placeholder }: {
  label: string;
  /** Singular, lower case: "principal". */
  noun: string;
  values: string[];
  onChange: (v: string[]) => void;
  problem: string | undefined;
  hint: string;
  placeholder: string;
}) {
  const id = useId();
  const [draft, setDraft] = useState("");
  const full = values.length >= ENGINE_CAPS.names;
  const add = () => {
    const parts = draft.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
    if (parts.length === 0) return;
    const next = [...values];
    for (const p of parts) if (!next.includes(p) && next.length < ENGINE_CAPS.names) next.push(p);
    onChange(next);
    setDraft("");
  };
  return (
    <div className="min-w-0">
      <label className="field-label" htmlFor={id}>{label}<span className="field-opt">optional</span></label>
      <div className="chips-field" data-invalid={problem ? true : undefined}>
        {values.length > 0 && (
          <ul className="chips-list" aria-label={`${label} added`}>
            {values.map((v) => (
              <li key={v} className="chip-item">
                <span className="mono">{v}</span>
                <button type="button" className="chip-remove" aria-label={`Remove ${noun} ${v}`} onClick={() => { onChange(values.filter((x) => x !== v)); }}>×</button>
              </li>
            ))}
          </ul>
        )}
        <input id={id} className="chips-input mono" spellCheck={false} autoComplete="off" disabled={full}
          placeholder={full ? `At most ${ENGINE_CAPS.names}` : placeholder} value={draft} aria-describedby={`${id}-hint`}
          onChange={(e) => { setDraft(e.target.value); }}
          onBlur={add}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") { e.preventDefault(); add(); }
            else if (e.key === "Backspace" && draft === "" && values.length > 0) onChange(values.slice(0, -1));
          }} />
      </div>
      <p id={`${id}-hint`} className={`field-hint${problem ? " field-problem" : ""}`}>{problem ?? hint}</p>
    </div>
  );
}

/** The parameters of the chosen dynamic engine. Values live in the form's `values` and `lists`. */
export function EngineParams({ engine, values, lists, setValue, setList, show }: {
  engine: VaultEngine;
  values: Record<string, string>;
  lists: Record<string, string[]>;
  setValue: (name: string, v: string) => void;
  setList: (name: string, v: string[]) => void;
  show: (name: string) => string | undefined;
}) {
  const ttl = (hint: string) => (
    <TextParam label="TTL (seconds)" optional mono inputMode="numeric" placeholder="role default" value={values.ttl ?? ""}
      onChange={(v) => { setValue("ttl", v); }} problem={show("ttl")} hint={hint} />
  );
  switch (engine) {
    case "database":
      return (
        <p className="ref-engine-note" role="note">
          The role decides the user name, the grants and the lease TTL. Mooring renews the lease at two thirds of its TTL while the
          session is open and revokes it when the session closes or the vault locks. The tab shows the lease.
        </p>
      );
    case "ssh_sign":
      return (
        <div className="cred-grid">
          <div className="col-span-full">
            <ChipsField label="Principals" noun="principal" values={lists.principals ?? []} onChange={(v) => { setList("principals", v); }}
              problem={show("principals")} placeholder="ops, deploy" hint="Logins the certificate is valid for. Empty = the role's default principals." />
          </div>
          {ttl("How long the certificate is valid, at most 86400 (24 h). Empty = the role's TTL.")}
          <p className="ref-engine-note col-span-full" role="note">
            Only the public key goes to Vault; the private key stays in the vault on this device. Pick this reference as the
            certificate of an SSH connection that signs in with an SSH key.
          </p>
        </div>
      );
    case "ssh_otp":
      return (
        <div className="cred-grid">
          <TextParam label="One-time password login" mono placeholder="ops" value={values.username ?? ""} onChange={(v) => { setValue("username", v); }}
            problem={show("username")} hint="The user on the host the password is issued for." />
        </div>
      );
    case "pki":
      return (
        <div className="cred-grid">
          <TextParam label="Common name" mono placeholder="client.example.test" value={values.common_name ?? ""} onChange={(v) => { setValue("common_name", v); }}
            problem={show("common_name")} hint="Required. The role must allow it." />
          {ttl("At most 86400 (24 h). Empty = the role's TTL.")}
          <div className="col-span-full">
            <ChipsField label="Alt names" noun="alt name" values={lists.alt_names ?? []} onChange={(v) => { setList("alt_names", v); }}
              problem={show("alt_names")} placeholder="alt.example.test" hint="Extra subject alternative names, at most 16." />
          </div>
          <p className="ref-engine-note col-span-full" role="note">
            PKI can only be tested for now. No connection signs in with an X.509 certificate from Vault yet, so Test is the only use.
          </p>
        </div>
      );
    default:
      return null;
  }
}

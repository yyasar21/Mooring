import { useState } from "react";
import { KUBE_EXEC_COMMANDS, type CredentialKind, type KubeConnOptions, type KubeExecCommand } from "../../../lib/ipc";
import type { OptionErrors } from "../../../lib/validate.options";
import { Toggle } from "../../settings/Toggle";
import { ReadOnly } from "./controls";

const KiB = 1024;
const MiB = 1024 * KiB;
export const LOG_BYTE_PRESETS = [64 * KiB, 256 * KiB, MiB, 2 * MiB, 4 * MiB, 8 * MiB, 16 * MiB, 32 * MiB, 64 * MiB];
const sizeLabel = (n: number) => (n >= MiB ? `${n / MiB} MiB` : `${n / KiB} KiB`);
const orNull = (s: string) => (s.trim() === "" ? null : s.trim());

/**
 * `KubeConnOptions` (ADR-0014 §3). `server` and the CA come from the kubeconfig, so they are asked
 * for only with a `kube_token` credential. The exec shell is chosen from a fixed allow-list.
 */
export function KubeOptions({ value, errors, onChange, credentialKind, contexts }: {
  value: KubeConnOptions;
  errors: OptionErrors;
  onChange: (v: KubeConnOptions) => void;
  credentialKind: CredentialKind | null;
  /** Context names of the kubeconfig credential (derived by Rust). */
  contexts: string[];
}) {
  const set = (p: Partial<KubeConnOptions>) => { onChange({ ...value, ...p }); };
  const [nsText, setNsText] = useState(value.allowedNamespaces.join(" "));
  const token = credentialKind === "kube_token";
  const presets = LOG_BYTE_PRESETS.includes(value.maxLogBytes) ? LOG_BYTE_PRESETS : [...LOG_BYTE_PRESETS, value.maxLogBytes].sort((a, b) => a - b);

  return (
    <div className="opt-grid">
      <div className="opt-readonly-row">
        <ReadOnly label="Access">Read-only. Mooring never creates, changes or deletes cluster objects.</ReadOnly>
        <ReadOnly label="Secrets">Secrets and ConfigMaps are not shown in this release.</ReadOnly>
      </div>
      {!token && (
        <div>
          <label className="field-label" htmlFor="kube-ctx">Context</label>
          <select id="kube-ctx" className="field mono" value={value.context ?? ""} aria-invalid={errors.context ? true : undefined}
            onChange={(e) => { set({ context: orNull(e.target.value) }); }}>
            <option value="">The kubeconfig's current context</option>
            {[...new Set([...contexts, ...(value.context ? [value.context] : [])])].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <p className="field-hint">One connection per context.</p>
        </div>
      )}
      {token && (
        <>
          <div>
            <label className="field-label" htmlFor="kube-server">API server</label>
            <input id="kube-server" className="field mono" spellCheck={false} placeholder="https://k8s.example.test:6443" value={value.server ?? ""}
              aria-invalid={errors.server ? true : undefined} onChange={(e) => { set({ server: orNull(e.target.value) }); }} />
            <Problem text={errors.server} hint="https only." />
          </div>
          <div>
            <label className="field-label" htmlFor="kube-ca">Cluster CA (PEM)</label>
            <textarea id="kube-ca" className="field mono h-24 resize-y text-[length:var(--fs-12)]" spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----"
              aria-invalid={errors.caPem ? true : undefined} value={value.caPem ?? ""} onChange={(e) => { set({ caPem: e.target.value === "" ? null : e.target.value }); }} />
            <Problem text={errors.caPem} hint="The server certificate must chain to this CA; there is no prompt and no fallback." />
          </div>
        </>
      )}
      {!token && (errors.server || errors.caPem) && <p className="field-hint field-problem" role="alert">{errors.server ?? errors.caPem}</p>}
      <div>
        <label className="field-label" htmlFor="kube-sni">TLS server name<span className="field-opt">optional</span></label>
        <input id="kube-sni" className="field mono" spellCheck={false} placeholder="from the server URL" value={value.tlsServerName ?? ""}
          aria-invalid={errors.tlsServerName ? true : undefined} onChange={(e) => { set({ tlsServerName: orNull(e.target.value) }); }} />
        <Problem text={errors.tlsServerName} />
      </div>
      <div>
        <label className="field-label" htmlFor="kube-ns">Default namespace<span className="field-opt">optional</span></label>
        <input id="kube-ns" className="field mono" spellCheck={false} placeholder="the context's namespace" value={value.namespace ?? ""}
          aria-invalid={errors.namespace ? true : undefined} onChange={(e) => { set({ namespace: orNull(e.target.value) }); }} />
        <Problem text={errors.namespace} />
      </div>
      <div>
        <label className="field-label" htmlFor="kube-allowed">Namespaces to offer<span className="field-opt">optional</span></label>
        <input id="kube-allowed" className="field mono" spellCheck={false} placeholder="payments monitoring" value={nsText}
          aria-invalid={errors.allowedNamespaces ? true : undefined}
          onChange={(e) => { setNsText(e.target.value); set({ allowedNamespaces: e.target.value.split(/[\s,]+/).filter(Boolean) }); }} />
        <Problem text={errors.allowedNamespaces} hint="Shown when the token may not list namespaces." />
      </div>
      <div>
        <label className="field-label" htmlFor="kube-exec">Exec shell</label>
        <select id="kube-exec" className="field mono" value={value.execCommand} aria-invalid={errors.execCommand ? true : undefined}
          onChange={(e) => { set({ execCommand: e.target.value as KubeExecCommand }); }}>
          {KUBE_EXEC_COMMANDS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <p className="field-hint">The default for new exec tabs. Only these shells are allowed; there is no custom command.</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="field-label" htmlFor="kube-tail">Log tail lines</label>
          <input id="kube-tail" className="field mono" inputMode="numeric" value={Number.isFinite(value.logTailLines) ? String(value.logTailLines) : ""}
            aria-invalid={errors.logTailLines ? true : undefined} onChange={(e) => { set({ logTailLines: e.target.value.trim() === "" ? NaN : Number(e.target.value) }); }} />
          <Problem text={errors.logTailLines} hint="1 to 10 000." />
        </div>
        <div>
          <label className="field-label" htmlFor="kube-bytes">Max log bytes</label>
          <select id="kube-bytes" className="field mono" value={value.maxLogBytes} aria-invalid={errors.maxLogBytes ? true : undefined}
            onChange={(e) => { set({ maxLogBytes: Number(e.target.value) }); }}>
            {presets.map((n) => <option key={n} value={n}>{sizeLabel(n)}</option>)}
          </select>
          <Problem text={errors.maxLogBytes} hint="A stream stops at this size." />
        </div>
      </div>
      <Toggle
        checked={value.portForward}
        onChange={(portForward) => { set({ portForward }); }}
        label="Allow pod port-forward"
        hint="Forwards listen on this machine only, unless you expose one explicitly."
      />
    </div>
  );
}

function Problem({ text, hint }: { text: string | undefined; hint?: string }) {
  if (text) return <p className="field-hint field-problem" role="alert">{text}</p>;
  return hint ? <p className="field-hint">{hint}</p> : null;
}

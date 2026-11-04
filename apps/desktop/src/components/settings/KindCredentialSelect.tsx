import type { CredentialKind, CredentialMeta } from "../../lib/ipc";
import { accountSummary } from "../../lib/credentials";
import { useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";

/**
 * Pick a credential of one kind by reference (a secret source's login, the sync access key).
 * Only ids move through here; when none of that kind exists yet, the control offers to create one.
 */
export function KindCredentialSelect({ id, label, kind, value, onChange, problem, hint }: {
  id: string;
  label: string;
  kind: CredentialKind;
  value: string;
  onChange: (id: string) => void;
  problem?: string | undefined;
  hint?: string | undefined;
}) {
  const items = useCredentials((s) => s.items);
  const kindLabel = useCredentials((s) => s.kinds.find((k) => k.kind === kind)?.label ?? kind);
  const show = useUi((s) => s.showCredentials);
  const options = items.filter((c) => c.kind === kind).sort((a, b) => a.name.localeCompare(b.name));
  const detail = (c: CredentialMeta) => {
    const a = accountSummary(c);
    return a ? `${c.name} · ${a}` : c.name;
  };
  return (
    <div className="min-w-0">
      <label className="field-label" htmlFor={id}>{label}</label>
      <div className="flex gap-2">
        <select id={id} className="field min-w-0 flex-1" value={value} aria-invalid={problem ? true : undefined} aria-describedby={`${id}-hint`}
          disabled={options.length === 0} onChange={(e) => { onChange(e.target.value); }}>
          <option value="">{options.length === 0 ? `No ${kindLabel} credential yet` : "Choose…"}</option>
          {options.map((c) => <option key={c.id} value={c.id}>{detail(c)}</option>)}
        </select>
        <button type="button" className="btn" onClick={() => { show({ mode: "new" }); }}>New {kindLabel}…</button>
      </div>
      <p id={`${id}-hint`} className={`field-hint${problem ? " field-problem" : ""}`}>{problem ?? hint}</p>
    </div>
  );
}

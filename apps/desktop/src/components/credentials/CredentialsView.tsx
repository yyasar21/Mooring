import { useMemo, useState } from "react";
import type { CredentialKind, CredentialMeta } from "../../lib/ipc";
import { accountSummary, schemaFor, usedByCount } from "../../lib/credentials";
import { useCredentials } from "../../stores/credentials";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { CredentialEditor, type Seed } from "./CredentialEditor";
import { Fingerprint, KindBadge } from "./fields";
import { KindPicker } from "./KindPicker";

/** Centre view: credential list on the left, picker or schema-driven editor on the right. */
export function CredentialsView() {
  const items = useCredentials((s) => s.items);
  const kinds = useCredentials((s) => s.kinds);
  const pane = useUi((s) => s.credentialPane);
  const show = useUi((s) => s.showCredentials);
  const setView = useUi((s) => s.setView);
  const connections = useTree((s) => s.connections);
  const folders = useTree((s) => s.folders);
  const [filter, setFilter] = useState("");
  // A kind chosen in the picker (with an optional paste seed). Local: a pasted secret never
  // reaches a global store; it is handed to the editor's input and dropped.
  const [draft, setDraft] = useState<{ kind: CredentialKind; seed?: Seed; n: number } | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const defaults = useMemo(() => folders.map((f) => f.defaultCredentialId), [folders]);
  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const sorted = [...items].sort((a, b) => a.name.localeCompare(b.name));
    if (!q) return sorted;
    return sorted.filter((c) => [c.name, c.kind, accountSummary(c), c.fingerprint ?? ""].some((v) => v.toLowerCase().includes(q)));
  }, [items, filter]);

  const selectedId = pane.mode === "edit" ? pane.id : null;
  const meta = items.find((c) => c.id === selectedId);
  const pick = (kind: CredentialKind, seed?: Seed) => {
    setDraft((d) => ({ kind, ...(seed ? { seed } : {}), n: (d?.n ?? 0) + 1 }));
    if (pane.mode !== "new") show({ mode: "new" });
  };
  const closeEditor = () => {
    setDraft(null);
    show({ mode: "none" });
  };
  const saved = (m: CredentialMeta) => {
    setDraft(null);
    show({ mode: "edit", id: m.id });
  };

  return (
    <section aria-label="Credentials" className="cred-view">
      <div className="cred-list-pane">
        <header className="cred-list-head">
          <h1 className="m-display text-[length:var(--fs-l)]">Credentials</h1>
          <span className="m-micro tnum">{items.length}</span>
          <button type="button" className="btn btn-primary ml-auto" onClick={() => { setDraft(null); show({ mode: "new" }); }}>
            New credential
          </button>
        </header>
        <div className="px-3 pb-2">
          <input
            aria-label="Filter credentials"
            className="field"
            placeholder="Filter by name, kind, account or fingerprint"
            value={filter}
            onChange={(e) => { setFilter(e.target.value); }}
          />
        </div>
        <ul aria-label="Stored credentials" className="cred-list">
          {shown.length === 0 && (
            <li className="px-4 py-6 text-text-faint">
              {items.length === 0 ? "No credentials yet. Create one to attach it to folders and connections." : "No credential matches the filter."}
            </li>
          )}
          {shown.map((c) => {
            const used = usedByCount(c.id, connections, defaults);
            return (
              <li key={c.id} className="cred-row" aria-selected={c.id === selectedId} data-selected={c.id === selectedId || undefined}>
                <button type="button" className="cred-row-main" onClick={() => { setConfirm(null); show({ mode: "edit", id: c.id }); }}>
                  <KindBadge kind={c.kind} kinds={kinds} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-text">{c.name}</span>
                    <span className="mono block truncate text-[length:var(--fs-xs)] text-text-muted">
                      {accountSummary(c) || "no account"}
                    </span>
                    {c.fingerprint && (
                      <span className="block truncate text-[length:var(--fs-xs)]"><Fingerprint value={c.fingerprint} /></span>
                    )}
                  </span>
                  <span className="used-by tnum" title={`Used by ${used} connection${used === 1 ? "" : "s"} or folder${used === 1 ? "" : "s"}`}>
                    {used}
                    <span className="m-micro">used</span>
                  </span>
                </button>
                {confirm === c.id ? (
                  <button
                    type="button"
                    className="btn btn-danger"
                    onClick={() =>
                      void useCredentials.getState().remove(c.id).then((ok) => {
                        setConfirm(null);
                        setError(ok ? null : useCredentials.getState().error);
                        if (ok) {
                          if (selectedId === c.id) show({ mode: "none" });
                          void useTree.getState().load();
                        }
                      })
                    }
                  >
                    Confirm delete
                  </button>
                ) : (
                  <button type="button" className="icon-btn cred-del" aria-label={`Delete ${c.name}`} title="Delete" onClick={() => { setConfirm(c.id); }}>
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
                      <path d="M2.5 3.5h7M4.5 3.5V2h3v1.5M3.5 3.5l.5 7h4l.5-7" />
                    </svg>
                  </button>
                )}
              </li>
            );
          })}
        </ul>
        {error && <p role="alert" className="px-4 py-2 text-[length:var(--fs-s)] text-danger">{error}</p>}
        <footer className="cred-list-foot">
          <button type="button" className="btn btn-ghost" onClick={() => { setView("workspace"); }}>
            Back to sessions
          </button>
        </footer>
      </div>

      <div className="cred-detail-pane">
        {pane.mode === "new" && !draft && (
          <KindPicker kinds={kinds} protocol={pane.protocol} onPick={pick} onCancel={closeEditor} />
        )}
        {pane.mode === "new" && draft && (() => {
          const schema = schemaFor(kinds, draft.kind);
          return schema ? (
            <CredentialEditor
              key={`${draft.kind}-${draft.n}`}
              schema={schema}
              kinds={kinds}
              {...(draft.seed ? { seed: draft.seed } : {})}
              onDone={saved}
              onCancel={() => { setDraft(null); }}
              onSwitchKind={pick}
            />
          ) : null;
        })()}
        {pane.mode === "edit" && meta && (() => {
          const schema = schemaFor(kinds, meta.kind);
          return schema ? (
            <CredentialEditor
              key={`${meta.id}-${meta.updatedAt}`}
              schema={schema}
              kinds={kinds}
              meta={meta}
              onDone={saved}
              onCancel={closeEditor}
              onSwitchKind={pick}
            />
          ) : null;
        })()}
        {(pane.mode === "none" || (pane.mode === "edit" && !meta)) && <EmptyDetail />}
      </div>
    </section>
  );
}

function EmptyDetail() {
  return (
    <div className="grid h-full place-items-center p-8 text-center">
      <div className="max-w-[360px]">
        <svg className="reticle mx-auto mb-4" width="64" height="64" viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="1" aria-hidden>
          <circle cx="24" cy="32" r="12" />
          <path d="M36 32h22M50 32v8M56 32v5" />
        </svg>
        <p className="m-display text-[length:var(--fs-l)] text-text-muted">Select a credential</p>
        <p className="mt-2 text-text-faint">
          Pick one on the left to edit it, or create a new one. Secrets are write-only: you can replace or clear them, never read them back.
        </p>
      </div>
    </div>
  );
}

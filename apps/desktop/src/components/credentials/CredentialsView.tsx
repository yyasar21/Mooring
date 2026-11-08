import { useEffect, useRef, useState } from "react";
import { Icon } from "@mooring/ui";
import type { CredentialKind, CredentialMeta } from "../../lib/ipc";
import { schemaFor } from "../../lib/credentials";
import { useCredentials } from "../../stores/credentials";
import { useToasts } from "../../stores/toast";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { CredentialDetail } from "./CredentialDetail";
import { CredentialEditor, type Seed } from "./CredentialEditor";
import { CredentialsTable } from "./CredentialsTable";
import { KindPicker } from "./KindPicker";

/**
 * Credentials (L2): the list as a full-width table, the picked credential's detail page on the
 * right (Overview, Used by, Audit), and the kind picker and editor in a side sheet over it.
 */
export function CredentialsView() {
  const items = useCredentials((s) => s.items);
  const kinds = useCredentials((s) => s.kinds);
  const pane = useUi((s) => s.credentialPane);
  const show = useUi((s) => s.showCredentials);
  // A kind chosen in the picker (with an optional paste seed). Local: a pasted secret never
  // reaches a global store; it is handed to the editor's input and dropped.
  const [draft, setDraft] = useState<{ kind: CredentialKind; seed?: Seed; n: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // N-6: the editor takes the pasted blob on mount; drop it here so it does not stay in state.
  useEffect(() => {
    if (draft?.seed?.paste) setDraft((d) => d && { kind: d.kind, n: d.n, ...(d.seed?.name ? { seed: { name: d.seed.name } } : {}) });
  }, [draft]);

  const selectedId = pane.mode === "edit" || pane.mode === "view" ? pane.id : null;
  const meta = items.find((c) => c.id === selectedId);
  // The form that pressed "New…" (U0): a save or a cancel goes back there with its draft intact.
  const returnTo = pane.mode === "new" ? pane.returnTo : undefined;
  const sheet = pane.mode === "new" || (pane.mode === "edit" && meta !== undefined);
  const pick = (kind: CredentialKind, seed?: Seed) => {
    setDraft((d) => ({ kind, ...(seed ? { seed } : {}), n: (d?.n ?? 0) + 1 }));
    if (pane.mode !== "new") show({ mode: "new" });
  };
  const closeEditor = () => {
    setDraft(null);
    if (returnTo) useUi.getState().resumeConnectionDialog(returnTo, null);
    else show(selectedId ? { mode: "view", id: selectedId } : { mode: "none" });
  };
  const saved = (m: CredentialMeta) => {
    setDraft(null);
    useToasts.getState().push("Credential saved", { detail: m.name });
    if (returnTo) useUi.getState().resumeConnectionDialog(returnTo, m.id);
    else show({ mode: "view", id: m.id });
  };
  const remove = async (id: string): Promise<boolean> => {
    const ok = await useCredentials.getState().remove(id);
    setError(ok ? null : useCredentials.getState().error);
    if (ok) {
      if (selectedId === id) show({ mode: "none" });
      void useTree.getState().load();
    }
    return ok;
  };

  return (
    <section aria-label="Credentials" className="cred-view" data-detail={meta !== undefined || undefined}>
      <div className="cred-list-pane">
        <header className="cred-list-head">
          <h1 className="t-page">Credentials</h1>
          <span className="badge tnum">{items.length}</span>
          <button type="button" className="btn btn-primary ml-auto" onClick={() => { setDraft(null); show({ mode: "new" }); }}>
            <Icon name="plus" size={14} />
            New credential
          </button>
        </header>
        <CredentialsTable
          items={items}
          kinds={kinds}
          selected={selectedId}
          onSelect={(id) => { show({ mode: "view", id }); }}
          onDelete={remove}
        />
        {error && <p role="alert" className="px-4 py-2 text-[length:var(--fs-13)] text-danger">{error}</p>}
      </div>

      {meta ? (
        <div className="cred-detail-pane" aria-hidden={sheet || undefined} inert={sheet}>
          <CredentialDetail
            key={meta.id}
            meta={meta}
            kinds={kinds}
            onEdit={() => { show({ mode: "edit", id: meta.id }); }}
            onDelete={() => remove(meta.id)}
          />
        </div>
      ) : (
        <EmptyDetail />
      )}

      {sheet && (
        <EditorSheet title={pane.mode === "edit" && meta ? `Edit ${meta.name}` : "New credential"} onClose={closeEditor}>
          {pane.mode === "new" && !draft && <KindPicker kinds={kinds} protocol={pane.protocol} onPick={pick} onCancel={closeEditor} />}
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
        </EditorSheet>
      )}
    </section>
  );
}

/**
 * The side sheet that holds the kind picker and the editor (L2). Focus moves in when it opens;
 * Escape and the scrim close it the way Cancel does. Secrets stay in the editor's own inputs.
 */
function EditorSheet({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const first = ref.current?.querySelector<HTMLElement>("input, textarea, select, button");
    first?.focus();
  }, []);
  return (
    <>
      <div className="cred-sheet-scrim" aria-hidden onMouseDown={onClose} />
      <div
        ref={ref}
        role="dialog"
        aria-label={title}
        className="cred-sheet"
        onKeyDown={(e) => {
          if (e.key === "Escape" && !e.defaultPrevented) {
            e.stopPropagation();
            onClose();
          }
        }}
      >
        {children}
      </div>
    </>
  );
}

function EmptyDetail() {
  return (
    <div className="cred-detail-pane cred-empty">
      <div className="empty-state">
        <span className="empty-icon" aria-hidden><Icon name="key" size={24} /></span>
        <p className="empty-title">Select a credential</p>
        <p className="empty-text">
          Pick one in the list to see its details, or create a new one. Secrets are write-only: you can replace or clear them, never read them back.
        </p>
      </div>
    </div>
  );
}

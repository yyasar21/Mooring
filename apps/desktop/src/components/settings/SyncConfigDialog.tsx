import { useState } from "react";
import { SYNC_INTERVAL, type SyncBackend, type SyncConfig } from "../../lib/ipc";
import { normalizeBackend, validateSyncConfig } from "../../lib/validate.secrets";
import { DialogFooter, Modal } from "../dialogs/Modal";
import { KindCredentialSelect } from "./KindCredentialSelect";
import { Toggle } from "./Toggle";

export const BLANK_BACKEND: SyncBackend = { kind: "s3", endpoint: "", region: "", bucket: "", prefix: "mooring", pathStyle: true };

/** The ADR-0017 S3 backend fields, shared by the sync settings and the join screen. */
export function BackendFields({ b, onChange, show, idPrefix = "sy" }: { b: SyncBackend; onChange: (b: SyncBackend) => void; show: (k: string) => string | undefined; idPrefix?: string }) {
  const patch = (p: Partial<SyncBackend>) => { onChange({ ...b, ...p }); };
  const field = (k: keyof SyncBackend, label: string, placeholder: string, hint: string, optional = false) => (
    <div className="min-w-0">
      <label className="field-label" htmlFor={`${idPrefix}-${k}`}>{label}{optional && <span className="field-opt">optional</span>}</label>
      <input id={`${idPrefix}-${k}`} className="field mono" spellCheck={false} placeholder={placeholder} value={String(b[k])}
        aria-invalid={show(k) ? true : undefined} onChange={(e) => { patch({ [k]: e.target.value }); }} />
      <p className={`field-hint${show(k) ? " field-problem" : ""}`}>{show(k) ?? hint}</p>
    </div>
  );
  return (
    <>
      {field("endpoint", "Endpoint", "https://s3.example.test", "https://host[:port] of AWS S3, MinIO or Ceph RGW. The certificate is pinned on first use (a native prompt).")}
      <div className="settings-grid">
        {field("bucket", "Bucket", "team-vault", "Must honour conditional writes; the first save checks.")}
        {field("region", "Region", "us-east-1", "Signing region.")}
      </div>
      <div className="settings-grid">
        {field("prefix", "Prefix", "mooring", "Objects live under <prefix>/<vault id>/.", true)}
        <Toggle checked={b.pathStyle} onChange={(pathStyle) => { patch({ pathStyle }); }} label="Path-style addressing" hint="On for most self-hosted endpoints." />
      </div>
    </>
  );
}

/** Interval control: manual only, or every N minutes within the backend's range. */
export function IntervalField({ value, onChange, problem }: { value: number | null; onChange: (v: number | null) => void; problem: string | undefined }) {
  const [text, setText] = useState(value === null ? String(SYNC_INTERVAL.default) : String(value));
  return (
    <div>
      <span className="field-label">Background sync</span>
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-[length:var(--fs-s)]">
          <input type="radio" name="sy-mode" checked={value === null} onChange={() => { onChange(null); }} />
          Manual only
        </label>
        <label className="flex items-center gap-2 text-[length:var(--fs-s)]">
          <input type="radio" name="sy-mode" checked={value !== null} onChange={() => { onChange(Number(text) || SYNC_INTERVAL.default); }} />
          Every
          <input aria-label="Minutes between syncs" className="field mono tnum settings-minutes" inputMode="numeric" disabled={value === null} value={text}
            aria-invalid={problem ? true : undefined}
            onChange={(e) => { setText(e.target.value); onChange(e.target.value.trim() === "" ? Number.NaN : Number(e.target.value)); }} />
          minutes
        </label>
      </div>
      <p className={`field-hint${problem ? " field-problem" : ""}`}>
        {problem ?? `${SYNC_INTERVAL.min} to ${SYNC_INTERVAL.max} minutes while unlocked, plus a little jitter. The first run after an unlock comes within 30 s.`}
      </p>
    </div>
  );
}

/** Configure ADR-0017 vault sync. Saving probes the storage (and may show the native certificate prompt). */
export function SyncConfigDialog({ current, onClose, onSave }: { current: SyncConfig | null; onClose: () => void; onSave: (c: SyncConfig) => Promise<boolean> }) {
  const [backend, setBackend] = useState<SyncBackend>(current ? { ...current.backend } : BLANK_BACKEND);
  const [credentialId, setCredentialId] = useState(current?.credentialId ?? "");
  const [interval, setInterval] = useState<number | null>(current ? current.intervalMinutes : SYNC_INTERVAL.default);
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const draft: SyncConfig = { backend, credentialId, intervalMinutes: interval };
  const errors = validateSyncConfig(draft);
  const show = (k: string) => (tried ? errors[k] : undefined);

  async function save() {
    setTried(true);
    if (Object.keys(errors).length > 0 || busy) return;
    setBusy(true);
    const ok = await onSave({ ...draft, backend: normalizeBackend(backend) });
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Modal title={current ? "Vault sync settings" : "Set up vault sync"} onClose={onClose} width={560}>
      <form onSubmit={(e) => { e.preventDefault(); void save(); }} autoComplete="off">
        <div className="settings-body">
          <BackendFields b={backend} onChange={setBackend} show={show} />
          <KindCredentialSelect id="sy-cred" label="Access key" kind="s3_access_key" value={credentialId} onChange={setCredentialId} problem={show("credentialId")}
            hint="An S3 access key credential. Its secret stays sealed in the vault and is opened only for each run." />
          <IntervalField value={interval} onChange={setInterval} problem={show("intervalMinutes")} />
        </div>
        <DialogFooter error={tried && Object.keys(errors).length > 0 ? "Fix the highlighted fields." : null}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Checking storage…" : "Save and check"}</button>
        </DialogFooter>
      </form>
    </Modal>
  );
}

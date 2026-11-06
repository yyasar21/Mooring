import type { ImportPreview } from "../../lib/ipc";
import { KIND_SCHEMAS } from "../../lib/ipc.kinds";
import { Toggle } from "../settings/Toggle";
import { groupWarnings, plural, SKIP_REASON_TEXT, WARNING_TEXT } from "./importText";
import type { ImportOptions } from "./useImportWizard";

const kindLabel = (kind: string) => KIND_SCHEMAS.find((k) => k.kind === kind)?.label ?? kind;

/** The six counters of a preview; skipped and warnings light up when non-zero. */
export function PreviewCounts({ preview }: { preview: ImportPreview }) {
  const c = preview.counts;
  const cells: { label: string; value: number; hot: boolean }[] = [
    { label: "folders", value: c.folders, hot: false },
    { label: "connections", value: c.connections, hot: false },
    { label: "credentials", value: c.credentials, hot: false },
    { label: "secrets", value: c.secrets, hot: false },
    { label: "skipped", value: c.skipped, hot: c.skipped > 0 },
    { label: "warnings", value: c.warnings, hot: c.warnings > 0 },
  ];
  return (
    <dl className="imp-counts" role="group" aria-label="Preview counts">
      {cells.map((x) => (
        <div key={x.label} data-hot={x.hot || undefined}>
          <dd className="tnum">{x.value}</dd>
          <dt>{x.label}</dt>
        </div>
      ))}
    </dl>
  );
}

/**
 * The opt-ins of ADR-0019 §3 and owner decision 16; each change re-runs the preview. The key-file
 * switch exists only on the known-location path (`~/.ssh/config`): Rust ignores it for a picked
 * file (F2, review 7 L-41), so a picked file never shows it.
 */
export function PreviewOptions({ preview, secretsPossible, known, options, busy, onOption }: {
  preview: ImportPreview;
  secretsPossible: boolean;
  /** The preview came from a known location, not a picked file. */
  known: boolean;
  options: ImportOptions;
  busy: boolean;
  onOption: (key: keyof ImportOptions, on: boolean) => void;
}) {
  if (!secretsPossible) return null;
  const openssh = preview.format === "openssh";
  if (openssh && !known) return null;
  return (
    <div className="imp-options" data-on={options.plaintextSecrets || options.keyFiles || undefined}>
      {!openssh && (
        <Toggle
          checked={options.plaintextSecrets}
          disabled={busy}
          onChange={(on) => { onOption("plaintextSecrets", on); }}
          label="Import plaintext passwords and keys"
          hint="This export stores secrets in clear text. On, they are sealed into the vault once and the preview runs again; off, each credential asks at connect. The export file stays on disk either way, so delete it when you are done."
        />
      )}
      {openssh && (
        <Toggle
          checked={options.keyFiles}
          disabled={busy}
          onChange={(on) => { onOption("keyFiles", on); }}
          label="Import private keys from ~/.ssh"
          hint="Reads each IdentityFile that is a regular file under ~/.ssh, at most 16 KB and in OpenSSH format, and seals it into an SSH key credential. Off, the connection uses your SSH agent."
        />
      )}
    </div>
  );
}

/** Credentials (name, kind, secret mark), the skipped list with reasons, warnings grouped by code. */
export function PreviewNotes({ preview, excluded, onToggle }: {
  preview: ImportPreview;
  excluded: ReadonlySet<string>;
  onToggle: (key: string, on: boolean) => void;
}) {
  const groups = groupWarnings(preview.warnings);
  return (
    <div className="imp-notes">
      {preview.format === "mremoteng" && (
        <p className="imp-banner" role="note">
          mRemoteNG passwords are never imported. Every credential below asks for its password at connect; re-enter them once and Mooring seals them.
        </p>
      )}
      {preview.credentials.length > 0 && (
        <section aria-label="Credentials">
          <h3 className="imp-note-title">{plural(preview.credentials.length, "credential")}</h3>
          <ul className="imp-creds">
            {preview.credentials.map((c) => (
              <li key={c.key} className="imp-cred" data-off={excluded.has(c.key) || undefined}>
                <label className="imp-row-label">
                  <input type="checkbox" checked={!excluded.has(c.key)} onChange={(e) => { onToggle(c.key, e.target.checked); }} aria-label={c.name} />
                  <span className="imp-row-name">{c.name}</span>
                </label>
                <span className="imp-cred-kind">{kindLabel(c.kind)}</span>
                {c.hasSecret && <span className="imp-secret">has secret</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {preview.skipped.length > 0 && (
        <section aria-label="Skipped">
          <h3 className="imp-note-title">{plural(preview.skipped.length, "item")} skipped</h3>
          <ul className="imp-list">
            {preview.skipped.map((s, i) => (
              <li key={`${s.sourceRef}-${i}`}>
                <span className="mono">{s.sourceRef}</span>
                <span className="imp-reason">{SKIP_REASON_TEXT[s.reason]}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {groups.length > 0 && (
        <section aria-label="Warnings">
          <h3 className="imp-note-title">{plural(preview.warnings.length, "warning")}</h3>
          <ul className="imp-list">
            {groups.map((g) => (
              <li key={g.code}>
                <span className="imp-reason">{WARNING_TEXT[g.code]}</span>
                <span className="mono imp-refs">{g.refs.join(", ")}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

import { useRef, useState } from "react";
import type { CredentialKind, KindSchema, Protocol } from "../../lib/ipc";
import { PROTOCOL_LABEL, detectKind, kindValidFor } from "../../lib/credentials";
import { KindBadge, MatrixStrip } from "./fields";
import { KIND_BLURB, bySection } from "./kindMeta";
import type { Seed } from "./CredentialEditor";

/**
 * Choose what kind of credential to create, grouped by what it signs in to. When opened for a
 * protocol, kinds that cannot sign in there stay visible but disabled, with the reason. Pasting a
 * key, certificate or kubeconfig into the drop zone picks the kind for you.
 */
export function KindPicker({
  kinds,
  protocol,
  onPick,
  onCancel,
}: {
  kinds: KindSchema[];
  protocol?: Protocol | undefined;
  onPick: (kind: CredentialKind, seed?: Seed) => void;
  onCancel: () => void;
}) {
  const [note, setNote] = useState<string | null>(null);
  const zone = useRef<HTMLTextAreaElement>(null);

  return (
    <div className="kind-picker" aria-label="Choose a credential kind" role="group">
      <header className="cred-editor-head">
        <div className="min-w-0 flex-1">
          <h2 className="m-display text-[length:var(--fs-16)]">New credential</h2>
          <p className="text-[length:var(--fs-12)] text-text-muted">
            {protocol ? `Showing what can sign in to ${PROTOCOL_LABEL[protocol]}.` : "Pick what you are storing."}
          </p>
        </div>
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
      </header>

      <div className="cred-editor-body">
        <label className="paste-zone" data-note={note ? true : undefined}>
          <span className="m-micro">Paste to detect</span>
          <textarea
            ref={zone}
            aria-label="Paste a key, certificate or kubeconfig"
            className="paste-input mono"
            rows={2}
            spellCheck={false}
            autoComplete="off"
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----   ·   -----BEGIN CERTIFICATE-----   ·   apiVersion: v1"
            onPaste={(e) => {
              const text = e.clipboardData.getData("text");
              e.preventDefault();
              const d = detectKind(text);
              if (d) onPick(d.kind, { paste: { field: d.field, text } });
              else setNote("Not recognised. Choose the kind below and paste into its field.");
            }}
            onChange={(e) => {
              // Typing here is not supported: drop anything typed so no secret lingers.
              e.target.value = "";
              setNote("Paste with the keyboard or the context menu; typing here is ignored.");
            }}
          />
          <span className="text-[length:var(--fs-12)] text-text-faint">
            {note ?? "OpenSSH or PEM private keys, X.509 certificates and kubeconfig files pick their own kind."}
          </span>
        </label>

        {bySection(kinds).map(({ section, kinds: group }) => (
          <section key={section} aria-label={section}>
            <h3 className="kind-section">{section}</h3>
            <ul className="kind-list">
              {group.map((k) => {
                const compat = protocol ? kindValidFor(k, protocol, k.kind === "sudo_become" ? "become" : "primary") : { ok: true as const };
                const reason = compat.ok ? null : compat.reason;
                return (
                  <li key={k.kind}>
                    <button
                      type="button"
                      className="kind-opt"
                      disabled={!compat.ok}
                      aria-labelledby={`kind-${k.kind}-n`}
                      aria-describedby={`kind-${k.kind}-d`}
                      onClick={() => { onPick(k.kind); }}
                    >
                      <KindBadge kind={k.kind} kinds={kinds} decorative />
                      <span className="min-w-0 flex-1">
                        <span className="kind-opt-name" id={`kind-${k.kind}-n`}>{k.label}</span>
                        <span id={`kind-${k.kind}-d`} className="kind-opt-blurb">
                          {reason ?? KIND_BLURB[k.kind]}
                        </span>
                      </span>
                      {k.supportsOtp && <span className="kind-tag" title="Accepts a TOTP second factor">TOTP</span>}
                      <MatrixStrip schema={k} />
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </div>
    </div>
  );
}

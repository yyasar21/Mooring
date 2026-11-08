import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import type { CertificateProblem } from "../../lib/ipc";
import { useSessions, type PendingPrompt } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { CertificateDetails, PROBLEM } from "./CertificateDetails";

/**
 * The answers `graphical_task::Gate` accepts: `yes` pins the leaf and reconnects; anything else
 * closes with `trust_rejected`. `once` (trust for this connect, nothing stored) is offered for
 * the RD Gateway only (ADR-0027 contract); the server dialog keeps its two answers.
 */
export const CERT_ANSWER = { trust: "yes", once: "once", reject: "no" } as const;

/** Problems that need an explicit "I checked" before Trust is enabled: more than a missing CA. */
const SERIOUS: readonly CertificateProblem[] = ["name_mismatch", "expired", "not_yet_valid"];

const DEFAULT_PORT: Record<string, number> = { rdp: 3389, vnc: 5900 };

/**
 * TOFU dialog for an untrusted RDP/VNC certificate (ADR-0011 §Trust). Never decides on its own:
 * focus starts on Reject, Escape rejects, Tab stays inside the dialog, and a serious problem
 * keeps Trust disabled until the user confirms the fingerprint check.
 */
export function CertificateTrustDialog({ tabId, prompt }: { tabId: string; prompt: PendingPrompt }) {
  const answer = useSessions((s) => s.answer);
  const tab = useSessions((s) => s.tabs.find((t) => t.id === tabId));
  const conn = useTree((s) => s.connections.find((c) => c.id === tab?.connectionId));
  const rejectRef = useRef<HTMLButtonElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const [checked, setChecked] = useState(false);
  const [sent, setSent] = useState(false);
  const cert = prompt.certificate ?? null;
  const problems = cert?.problems ?? [];
  const serious = problems.some((p) => SERIOUS.includes(p));
  const hot = problems.length > 0;
  const protocol = tab?.protocol ?? conn?.protocol ?? "rdp";
  const port = conn?.port ?? DEFAULT_PORT[protocol] ?? 0;
  // ADR-0027: the RD Gateway's own certificate, pinned at the gateway's host:port (`known_rdg_certs`).
  const gateway = prompt.purpose === "gateway_certificate_trust";
  const target = gateway ? (tab?.gateway?.host ?? "RD Gateway") : `${conn?.host ?? "?"}:${String(port)}`;
  const who = gateway ? "RD Gateway" : "host and port";
  const headingId = `cert-h-${tabId}`;
  const bodyId = `cert-b-${tabId}`;

  useEffect(() => {
    setChecked(false);
    setSent(false);
    rejectRef.current?.focus();
  }, [prompt.id]);

  function send(text: string) {
    if (sent) return;
    setSent(true);
    void answer(tabId, text);
  }

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation();
      send(CERT_ANSWER.reject);
      return;
    }
    if (e.key !== "Tab" || !boxRef.current) return;
    const items = [...boxRef.current.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled)")];
    const first = items[0];
    const last = items.at(-1);
    if (!first || !last) return;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="absolute inset-0 z-20 grid place-items-center overflow-y-auto py-4" style={{ background: "var(--scrim)" }}>
      <div
        ref={boxRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={headingId}
        aria-describedby={bodyId}
        className="pop m-hud cert-dialog w-[560px] max-w-[calc(100%-32px)] p-5"
        data-tone={hot ? "hot" : undefined}
        onKeyDown={onKeyDown}
      >
        <p aria-hidden className="m-micro mb-2" style={{ color: hot ? "var(--hot)" : "var(--accent)" }}>
          {hot ? "Untrusted certificate" : "New certificate"}
        </p>
        <h2 id={headingId} className="m-display flex items-center gap-2.5 text-[length:var(--fs-l)]">
          <span aria-hidden className={hot ? "tab-attn" : undefined} />
          {gateway ? "RD Gateway certificate" : "Verify server certificate"}
        </h2>
        <p className="cert-target mono mt-2">
          <span className="chip">{gateway ? "RD Gateway" : protocol.toUpperCase()}</span>
          <span className="select-text">{target}</span>
        </p>
        <p id={bodyId} className="mt-3 text-[length:var(--fs-s)] text-text-muted">
          {gateway && `Before it reaches ${conn?.name ?? "the computer"}, Mooring connects through this RD Gateway. `}
          Mooring has no stored certificate for this {who}{hot ? ", and no trusted authority vouches for this one" : ""}. Compare
          the SHA-256 fingerprint with one you got from the server owner before you trust it.
        </p>

        {problems.length > 0 && (
          <ul className="cert-problems mt-3" aria-label="Problems">
            {problems.map((p) => (
              <li key={p}>
                <span className="chip" data-tone="hot">{PROBLEM[p].label}</span>
                <span>{PROBLEM[p].detail}</span>
              </li>
            ))}
          </ul>
        )}

        {cert ? <CertificateDetails cert={cert} /> : <p className="field-hint field-problem mt-3">The server sent no certificate details.</p>}

        <p className="mt-3 text-[length:var(--fs-xs)] text-text-muted">
          Trust and remember stores this fingerprint for {target} and connects again.{gateway && " Trust once uses it for this connection only and stores nothing."}{" "}
          If the certificate changes later, the connection stops until you remove the stored one in Settings → Trust.
        </p>
        {serious && (
          <label className="cert-ack mt-3">
            <input type="checkbox" checked={checked} onChange={(e) => { setChecked(e.target.checked); }} />
            <span>I compared the fingerprint with the server owner and still want to trust this certificate.</span>
          </label>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button ref={rejectRef} type="button" className="btn" disabled={sent} onClick={() => { send(CERT_ANSWER.reject); }}>
            Reject
          </button>
          {gateway && (
            <button type="button" className="btn" disabled={sent || !cert || (serious && !checked)} onClick={() => { send(CERT_ANSWER.once); }}>
              Trust once
            </button>
          )}
          <button
            type="button"
            className={hot ? "btn btn-danger" : "btn btn-primary"}
            disabled={sent || !cert || (serious && !checked)}
            onClick={() => { send(CERT_ANSWER.trust); }}
          >
            Trust and remember
          </button>
        </div>
      </div>
    </div>
  );
}

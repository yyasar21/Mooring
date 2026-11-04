import type { CertificateInfo, CertificateProblem } from "../../lib/ipc";

const PROBLEM: Record<CertificateProblem, string> = {
  self_signed: "Self-signed",
  unknown_issuer: "Unknown issuer",
  name_mismatch: "Name does not match the host",
  expired: "Expired",
  not_yet_valid: "Not valid yet",
};

/** SHA-256 hex as colon-separated byte pairs, wrapped by the layout. */
export function formatFingerprint(hex: string): string {
  return (hex.toUpperCase().match(/[0-9A-F]{2}/g) ?? []).join(":");
}

/**
 * The leaf of a `certificate_trust` prompt. Subject and issuer are server-controlled text, shown
 * as plain text only; the decision itself never depends on them. The full TOFU dialog is U2.
 */
export function CertificateDetails({ cert }: { cert: CertificateInfo }) {
  return (
    <dl className="cert-details mono mt-3 select-text">
      <dt>Subject</dt>
      <dd>{cert.subject || "(none)"}</dd>
      <dt>Issuer</dt>
      <dd>{cert.issuer || "(none)"}</dd>
      <dt>Valid</dt>
      <dd>
        {cert.notBefore || "?"} → {cert.notAfter || "?"}
      </dd>
      <dt>SHA-256</dt>
      <dd className="cert-fp">{formatFingerprint(cert.sha256) || "(missing)"}</dd>
      {cert.problems.length > 0 && (
        <>
          <dt>Problems</dt>
          <dd className="flex flex-wrap gap-1.5">
            {cert.problems.map((p) => (
              <span key={p} className="chip" data-tone="hot">
                {PROBLEM[p]}
              </span>
            ))}
          </dd>
        </>
      )}
    </dl>
  );
}

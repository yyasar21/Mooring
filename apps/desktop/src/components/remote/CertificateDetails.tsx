import type { CertificateInfo, CertificateProblem } from "../../lib/ipc";

export const PROBLEM: Record<CertificateProblem, { label: string; detail: string }> = {
  self_signed: { label: "Self-signed", detail: "The certificate signs itself; no authority vouches for it." },
  unknown_issuer: { label: "Unknown issuer", detail: "It was issued by an authority this computer does not trust." },
  name_mismatch: { label: "Name does not match the host", detail: "None of its names is the host you are connecting to." },
  expired: { label: "Expired", detail: "Its validity period has ended." },
  not_yet_valid: { label: "Not valid yet", detail: "Its validity period has not started. Check this computer's clock." },
};

/** SHA-256 hex as colon-separated byte pairs. */
export function formatFingerprint(hex: string): string {
  return (hex.toUpperCase().match(/[0-9A-F]{2}/g) ?? []).join(":");
}

/** The fingerprint as groups of four bytes (eight groups for SHA-256), for reading aloud. */
export function fingerprintGroups(hex: string): string[] {
  const bytes = hex.toUpperCase().match(/[0-9A-F]{2}/g) ?? [];
  const out: string[] = [];
  for (let i = 0; i < bytes.length; i += 4) out.push(bytes.slice(i, i + 4).join(":"));
  return out;
}

export type Validity = "valid" | "expired" | "not_yet_valid" | "unknown";

/** Validity at `now` from the RFC 3339 bounds (the `problems` list is Rust's verdict; this is the UI's own check). */
export function validityAt(cert: Pick<CertificateInfo, "notBefore" | "notAfter">, now: number): Validity {
  const from = Date.parse(cert.notBefore);
  const to = Date.parse(cert.notAfter);
  if (Number.isNaN(from) || Number.isNaN(to)) return "unknown";
  if (now > to) return "expired";
  if (now < from) return "not_yet_valid";
  return "valid";
}

function shortDate(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso || "?" : new Date(t).toISOString().replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC");
}

/**
 * The leaf of a `certificate_trust` prompt. Subject, issuer and names are server-controlled text,
 * shown as plain text only; the decision itself never depends on them.
 */
export function CertificateDetails({ cert, now = Date.now() }: { cert: CertificateInfo; now?: number }) {
  const validity = validityAt(cert, now);
  const groups = fingerprintGroups(cert.sha256);
  return (
    <dl className="cert-details mono mt-3 select-text">
      <dt>Subject</dt>
      <dd>{cert.subject || "(none)"}</dd>
      <dt>Issuer</dt>
      <dd>
        {cert.issuer || "(none)"}
        {cert.issuer !== "" && cert.issuer === cert.subject && <span className="cert-note"> · same as subject</span>}
      </dd>
      <dt>Valid</dt>
      <dd data-tone={validity === "expired" || validity === "not_yet_valid" ? "hot" : undefined}>
        <span data-tone={validity === "not_yet_valid" ? "hot" : undefined}>{shortDate(cert.notBefore)}</span>
        {" → "}
        <span data-tone={validity === "expired" ? "hot" : undefined}>{shortDate(cert.notAfter)}</span>
        {validity === "expired" && <span className="cert-flag">expired</span>}
        {validity === "not_yet_valid" && <span className="cert-flag">not valid yet</span>}
      </dd>
      {cert.san.length > 0 && (
        <>
          <dt>Names</dt>
          <dd className="cert-san">
            {cert.san.map((n, i) => (
              <span key={`${n}-${String(i)}`}>{n}</span>
            ))}
          </dd>
        </>
      )}
      <dt>SHA-256</dt>
      <dd className="cert-fp" aria-label={`SHA-256 fingerprint ${formatFingerprint(cert.sha256)}`}>
        {groups.length === 0 ? "(missing)" : groups.map((g, i) => <span key={i}>{g}</span>)}
      </dd>
    </dl>
  );
}

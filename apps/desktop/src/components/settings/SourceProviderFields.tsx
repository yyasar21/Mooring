import { useId } from "react";
import { BWS_PATHS, type SecretSourceKind } from "../../lib/ipc";

/** One line under the provider choice (ADR-0026 §3–§4). */
export const KIND_HINT: Readonly<Record<SecretSourceKind, string>> = {
  vault: "Self-hosted Vault or OpenBao: KV v2 secrets and the database, SSH and PKI engines.",
  onepassword: "A 1Password Connect server on your network, signed in with its Connect token. Connect itself syncs from 1password.com.",
  bitwarden: "Bitwarden Secrets Manager on a self-hosted server, read through the bws command-line tool with a machine access token.",
};

/** The fixed `bws` locations, in the order Mooring tries them when none is chosen. */
export function BwsPathList({ chosen }: { chosen: string | null }) {
  return (
    <ul className="bws-paths" aria-label="Where Mooring looks for bws">
      {BWS_PATHS.map((p) => <li key={p} data-chosen={chosen === p || undefined}>{p}</li>)}
    </ul>
  );
}

/**
 * `options.bwsPath` (ADR-0026 §4, R-SEC-CLI): one of the fixed locations or null = the first that
 * exists. No free path: Rust refuses anything outside the list.
 */
export function BwsPathField({ value, onChange, problem }: { value: string | null; onChange: (v: string | null) => void; problem: string | undefined }) {
  const id = useId();
  return (
    <div className="min-w-0">
      <label className="field-label" htmlFor={id}>bws location</label>
      <select id={id} className="field mono" value={value ?? ""} aria-describedby={`${id}-hint`} aria-invalid={problem ? true : undefined}
        onChange={(e) => { onChange(e.target.value === "" ? null : e.target.value); }}>
        <option value="">First one found</option>
        {BWS_PATHS.map((p) => <option key={p} value={p}>{p}</option>)}
      </select>
      <div id={`${id}-hint`} className={`field-hint${problem ? " field-problem" : ""}`}>
        {problem ?? (
          <>
            <p className="m-0">
              Mooring runs bws only from these locations (no PATH search), with an environment that holds just the access token and the
              server URL. It records the binary's SHA-256 on first use and warns when it changes.
            </p>
            <BwsPathList chosen={value} />
            <p className="m-0 mt-1">bws makes its own TLS connection to the server, so Mooring does not pin that certificate and there is no CA field.</p>
          </>
        )}
      </div>
    </div>
  );
}

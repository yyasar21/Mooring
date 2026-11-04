import { useState } from "react";
import { ipc } from "../../lib/ipc";
import { isValidHost } from "../../lib/validate.exit";
import { describeError } from "../../stores/errors";
import { fingerprintGroups } from "../remote/CertificateDetails";
import { DialogFooter, Modal } from "../dialogs/Modal";
import { Seg } from "../dialogs/options/controls";
import { SettingsCard } from "./Toggle";
import { filterPins, useKnownCerts, type CertProtocol, type PinRow } from "./useKnownCerts";

// TODO(A2-U2): SSH host keys (`known_hosts`) have no list/remove IPC command yet; add a section
// here once rust-core exposes one (ADR-0007 keeps the file hashed like known_*_certs).

const PROTOCOLS: { value: CertProtocol; label: string }[] = [
  { value: "rdp", label: "RDP" },
  { value: "vnc", label: "VNC" },
];

function fingerprintHex(fp: string): string {
  return fp.replace(/^SHA256:/i, "");
}

function shortDate(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toISOString().slice(0, 10);
}

/**
 * Settings → Trust: the certificates the user pinned on first use (ADR-0011 §Trust). Removing one
 * is the only way past a `trust_mismatch` hard stop, so it is confirmed here and audited by Rust.
 * Host names are stored hashed; a pin is labelled only when it matches one of the user's connections.
 */
export function KnownCertsCard() {
  const [protocol, setProtocol] = useState<CertProtocol>("rdp");
  const [query, setQuery] = useState("");
  const [removing, setRemoving] = useState<PinRow | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const { rows, error, reload } = useKnownCerts(protocol);
  const shown = rows ? filterPins(rows, query) : [];

  return (
    <SettingsCard title="Known certificates" kicker="Trust" labelledBy="trust-title">
      <div className="settings-body">
        <p className="field-hint">
          Certificates you trusted for RDP and VNC hosts. If a server is reinstalled and its certificate changes, Mooring stops the
          connection; remove the old entry here after the server owner confirms the new fingerprint.
        </p>
        <div className="flex flex-wrap items-end gap-3">
          <Seg legend="Protocol" name="trust-proto" value={protocol} options={PROTOCOLS} onChange={(p) => { setProtocol(p); setStatus(null); }} />
          <div className="min-w-[160px] flex-1">
            <label className="field-label" htmlFor="trust-q">Search</label>
            <input id="trust-q" type="search" className="field" placeholder="name, host or fingerprint" value={query} onChange={(e) => { setQuery(e.target.value); }} />
          </div>
        </div>

        {error && <p role="alert" className="settings-err">{error}</p>}
        {status && <p role="status" className="settings-ok">{status}</p>}
        {rows === null ? (
          <p className="field-hint" role="status">Loading…</p>
        ) : rows.length === 0 ? (
          !error && (
            <div className="trust-empty">
              <span className="m-micro">No stored certificates</span>
              <span className="field-hint">
                {protocol.toUpperCase()} certificates appear here after you choose “Trust and remember” when connecting.
              </span>
            </div>
          )
        ) : shown.length === 0 ? (
          <p className="field-hint">Nothing matches “{query}”.</p>
        ) : (
          <ul className="trust-list" aria-label={`${protocol.toUpperCase()} certificates`}>
            {shown.map((r) => (
              <li key={`${r.hostHash}-${r.fingerprint}`} className="trust-row">
                <div className="min-w-0">
                  <p className="trust-target">
                    {r.target ? (
                      <span className="mono select-text">{r.target.host}:{r.target.port}</span>
                    ) : (
                      <span className="text-text-muted">Host not in your connections (stored hashed)</span>
                    )}
                    {r.connections.length > 0 && <span className="trust-names">{r.connections.join(", ")}</span>}
                  </p>
                  <p className="trust-fp mono select-text" title={r.fingerprint}>
                    SHA256 {fingerprintGroups(fingerprintHex(r.fingerprint)).join(" ")}
                  </p>
                  <p className="field-hint">First seen {shortDate(r.addedAt)}</p>
                </div>
                <button type="button" className="btn btn-ghost btn-danger" onClick={() => { setRemoving(r); setStatus(null); }}>
                  Remove…
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      {removing && (
        <RemoveDialog
          protocol={protocol}
          row={removing}
          onClose={() => { setRemoving(null); }}
          onRemoved={(target) => {
            setRemoving(null);
            setStatus(`Removed the stored certificate for ${target}. The next connection will ask you to verify it.`);
            reload();
          }}
        />
      )}
    </SettingsCard>
  );
}

/** Confirm a removal. A hashed pin without a matching connection needs the host and port typed in. */
function RemoveDialog({ protocol, row, onClose, onRemoved }: { protocol: CertProtocol; row: PinRow; onClose: () => void; onRemoved: (target: string) => void }) {
  const [host, setHost] = useState(row.target?.host ?? "");
  const [port, setPort] = useState(row.target ? String(row.target.port) : protocol === "rdp" ? "3389" : "5900");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const portNum = Number(port);
  const hostOk = isValidHost(host.trim().replace(/^\[|\]$/g, ""));
  const portOk = /^\d{1,5}$/.test(port) && portNum >= 1 && portNum <= 65535;
  const target = `${host.trim()}:${port}`;

  async function remove() {
    setBusy(true);
    try {
      const { removed } = await ipc.knownCertsRemove({ protocol, host: host.trim(), port: portNum });
      if (removed > 0) onRemoved(target);
      else setError(`No stored ${protocol.toUpperCase()} certificate matches ${target}.`);
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Remove stored certificate" onClose={onClose} width={480}>
      <form onSubmit={(e) => { e.preventDefault(); if (hostOk && portOk) void remove(); }}>
        <div className="space-y-3 px-4 py-4 text-[length:var(--fs-s)]">
          {row.target ? (
            <p>
              Remove the stored {protocol.toUpperCase()} certificate for <span className="mono">{target}</span>
              {row.connections.length > 0 ? ` (${row.connections.join(", ")})` : ""}?
            </p>
          ) : (
            <>
              <p>The host of this certificate is stored hashed. Enter the host and port it belongs to.</p>
              <div className="grid grid-cols-[1fr_96px] gap-3">
                <div>
                  <label className="field-label" htmlFor="trust-host">Host</label>
                  <input id="trust-host" className="field mono" spellCheck={false} placeholder="server.example.test" aria-invalid={host !== "" && !hostOk ? true : undefined} value={host} onChange={(e) => { setHost(e.target.value); setError(null); }} />
                </div>
                <div>
                  <label className="field-label" htmlFor="trust-port">Port</label>
                  <input id="trust-port" className="field mono" inputMode="numeric" aria-invalid={!portOk ? true : undefined} value={port} onChange={(e) => { setPort(e.target.value); setError(null); }} />
                </div>
              </div>
            </>
          )}
          <p className="trust-fp mono">SHA256 {fingerprintGroups(fingerprintHex(row.fingerprint)).join(" ")}</p>
          <p className="settings-warn">
            The next connection to this host will show the certificate prompt again. Only continue if the server owner confirmed the new
            certificate. The removal is recorded in the audit log.
          </p>
        </div>
        <DialogFooter error={error}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-danger" disabled={busy || !hostOk || !portOk}>Remove certificate</button>
        </DialogFooter>
      </form>
    </Modal>
  );
}

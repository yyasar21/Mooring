import { useState } from "react";
import { ipc } from "../../lib/ipc";
import { isValidHost } from "../../lib/validate.exit";
import { describeError } from "../../stores/errors";
import { fingerprintGroups } from "../remote/CertificateDetails";
import { DialogFooter, Modal } from "../dialogs/Modal";
import { Seg } from "../dialogs/options/controls";
import { SettingsCard } from "./Toggle";
import { DEFAULT_PORT, STORE_LABEL, filterPins, useKnownCerts, type CertProtocol, type PinRow } from "./useKnownCerts";

// TODO(A2-U2): SSH host keys (`known_hosts`) have no list/remove IPC command yet; add a section
// here once rust-core exposes one (ADR-0007 keeps the file hashed like known_*_certs).

const PROTOCOLS: { value: CertProtocol; label: string }[] = (["rdp", "vnc", "rdg"] as const).map((value) => ({ value, label: STORE_LABEL[value] }));

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
    <SettingsCard title="Known certificates" labelledBy="trust-title">
      <div className="settings-body">
        <p className="field-hint">
          Certificates you trusted for RDP and VNC hosts and for RD Gateways. If a server is reinstalled and its certificate changes, Mooring stops the
          connection; remove the old entry here after the server owner confirms the new fingerprint. When vault sync brings in a different
          certificate for the same host from another device, both are kept and marked as a conflict: Mooring refuses to connect until you
          remove one.
        </p>
        <p className="field-hint">
          The sync storage certificate is pinned through two system dialogs with three buttons each: “Trust once (this sync only)”, then
          “Trust and remember”. Return and Escape refuse; only a click confirms.
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
                {STORE_LABEL[protocol]} certificates appear here after you choose “Trust and remember” when connecting.
              </span>
            </div>
          )
        ) : shown.length === 0 ? (
          <p className="field-hint">Nothing matches “{query}”.</p>
        ) : (
          <ul className="trust-list" aria-label={`${STORE_LABEL[protocol]} certificates`}>
            {shown.map((r) => (
              <li key={`${r.hostHash}-${r.fingerprint}`} className="trust-row" data-conflict={r.conflict || undefined}>
                <div className="min-w-0">
                  <p className="trust-target">
                    {r.conflict && <span className="trust-conflict">Conflict</span>}
                    {r.target ? (
                      <span className="mono select-text">{r.target.host}:{r.target.port}</span>
                    ) : (
                      <span className="text-text-muted">
                        {protocol === "rdg" ? "RD Gateway (host stored hashed)" : "Host not in your connections (stored hashed)"}
                      </span>
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
  const [port, setPort] = useState(String(row.target ? row.target.port : DEFAULT_PORT[protocol]));
  const store = STORE_LABEL[protocol];
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
      else setError(`No stored ${store} certificate matches ${target}.`);
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Remove stored certificate" onClose={onClose} width={480}>
      <form onSubmit={(e) => { e.preventDefault(); if (hostOk && portOk) void remove(); }}>
        <div className="space-y-3 px-4 py-4 text-[length:var(--fs-13)]">
          {row.target ? (
            <p>
              Remove the stored {store} certificate for <span className="mono">{target}</span>
              {row.connections.length > 0 ? ` (${row.connections.join(", ")})` : ""}?
              {row.conflict && " This host has conflicting stored certificates (synced from another device); removing clears all of them."}
            </p>
          ) : (
            <>
              <p>
                The host of this certificate is stored hashed. Enter the {protocol === "rdg" ? "RD Gateway's host and port (as in the connection's RD Gateway section)" : "host and port it belongs to"}.
              </p>
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

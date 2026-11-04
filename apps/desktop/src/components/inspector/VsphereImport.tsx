import { useState } from "react";
import { ipc, type ConnectionSummary, type VsphereTestResult } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { Modal } from "../dialogs/Modal";

/**
 * Entry point for the vCenter inventory import (ADR-0015). The wizard itself (U2) is not built
 * yet; this dialog says what the import will do and can already test the sign-in.
 */
export function VsphereImport({ connection }: { connection: ConnectionSummary }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<VsphereTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const test = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await ipc.vsphereTest({ connectionId: connection.id }));
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button type="button" className="btn" onClick={() => { setOpen(true); }}>Import inventory…</button>
      {open && (
        <Modal title="Import vCenter inventory" onClose={() => { setOpen(false); }} width={480}>
          <div className="space-y-3 px-4 py-3.5">
            <p className="text-text-muted">
              Mooring will copy the datacenters, clusters, hosts and VMs of <span className="mono">{connection.host}</span> into a
              read-only folder and keep it up to date. Nothing in vCenter is changed by an import.
            </p>
            <p className="field-hint">The import wizard is not available in this build yet. You can already check the sign-in.</p>
            {result && (
              <p role="status" className="mono text-[length:var(--fs-s)]">
                Signed in as {result.user} · vCenter {result.version} (build {result.build})
              </p>
            )}
            {error && <p role="alert" className="field-hint field-problem">{error}</p>}
          </div>
          <div className="flex justify-end gap-2 border-t border-line px-4 py-3">
            <button type="button" className="btn btn-ghost" onClick={() => { setOpen(false); }}>Close</button>
            <button type="button" className="btn" disabled={busy} onClick={() => void test()}>Test sign-in</button>
            <button type="button" className="btn btn-primary" disabled title="Arrives with the import wizard">Start import</button>
          </div>
        </Modal>
      )}
    </>
  );
}

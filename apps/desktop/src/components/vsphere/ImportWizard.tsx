import { useEffect, useState } from "react";
import { ipc, type ConnectionSummary, type Folder, type VsphereSyncReport, type VsphereTestResult } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { folderPath, useTree } from "../../stores/tree";
import { Modal } from "../dialogs/Modal";
import { ReportCounts } from "./ReportCounts";

type Step = "test" | "folder" | "run";

/**
 * Import wizard of ADR-0015 §2: check the sign-in → choose the parent folder → enable sync
 * (`vsphere_sync_enable` creates the read-only root named after the connection and runs the
 * first import). The vault credential never appears here; Rust signs in with it.
 */
export function ImportWizard({ connection, onClose }: { connection: ConnectionSummary; onClose: () => void }) {
  const folders = useTree((s) => s.folders);
  const [step, setStep] = useState<Step>("test");
  const [busy, setBusy] = useState(false);
  const [test, setTest] = useState<VsphereTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [parent, setParent] = useState(connection.folderId);
  const [report, setReport] = useState<{ root: Folder; report: VsphereSyncReport } | null>(null);
  const candidates = folders.filter((f) => !f.syncSource);

  const runTest = async () => {
    setBusy(true);
    setError(null);
    setTest(null);
    try {
      setTest(await ipc.vsphereTest({ connectionId: connection.id }));
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { void runTest(); }, []); // eslint-disable-line react-hooks/exhaustive-deps -- once per open

  const runImport = async () => {
    setBusy(true);
    setError(null);
    try {
      const root = await ipc.vsphereSyncEnable({ connectionId: connection.id, parentFolderId: parent });
      const tree = useTree.getState();
      await tree.load();
      const status = await ipc.vsphereStatus({ connectionId: connection.id });
      setReport({ root, report: status.lastReport ?? { added: 0, changed: 0, missing: 0, deleted: 0, at: new Date().toISOString() } });
      tree.toggle(parent, true);
      tree.toggle(root.id, true);
    } catch (e: unknown) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  const steps: { id: Step; label: string }[] = [{ id: "test", label: "Sign-in" }, { id: "folder", label: "Folder" }, { id: "run", label: "Import" }];
  const parentName = folderPath(folders, parent).join(" / ") || "Top level";

  return (
    <Modal title="Import vCenter inventory" onClose={onClose} width={520}>
      <ol className="vs-steps" aria-label="Import steps">
        {steps.map((s, i) => (
          <li key={s.id} aria-current={step === s.id ? "step" : undefined} data-done={steps.findIndex((x) => x.id === step) > i || undefined}>
            <span className="tnum">{i + 1}</span>
            {s.label}
          </li>
        ))}
      </ol>

      <div className="space-y-3 px-4 py-3.5">
        {step === "test" && (
          <>
            <p className="text-text-muted">
              Mooring signs in to <span className="mono">{connection.host}</span> with the connection's vsphere_user credential and signs out
              again. Nothing in vCenter is changed by the import.
            </p>
            {busy && <p role="status" className="vs-line">Signing in…</p>}
            {test && (
              <p role="status" className="vs-line" data-tone="ok">
                Signed in as <span className="mono">{test.user}</span> · vCenter {test.version} (build {test.build})
              </p>
            )}
            {error && <p role="alert" className="field-hint field-problem">{error}</p>}
          </>
        )}
        {step === "folder" && (
          <>
            <label className="field-label" htmlFor="vs-parent">Put the inventory under</label>
            <select id="vs-parent" className="field" value={parent} onChange={(e) => { setParent(e.target.value); }}>
              {candidates.map((f) => (
                <option key={f.id} value={f.id}>{folderPath(folders, f.id).join(" / ") || f.name}</option>
              ))}
            </select>
            <p className="field-hint">
              A folder named “{connection.name}” is created there with Datacenter → Cluster → Host → VM below it. That subtree is
              read-only: rename, move or delete in vCenter, then refresh. Credentials, tags and options you set on a VM stay yours.
            </p>
          </>
        )}
        {step === "run" && !report && (
          <>
            <dl className="prop-grid">
              <dt>vCenter</dt><dd className="mono">{connection.host}</dd>
              <dt>Signed in</dt><dd className="mono">{test?.user ?? "—"}</dd>
              <dt>Folder</dt><dd>{parentName} / {connection.name}</dd>
            </dl>
            {busy && <p role="status" className="vs-line">Importing the inventory… this can take a minute on a large vCenter.</p>}
            {error && <p role="alert" className="field-hint field-problem">{error}</p>}
          </>
        )}
        {report && (
          <>
            <p role="status" className="vs-line" data-tone="ok">Inventory imported into “{report.root.name}”.</p>
            <ReportCounts report={report.report} />
            <p className="field-hint">Refresh on a schedule or by hand from the vCenter connection's details.</p>
          </>
        )}
      </div>

      <div className="flex justify-end gap-2 border-t border-line px-4 py-3">
        {report ? (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              onClose();
              useTree.getState().select({ kind: "folder", id: report.root.id }); // after close: this dialog lives in the vCenter's inspector
            }}
          >
            Show the folder
          </button>
        ) : (
          <>
            <button type="button" className="btn btn-ghost" disabled={busy} onClick={onClose}>Cancel</button>
            {step === "test" && (
              <>
                {(error || test) && <button type="button" className="btn" disabled={busy} onClick={() => void runTest()}>Test again</button>}
                <button type="button" className="btn btn-primary" disabled={busy || !test} onClick={() => { setStep("folder"); }}>Next</button>
              </>
            )}
            {step === "folder" && (
              <>
                <button type="button" className="btn" onClick={() => { setStep("test"); }}>Back</button>
                <button type="button" className="btn btn-primary" onClick={() => { setStep("run"); }}>Next</button>
              </>
            )}
            {step === "run" && (
              <>
                <button type="button" className="btn" disabled={busy} onClick={() => { setStep("folder"); }}>Back</button>
                <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void runImport()}>
                  {error ? "Try again" : "Start import"}
                </button>
              </>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}

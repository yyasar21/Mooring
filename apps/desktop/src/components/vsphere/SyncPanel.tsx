import { useEffect, useState } from "react";
import { HudLabel } from "@mooring/ui";
import { ipc, type ConnectionSummary, type VsphereConnOptions } from "../../lib/ipc";
import { useConnOptions } from "../../stores/connOptions";
import { describeCode, describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";
import { Modal } from "../dialogs/Modal";
import { ReportCounts } from "./ReportCounts";
import { useVsphereStatus } from "./useVsphere";
import { nextScheduled, relativeTime } from "./vsphere";

/**
 * Inspector section of a vCenter whose inventory is synced (ADR-0015 §2, V2 `vsphere_status`):
 * last refresh, the next scheduled one, the last error and report, "Refresh now" and
 * "Disable sync" (keep the rows as ordinary folders, or remove them).
 */
export function SyncPanel({ vcenter }: { vcenter: ConnectionSummary }) {
  const status = useVsphereStatus(vcenter.id);
  const options = useConnOptions((s) => s.byId[vcenter.id] as VsphereConnOptions | undefined);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ text: string; tone: "ok" | "hot" } | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => { void useConnOptions.getState().load(vcenter.id); }, [vcenter.id]);
  useEffect(() => { setNow(Date.now()); }, [status.value]);

  const refresh = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const r = await ipc.vsphereRefresh({ connectionId: vcenter.id });
      await useTree.getState().load();
      setNotice({ text: `Refreshed: ${String(r.added)} added, ${String(r.changed)} changed, ${String(r.missing)} missing, ${String(r.deleted)} deleted.`, tone: "ok" });
    } catch (e: unknown) {
      setNotice({ text: describeError(e), tone: "hot" });
    } finally {
      setBusy(false);
      await status.reload();
    }
  };

  const disable = async (keep: boolean) => {
    setConfirm(false);
    setBusy(true);
    setNotice(null);
    try {
      await ipc.vsphereSyncDisable({ connectionId: vcenter.id, keep });
      const tree = useTree.getState();
      await tree.load();
      await useConnOptions.getState().load(vcenter.id);
      tree.select({ kind: "connection", id: vcenter.id });
    } catch (e: unknown) {
      setNotice({ text: describeError(e), tone: "hot" });
    } finally {
      setBusy(false);
    }
  };

  const s = status.value;
  const next = s ? nextScheduled(s.lastRefresh, options?.refreshMinutes ?? null, s.scheduled) : null;
  const schedule = !s
    ? "…"
    : options?.refreshMinutes === null
      ? "manual only"
      : !s.scheduled
        ? "paused (vault locked or sync off)"
        : next
          ? `about ${relativeTime(next, now)} (every ${String(options?.refreshMinutes ?? "?")} min)`
          : "soon";

  return (
    <section className="readout-section" aria-label="Inventory sync">
      <HudLabel>Inventory sync</HudLabel>
      <dl className="prop-grid">
        <dt>Refreshed</dt>
        <dd title={s?.lastRefresh ?? undefined}>{status.error ? "unknown" : s ? (s.running ? "running now…" : relativeTime(s.lastRefresh, now)) : "…"}</dd>
        <dt>Next</dt>
        <dd>{schedule}</dd>
        <dt>Last error</dt>
        <dd className={s?.lastError ? "text-danger" : "text-text-faint"} title={s?.lastError ?? undefined} style={{ whiteSpace: "normal", lineHeight: 1.4, paddingTop: 3 }}>
          {status.error ?? (s?.lastError ? describeCode(s.lastError) : "none")}
        </dd>
      </dl>
      {s?.lastReport && <ReportCounts report={s.lastReport} />}
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" className="btn" disabled={busy || s?.running} onClick={() => void refresh()}>
          {busy ? "Refreshing…" : "Refresh now"}
        </button>
        <button type="button" className="btn btn-ghost btn-danger" disabled={busy} onClick={() => { setConfirm(true); }}>
          Disable sync…
        </button>
      </div>
      {notice && (
        <p role={notice.tone === "hot" ? "alert" : "status"} className="vs-line mt-2" data-tone={notice.tone}>
          {notice.text}
        </p>
      )}
      {confirm && (
        <Modal title="Disable inventory sync" onClose={() => { setConfirm(false); }} width={480}>
          <div className="space-y-3 px-4 py-3.5">
            <p className="text-text-muted">
              Mooring stops refreshing the inventory of <span className="mono">{vcenter.host}</span>. What happens to the imported folders and
              VMs?
            </p>
            <ul className="vs-choices">
              <li>
                <strong>Keep</strong> turns them into ordinary folders and connections you can edit, move and delete. Credentials, tags and
                options stay.
              </li>
              <li>
                <strong>Remove</strong> deletes the synced folder with every VM in it, including the credentials and tags you set on them.
              </li>
            </ul>
          </div>
          <div className="flex justify-end gap-2 border-t border-line px-4 py-3">
            <button type="button" className="btn btn-ghost" onClick={() => { setConfirm(false); }}>Cancel</button>
            <button type="button" className="btn" onClick={() => void disable(true)}>Keep as ordinary folders</button>
            <button type="button" className="btn btn-danger" onClick={() => void disable(false)}>Remove folder and VMs</button>
          </div>
        </Modal>
      )}
    </section>
  );
}

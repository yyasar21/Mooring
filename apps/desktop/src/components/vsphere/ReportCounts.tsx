import type { VsphereSyncReport } from "../../lib/ipc";

/** The four counters of a `SyncReport`; `missing` and `deleted` light up when non-zero. */
export function ReportCounts({ report }: { report: VsphereSyncReport }) {
  const cells: { k: keyof Omit<VsphereSyncReport, "at">; label: string; hot: boolean }[] = [
    { k: "added", label: "added", hot: false },
    { k: "changed", label: "changed", hot: false },
    { k: "missing", label: "missing", hot: report.missing > 0 },
    { k: "deleted", label: "deleted", hot: report.deleted > 0 },
  ];
  return (
    <dl className="vs-counts" role="group" aria-label="Last refresh">
      {cells.map((c) => (
        <div key={c.k} data-hot={c.hot || undefined}>
          <dd className="tnum">{report[c.k]}</dd>
          <dt>{c.label}</dt>
        </div>
      ))}
    </dl>
  );
}

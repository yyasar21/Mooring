import { useState } from "react";
import { DataTable, HudLabel, type DataColumn } from "@mooring/ui";
import type { ConnectionSummary } from "../../lib/ipc";
import { folderPath, useTree } from "../../stores/tree";

/**
 * The VMs a vCenter imported (M5), as a sortable grid in the synced root folder's details:
 * name, the folder under the root and whether vCenter still reports it. Enter or a
 * double click selects the VM in the tree, where its power state and consoles are.
 */
export function VmTable({ vcenterId, rootId }: { vcenterId: string; rootId: string }) {
  const connections = useTree((s) => s.connections);
  const folders = useTree((s) => s.folders);
  const [picked, setPicked] = useState<string | null>(null);
  const vms = connections.filter((c) => c.syncSource === vcenterId && c.protocol === "vsphere-console");
  const where = (c: ConnectionSummary) => {
    const path = folderPath(folders, c.folderId);
    const root = folders.find((f) => f.id === rootId)?.name;
    const at = root ? path.indexOf(root) : -1;
    return (at >= 0 ? path.slice(at + 1) : path).join(" / ");
  };
  const columns: DataColumn<ConnectionSummary>[] = [
    { id: "name", header: "Name", cell: (c) => c.name, sortValue: (c) => c.name },
    { id: "where", header: "Folder", className: "text-text-muted", cell: where, sortValue: where },
    {
      id: "state", header: "State", width: "84px", sortValue: (c) => (c.syncState === "missing" ? 1 : 0),
      cell: (c) => (c.syncState === "missing" ? <span className="pill" data-tone="warning">Missing</span> : <span className="pill">Synced</span>),
    },
  ];
  const reveal = (c: ConnectionSummary) => { useTree.getState().select({ kind: "connection", id: c.id }); };

  return (
    <section className="readout-section" aria-label="Imported VMs">
      <HudLabel>Imported VMs <span className="badge tnum">{vms.length}</span></HudLabel>
      <DataTable
        label="Synced VMs"
        className="vs-table"
        columns={columns}
        rows={vms}
        rowKey={(c) => c.id}
        rowLabel={(c) => `${c.name}${c.syncState === "missing" ? ", missing" : ""}`}
        selected={picked}
        onSelect={setPicked}
        onActivate={reveal}
        defaultSort={{ column: "name", dir: "ascending" }}
        empty="The inventory has no VMs yet."
      />
      <p className="field-hint mt-2">Press Enter or double-click a VM to select it in the tree.</p>
    </section>
  );
}

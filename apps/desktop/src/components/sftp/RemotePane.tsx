import { DataTable, type DataColumn } from "@mooring/ui";
import type { SftpEntry } from "../../lib/ipc";
import { formatBytes, formatMode, formatMtime } from "./format";
import type { RemoteDir } from "./useRemoteDir";

const KIND_TAG: Record<SftpEntry["kind"], string> = { dir: "DIR", file: "", symlink: "LNK", other: "?" };

export interface RemoteKeys {
  onOpen: (e: SftpEntry) => void;
  onRename: (e: SftpEntry) => void;
  onRemove: (e: SftpEntry) => void;
}

/** Folders stay above files whichever way a column is sorted by name. */
const folderFirst = (e: SftpEntry) => `${e.kind === "dir" ? "0" : "1"}${e.name}`;

const COLUMNS: DataColumn<SftpEntry>[] = [
  {
    id: "name", header: "Name", sortValue: folderFirst,
    cell: (e) => (
      <span className="sftp-name" data-kind={e.kind}>
        <span className="sftp-kind" aria-hidden>{KIND_TAG[e.kind]}</span>
        <span className="truncate select-text">{e.name}</span>
      </span>
    ),
  },
  { id: "size", header: "Size", width: "96px", numeric: true, className: "mono text-text-muted", cell: (e) => (e.kind === "dir" ? "" : formatBytes(e.size)), sortValue: (e) => (e.kind === "dir" ? -1 : e.size) },
  { id: "mtime", header: "Modified", width: "148px", className: "mono tnum text-text-muted", cell: (e) => formatMtime(e.mtime), sortValue: (e) => e.mtime ?? 0 },
  { id: "mode", header: "Mode", width: "112px", className: "mono text-text-faint", cell: (e) => formatMode(e.kind, e.mode) },
];

const label = (e: SftpEntry) => (e.kind === "dir" ? `${e.name}, folder` : e.kind === "symlink" ? `${e.name}, link` : `${e.name}, ${formatBytes(e.size)}`);

/**
 * The remote listing as a single-select grid (M5). Keys: arrows / Home / End move, Enter opens a
 * folder or downloads a file, Backspace goes up, F2 renames, Delete removes (after a confirm). The
 * row names are the ones the listbox options had ("logs, folder", "README.md, 1.3 KiB").
 */
export function RemotePane({ dir, selected, onSelect, keys }: {
  dir: RemoteDir;
  selected: string | null;
  onSelect: (name: string | null) => void;
  keys: RemoteKeys;
}) {
  return (
    <div className="sftp-remote">
      <DataTable
        label={`Remote files in ${dir.path}`}
        className="sftp-list"
        columns={COLUMNS}
        rows={dir.entries}
        rowKey={(e) => e.name}
        rowLabel={label}
        rowAttrs={(e) => ({ "data-kind": e.kind })}
        selected={selected}
        selectOnFocus
        onSelect={(name) => { onSelect(name); }}
        onActivate={keys.onOpen}
        busy={dir.loading}
        onKeyDown={(ev, e) => {
          if (ev.key === "Backspace") dir.up();
          else if (ev.key === "F2" && e) keys.onRename(e);
          else if (ev.key === "Delete" && e) keys.onRemove(e);
          else return false;
          return true;
        }}
        footer={
          <>
            {dir.entries.length === 0 && !dir.loading && !dir.error && <p className="tool-empty">This folder is empty.</p>}
            {dir.truncated && <p className="sftp-note">The server returned more than 10 000 entries; the list is cut.</p>}
          </>
        }
      />
    </div>
  );
}

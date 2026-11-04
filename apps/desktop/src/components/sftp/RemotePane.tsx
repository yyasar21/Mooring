import { useEffect, useId, useRef } from "react";
import type { SftpEntry } from "../../lib/ipc";
import { formatBytes, formatMode, formatMtime } from "./format";
import type { RemoteDir } from "./useRemoteDir";

const KIND_TAG: Record<SftpEntry["kind"], string> = { dir: "DIR", file: "", symlink: "LNK", other: "?" };

export interface RemoteKeys {
  onOpen: (e: SftpEntry) => void;
  onRename: (e: SftpEntry) => void;
  onRemove: (e: SftpEntry) => void;
}

/**
 * The remote listing as a single-select listbox. Keys: arrows / Home / End move, Enter opens a
 * folder or downloads a file, Backspace goes up, F2 renames, Delete removes (after a confirm).
 */
export function RemotePane({ dir, selected, onSelect, keys }: {
  dir: RemoteDir;
  selected: string | null;
  onSelect: (name: string | null) => void;
  keys: RemoteKeys;
}) {
  const id = useId();
  const listRef = useRef<HTMLDivElement>(null);
  const index = dir.entries.findIndex((e) => e.name === selected);
  const current = index >= 0 ? dir.entries[index] : undefined;
  const optionId = (i: number) => `${id}-opt-${i}`;

  useEffect(() => {
    if (index < 0) return;
    document.getElementById(optionId(index))?.scrollIntoView({ block: "nearest" });
  });

  const move = (to: number) => {
    const e = dir.entries[Math.max(0, Math.min(dir.entries.length - 1, to))];
    if (e) onSelect(e.name);
  };

  const onKeyDown = (ev: React.KeyboardEvent) => {
    switch (ev.key) {
      case "ArrowDown": move(index + 1); break;
      case "ArrowUp": move(index < 0 ? 0 : index - 1); break;
      case "Home": move(0); break;
      case "End": move(dir.entries.length - 1); break;
      case "Enter": if (current) keys.onOpen(current); break;
      case "Backspace": dir.up(); break;
      case "F2": if (current) keys.onRename(current); break;
      case "Delete": if (current) keys.onRemove(current); break;
      default: return;
    }
    ev.preventDefault();
  };

  return (
    <div className="sftp-remote">
      <div className="sftp-row sftp-row-head" aria-hidden>
        <span>Name</span>
        <span className="text-right">Size</span>
        <span>Modified</span>
        <span>Mode</span>
      </div>
      <div className="sftp-list">
        <div
          ref={listRef}
          role="listbox"
          aria-label={`Remote files in ${dir.path}`}
          aria-activedescendant={index >= 0 ? optionId(index) : undefined}
          aria-busy={dir.loading || undefined}
          tabIndex={0}
          className="sftp-listbox"
          onKeyDown={onKeyDown}
          onFocus={() => { if (index < 0 && dir.entries.length > 0) move(0); }}
        >
          {dir.entries.map((e, i) => (
            <div
              key={e.name}
              id={optionId(i)}
              role="option"
              aria-selected={e.name === selected}
              aria-label={e.kind === "dir" ? `${e.name}, folder` : e.kind === "symlink" ? `${e.name}, link` : `${e.name}, ${formatBytes(e.size)}`}
              className="sftp-row"
              data-kind={e.kind}
              onMouseDown={() => { onSelect(e.name); }}
              onDoubleClick={() => { keys.onOpen(e); }}
            >
              <span className="sftp-name">
                <span className="sftp-kind" aria-hidden>{KIND_TAG[e.kind]}</span>
                <span className="truncate select-text">{e.name}</span>
              </span>
              <span className="mono tnum text-right text-text-muted">{e.kind === "dir" ? "" : formatBytes(e.size)}</span>
              <span className="mono tnum text-text-muted">{formatMtime(e.mtime)}</span>
              <span className="mono text-text-faint">{formatMode(e.kind, e.mode)}</span>
            </div>
          ))}
        </div>
        {dir.entries.length === 0 && !dir.loading && !dir.error && <p className="tool-empty">This folder is empty.</p>}
        {dir.truncated && <p className="sftp-note">The server returned more than 10 000 entries; the list is cut.</p>}
      </div>
    </div>
  );
}

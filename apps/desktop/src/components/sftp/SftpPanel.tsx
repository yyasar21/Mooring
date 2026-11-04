import { useState } from "react";
import type { SftpEntry } from "../../lib/ipc";
import { localName, pickDownloadDir, pickUploadFile } from "../../lib/dialog";
import { crumbs, joinRemote } from "../../lib/remotePath";
import { describeError } from "../../stores/errors";
import { useTransfers } from "../../stores/transfers";
import { NameDialog, RemoveDialog } from "./EntryDialogs";
import { RemotePane } from "./RemotePane";
import { TransfersDrawer } from "./TransfersDrawer";
import { useRemoteDir } from "./useRemoteDir";

type Pending = { kind: "mkdir" } | { kind: "rename"; entry: SftpEntry } | { kind: "remove"; entry: SftpEntry } | null;

/** Two-pane SFTP browser of one SSH session, with the transfers drawer underneath. */
export function SftpPanel({ sessionId }: { sessionId: string | null }) {
  if (!sessionId) {
    return (
      <section aria-label="Files" className="tool-panel">
        <p className="tool-empty">The file browser is available once the session is connected.</p>
      </section>
    );
  }
  return <Browser sessionId={sessionId} />;
}

function Browser({ sessionId }: { sessionId: string }) {
  const dir = useRemoteDir(sessionId);
  const download = useTransfers((s) => s.download);
  const upload = useTransfers((s) => s.upload);
  const [selected, setSelected] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending>(null);
  /** Chosen in the OS dialog; kept in memory for this panel only, shown by name. */
  const [downloadDir, setDownloadDir] = useState<string | null>(null);
  const [lastUpload, setLastUpload] = useState<string | null>(null);
  const [pickError, setPickError] = useState<string | null>(null);
  const entry = dir.entries.find((e) => e.name === selected) ?? null;

  const go = (path: string) => { setSelected(null); dir.navigate(path); };

  const chooseDir = async (): Promise<string | null> => {
    try {
      const picked = await pickDownloadDir();
      if (picked) setDownloadDir(picked);
      setPickError(null);
      return picked;
    } catch (e: unknown) {
      setPickError(describeError(e));
      return null;
    }
  };

  const startDownload = async (e: SftpEntry) => {
    if (e.kind !== "file") return;
    const target = downloadDir ?? (await chooseDir());
    if (target) await download(sessionId, joinRemote(dir.path, e.name), target);
  };

  const startUpload = async () => {
    try {
      const file = await pickUploadFile();
      setPickError(null);
      if (!file) return;
      setLastUpload(localName(file));
      await upload(sessionId, file, dir.path);
    } catch (e: unknown) {
      setPickError(describeError(e));
    }
  };

  const open = (e: SftpEntry) => {
    if (e.kind === "dir") go(joinRemote(dir.path, e.name));
    else void startDownload(e);
  };

  return (
    <section aria-label="Files" className="tool-panel">
      <header className="tool-head">
        <h2 className="m-display text-[length:var(--fs-l)]">Files</h2>
        <nav aria-label="Remote path" className="sftp-crumbs">
          {crumbs(dir.path).map(([label, path], i, all) => (
            <button key={path} type="button" className="sftp-crumb" aria-current={i === all.length - 1 ? "location" : undefined} onClick={() => { go(path); }}>
              {label}
            </button>
          ))}
        </nav>
      </header>
      {(dir.error ?? pickError) && (
        <p role="alert" className="tool-error">{dir.error ?? pickError}</p>
      )}

      <div className="sftp-panes">
        <aside aria-label="This computer" className="sftp-local">
          <h3 className="m-micro">This computer</h3>
          <dl className="prop-grid mt-3">
            <dt>Download to</dt>
            <dd className="mono" title={downloadDir ? localName(downloadDir) : undefined}>
              {downloadDir ? localName(downloadDir) : <span className="text-text-faint">not chosen</span>}
            </dd>
            <dt>Last upload</dt>
            <dd className="mono">{lastUpload ?? <span className="text-text-faint">none</span>}</dd>
          </dl>
          <div className="mt-3 flex flex-col gap-2">
            <button type="button" className="btn" onClick={() => void chooseDir()}>Choose download folder…</button>
            <button type="button" className="btn btn-primary" onClick={() => void startUpload()}>Upload a file…</button>
          </div>
          <p className="field-hint mt-3">
            Local files and folders are chosen in the system dialog only. Mooring never browses or types local paths.
          </p>
        </aside>

        <div className="sftp-remote-wrap">
          <div role="toolbar" aria-label="Remote actions" className="sftp-actions">
            <button type="button" className="btn btn-ghost" disabled={dir.path === "/"} onClick={() => { go(joinRemote(dir.path, "..")); }}>Up</button>
            <button type="button" className="btn btn-ghost" onClick={() => void dir.refresh()}>Refresh</button>
            <button type="button" className="btn btn-ghost" onClick={() => { setPending({ kind: "mkdir" }); }}>New folder</button>
            <span className="flex-1" />
            <button type="button" className="btn" disabled={entry?.kind !== "file"} onClick={() => { if (entry) void startDownload(entry); }}>Download</button>
            <button type="button" className="btn btn-ghost" disabled={!entry} onClick={() => { if (entry) setPending({ kind: "rename", entry }); }}>Rename</button>
            <button type="button" className="btn btn-ghost btn-danger" disabled={!entry} onClick={() => { if (entry) setPending({ kind: "remove", entry }); }}>Delete</button>
          </div>
          <RemotePane
            dir={dir}
            selected={selected}
            onSelect={setSelected}
            keys={{
              onOpen: open,
              onRename: (e) => { setPending({ kind: "rename", entry: e }); },
              onRemove: (e) => { setPending({ kind: "remove", entry: e }); },
            }}
          />
        </div>
      </div>

      <TransfersDrawer sessionId={sessionId} />

      {pending?.kind === "mkdir" && (
        <NameDialog title="New folder" label={`Name, in ${dir.path}`} initial="" action="Create"
          onSubmit={(name) => dir.mkdir(name)} onClose={() => { setPending(null); }} />
      )}
      {pending?.kind === "rename" && (
        <NameDialog title="Rename" label="New name" initial={pending.entry.name} action="Rename"
          onSubmit={async (name) => {
            const ok = await dir.rename(pending.entry, name);
            if (ok) setSelected(name);
            return ok;
          }}
          onClose={() => { setPending(null); }} />
      )}
      {pending?.kind === "remove" && (
        <RemoveDialog entry={pending.entry} path={joinRemote(dir.path, pending.entry.name)}
          onConfirm={async () => {
            const ok = await dir.remove(pending.entry);
            if (ok) setSelected(null);
            return ok;
          }}
          onClose={() => { setPending(null); }} />
      )}
    </section>
  );
}

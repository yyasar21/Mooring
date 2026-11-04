import { create } from "zustand";
import { ipc, isIpcError, type LocalPick, type TransferProgress, type TransferState } from "../lib/ipc";
import { baseName, joinRemote } from "../lib/remotePath";
import { describeError } from "./errors";

/** `null`: a transfer re-adopted after an unlock; the backend reports only its progress. */
export type Direction = "download" | "upload" | null;

/** How a download request ended: `exists` = the local file is there; ask, then retry with overwrite. */
export type StartResult = "started" | "exists" | "failed";

export interface Transfer {
  /** Local key: exists before the backend hands out a transfer id. */
  key: string;
  sessionId: string;
  transferId: string | null;
  direction: Direction;
  /** File name only (the pick's display name or the remote base name); local paths never reach the UI. */
  name: string;
  /** Remote side: the file (download) or the target folder (upload). */
  remote: string;
  bytesDone: number;
  bytesTotal: number | null;
  state: "starting" | TransferState;
  error: string | null;
  cancelRequested: boolean;
}

interface TransfersState {
  items: Transfer[];
  /** Bumped when an upload lands, so the remote listing of that session refreshes. */
  landed: Record<string, number>;
  /** `folder` comes from `sftpPickLocal({ mode: "folder" })`. */
  download: (sessionId: string, remote: string, folder: LocalPick, overwrite?: boolean) => Promise<StartResult>;
  /** `file` comes from `sftpPickLocal({ mode: "file" })`. */
  upload: (sessionId: string, file: LocalPick, remoteDir: string) => Promise<StartResult>;
  /** After an unlock: list the session's running transfers (`sftp_transfers`) and show them again. */
  adopt: (sessionId: string) => Promise<void>;
  cancel: (key: string) => Promise<void>;
  dismiss: (key: string) => void;
  clearFinished: (sessionId: string) => void;
  reset: () => void;
}

let seq = 0;

export function isFinished(t: Transfer): boolean {
  return t.state === "done" || t.state === "failed" || t.state === "cancelled";
}

export const useTransfers = create<TransfersState>((set, get) => {
  const patch = (key: string, p: Partial<Transfer>) => {
    set({ items: get().items.map((t) => (t.key === key ? { ...t, ...p } : t)) });
  };

  // A channel keeps its first key; after a lock wiped the rows, the row re-adopted from
  // `sftp_transfers` is found by transfer id instead, so the same channel drives it again.
  const onProgress = (key: string, sessionId: string) => (p: TransferProgress) => {
    const t = get().items.find((x) => x.key === key)
      ?? get().items.find((x) => x.sessionId === sessionId && p.transferId !== "" && x.transferId === p.transferId);
    if (!t || isFinished(t)) return; // late message after a terminal state, or a wiped row: ignore
    patch(t.key, { transferId: p.transferId || t.transferId, bytesDone: p.bytesDone, bytesTotal: p.bytesTotal, state: p.state, error: p.error });
    if (p.state === "done" && t.direction !== "download") {
      set({ landed: { ...get().landed, [t.sessionId]: (get().landed[t.sessionId] ?? 0) + 1 } });
    }
  };

  const nextKey = () => {
    seq += 1;
    return `xfer-${seq}`;
  };

  const start = async (t: Pick<Transfer, "sessionId" | "direction" | "name" | "remote">, run: (h: (p: TransferProgress) => void) => Promise<{ transferId: string }>): Promise<StartResult> => {
    const key = nextKey();
    set({ items: [...get().items, { ...t, key, transferId: null, bytesDone: 0, bytesTotal: null, state: "starting", error: null, cancelRequested: false }] });
    try {
      const { transferId } = await run(onProgress(key, t.sessionId));
      const cur = get().items.find((x) => x.key === key);
      if (!cur) return "started";
      patch(key, { transferId });
      if (cur.cancelRequested && !isFinished(cur)) await ipc.sftpCancel({ sessionId: t.sessionId, transferId }).catch(() => undefined);
      return "started";
    } catch (e: unknown) {
      if (isIpcError(e) && e.code === "sftp.exists") {
        // Not a failure yet: the panel asks "Replace?" and retries with `overwrite: true`.
        set({ items: get().items.filter((x) => x.key !== key) });
        return "exists";
      }
      patch(key, { state: "failed", error: describeError(e) });
      return "failed";
    }
  };

  return {
    items: [],
    landed: {},

    download: (sessionId, remote, folder, overwrite = false) =>
      start({ sessionId, direction: "download", name: baseName(remote), remote }, (onProgress) =>
        ipc.sftpDownload({ sessionId, remote, pick: folder.pickId, ...(overwrite ? { overwrite: true } : {}), onProgress }),
      ),

    upload: (sessionId, file, remoteDir) =>
      start({ sessionId, direction: "upload", name: file.name, remote: remoteDir }, (onProgress) =>
        ipc.sftpUpload({ sessionId, pick: file.pickId, remoteDir, onProgress }),
      ),

    adopt: async (sessionId) => {
      let running: TransferProgress[];
      try {
        running = await ipc.sftpTransfers({ sessionId });
      } catch {
        return; // not connected yet, or gone: nothing to re-adopt
      }
      const known = new Set(get().items.map((x) => x.transferId));
      const fresh: Transfer[] = running
        .filter((p) => p.transferId !== "" && !known.has(p.transferId) && p.state === "running")
        .map((p) => ({
          key: nextKey(), sessionId, transferId: p.transferId, direction: null, name: `Transfer ${p.transferId}`, remote: "",
          bytesDone: p.bytesDone, bytesTotal: p.bytesTotal, state: p.state, error: null, cancelRequested: false,
        }));
      if (fresh.length > 0) set({ items: [...get().items, ...fresh] });
    },

    cancel: async (key) => {
      const t = get().items.find((x) => x.key === key);
      if (!t || isFinished(t)) return;
      if (!t.transferId) {
        patch(key, { cancelRequested: true });
        return;
      }
      try {
        await ipc.sftpCancel({ sessionId: t.sessionId, transferId: t.transferId });
      } catch (e: unknown) {
        patch(key, { error: describeError(e) });
      }
    },

    dismiss: (key) => { set({ items: get().items.filter((t) => t.key !== key || !isFinished(t)) }); },
    clearFinished: (sessionId) => { set({ items: get().items.filter((t) => t.sessionId !== sessionId || !isFinished(t)) }); },
    reset: () => { set({ items: [], landed: {} }); },
  };
});

/** Remote path an upload lands at, for display. */
export function uploadTarget(t: Transfer): string {
  if (t.direction === null) return "";
  return t.direction === "upload" ? joinRemote(t.remote, t.name) : t.remote;
}

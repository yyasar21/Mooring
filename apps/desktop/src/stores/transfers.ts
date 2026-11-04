import { create } from "zustand";
import { ipc, type TransferProgress, type TransferState } from "../lib/ipc";
import { localName } from "../lib/dialog";
import { baseName, joinRemote } from "../lib/remotePath";
import { describeError } from "./errors";

export type Direction = "download" | "upload";

export interface Transfer {
  /** Local key: exists before the backend hands out a transfer id. */
  key: string;
  sessionId: string;
  transferId: string | null;
  direction: Direction;
  /** File name only; full local paths are never kept in state. */
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
  download: (sessionId: string, remote: string, localDir: string) => Promise<void>;
  upload: (sessionId: string, localPath: string, remoteDir: string) => Promise<void>;
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

  const onProgress = (key: string) => (p: TransferProgress) => {
    const t = get().items.find((x) => x.key === key);
    if (!t || isFinished(t)) return; // late message after a terminal state: ignore
    patch(key, { transferId: p.transferId || t.transferId, bytesDone: p.bytesDone, bytesTotal: p.bytesTotal, state: p.state, error: p.error });
    if (p.state === "done" && t.direction === "upload") {
      set({ landed: { ...get().landed, [t.sessionId]: (get().landed[t.sessionId] ?? 0) + 1 } });
    }
  };

  const start = async (t: Omit<Transfer, "key" | "transferId" | "bytesDone" | "bytesTotal" | "state" | "error" | "cancelRequested">, run: (h: (p: TransferProgress) => void) => Promise<{ transferId: string }>) => {
    seq += 1;
    const key = `xfer-${seq}`;
    set({ items: [...get().items, { ...t, key, transferId: null, bytesDone: 0, bytesTotal: null, state: "starting", error: null, cancelRequested: false }] });
    try {
      const { transferId } = await run(onProgress(key));
      const cur = get().items.find((x) => x.key === key);
      if (!cur) return;
      patch(key, { transferId });
      if (cur.cancelRequested && !isFinished(cur)) await ipc.sftpCancel({ sessionId: t.sessionId, transferId }).catch(() => undefined);
    } catch (e: unknown) {
      patch(key, { state: "failed", error: describeError(e) });
    }
  };

  return {
    items: [],
    landed: {},

    download: (sessionId, remote, localDir) =>
      start({ sessionId, direction: "download", name: baseName(remote), remote }, (onProgress) =>
        ipc.sftpDownload({ sessionId, remote, localDir, onProgress }),
      ),

    upload: (sessionId, localPath, remoteDir) =>
      start({ sessionId, direction: "upload", name: localName(localPath), remote: remoteDir }, (onProgress) =>
        ipc.sftpUpload({ sessionId, localPath, remoteDir, onProgress }),
      ),

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
  return t.direction === "upload" ? joinRemote(t.remote, t.name) : t.remote;
}

import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, type SftpEntry } from "../../lib/ipc";
import { joinRemote, normalizeRemote, parentOf } from "../../lib/remotePath";
import { describeError } from "../../stores/errors";
import { useTransfers } from "../../stores/transfers";

export const START_PATH = "/home";

export interface RemoteDir {
  path: string;
  entries: SftpEntry[];
  truncated: boolean;
  loading: boolean;
  error: string | null;
  navigate: (path: string) => void;
  up: () => void;
  refresh: () => Promise<void>;
  /** Each action resolves true on success; failures set `error`. */
  mkdir: (name: string) => Promise<boolean>;
  rename: (from: SftpEntry, toName: string) => Promise<boolean>;
  remove: (entry: SftpEntry) => Promise<boolean>;
  clearError: () => void;
}

/** Folders first, then by name (locale-aware, numeric). */
export function sortEntries(entries: SftpEntry[]): SftpEntry[] {
  const rank = (e: SftpEntry) => (e.kind === "dir" ? 0 : 1);
  return [...entries].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name, undefined, { numeric: true }));
}

/** One remote directory of an SSH session's SFTP channel. */
export function useRemoteDir(sessionId: string | null, initial = START_PATH): RemoteDir {
  const [path, setPath] = useState(initial);
  const [entries, setEntries] = useState<SftpEntry[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const landed = useTransfers((s) => (sessionId ? (s.landed[sessionId] ?? 0) : 0));
  const want = useRef(path);
  want.current = path;

  const load = useCallback(async (p: string) => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const l = await ipc.sftpList({ sessionId, path: p });
      if (want.current !== p) return; // the user navigated on meanwhile
      setEntries(sortEntries(l.entries));
      setTruncated(l.truncated);
      setError(null);
    } catch (e: unknown) {
      if (want.current === p) setError(describeError(e));
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => { void load(path); }, [load, path, landed]);

  const navigate = useCallback((p: string) => {
    let next: string;
    try {
      next = normalizeRemote(p);
    } catch (e: unknown) {
      setError(describeError(e));
      return;
    }
    setEntries([]);
    setPath(next);
  }, []);

  const act = useCallback(async (run: () => Promise<void>) => {
    try {
      await run();
      await load(want.current);
      return true;
    } catch (e: unknown) {
      setError(describeError(e));
      return false;
    }
  }, [load]);

  return {
    path,
    entries,
    truncated,
    loading,
    error,
    navigate,
    up: () => { navigate(parentOf(path)); },
    refresh: () => load(path),
    mkdir: (name) => act(() => (sessionId ? ipc.sftpMkdir({ sessionId, path: joinRemote(path, name) }) : Promise.resolve())),
    rename: (from, toName) =>
      act(() => (sessionId ? ipc.sftpRename({ sessionId, from: joinRemote(path, from.name), to: joinRemote(path, toName) }) : Promise.resolve())),
    remove: (entry) => act(() => (sessionId ? ipc.sftpRemove({ sessionId, path: joinRemote(path, entry.name) }) : Promise.resolve())),
    clearError: () => { setError(null); },
  };
}

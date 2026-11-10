import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, type AuditEntry, type AuditFilterInput } from "../../lib/ipc";
import { describeError } from "../../stores/errors";

export const AUDIT_PAGE = 200;

/**
 * Where the list continues:
 * - `older`: the unfiltered log has older entries ("Load older entries")
 * - `page`: the filtered page was full ("Load more")
 * - `scan`: Rust stopped at its scan cap before a full page ("Continue search")
 */
export type AuditCursor = { kind: "none" } | { kind: "older" | "page" | "scan"; before: number };

export interface AuditLog {
  entries: AuditEntry[];
  cursor: AuditCursor;
  error: string | null;
  /** The newest seq seen in the log (to say how far a filtered search has got). */
  newest: number | null;
  loading: boolean;
  reload: () => Promise<void>;
  more: () => Promise<void>;
}

/**
 * The audit list. Without a filter it pages the bare `audit_tail`, as before. With one, Rust
 * filters the whole log (`auditSearch`), and the list pages with `scannedTo` until `done`.
 * A newer request (a filter change, a reload) drops the answer of an older one.
 */
export function useAuditLog(filter: AuditFilterInput | null): AuditLog {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [cursor, setCursor] = useState<AuditCursor>({ kind: "none" });
  const [error, setError] = useState<string | null>(null);
  const [newest, setNewest] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const token = useRef(0);

  const load = useCallback(async (before: number | null) => {
    token.current += 1;
    const mine = token.current;
    setLoading(true);
    try {
      let page: AuditEntry[];
      let next: AuditCursor;
      if (filter === null) {
        page = await ipc.auditTail({ limit: AUDIT_PAGE, before });
        const last = page.at(-1);
        next = page.length === AUDIT_PAGE && last ? { kind: "older", before: last.seq } : { kind: "none" };
      } else {
        const res = await ipc.auditSearch({ limit: AUDIT_PAGE, before, filter });
        page = res.entries;
        next = res.done || res.scannedTo === null ? { kind: "none" } : { kind: res.entries.length === AUDIT_PAGE ? "page" : "scan", before: res.scannedTo };
      }
      if (mine !== token.current) return;
      setEntries((cur) => (before === null ? page : [...cur, ...page]));
      setCursor(next);
      const top = page[0]?.seq;
      if (top !== undefined) setNewest((n) => (n === null || top > n ? top : n));
      setError(null);
    } catch (e: unknown) {
      if (mine !== token.current) return;
      if (before === null) {
        setEntries([]);
        setCursor({ kind: "none" });
      }
      setError(describeError(e));
    } finally {
      if (mine === token.current) setLoading(false);
    }
  }, [filter]);

  useEffect(() => { void load(null); }, [load]);

  const reload = useCallback(() => load(null), [load]);
  const more = useCallback(() => (cursor.kind === "none" ? Promise.resolve() : load(cursor.before)), [cursor, load]);

  return { entries, cursor, error, newest, loading, reload, more };
}

/** How many of the newest entries a stopped search has tested (seqs are consecutive). */
export function searchedCount(newest: number | null, before: number): number | null {
  return newest === null || before > newest + 1 ? null : newest - before + 1;
}

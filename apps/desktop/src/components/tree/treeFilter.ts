import type { ConnectionSummary, Folder } from "../../lib/ipc";

/** Every whitespace-separated term must appear in the name, host or a tag (case-insensitive). */
export function matchesConnection(c: ConnectionSummary, query: string): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const hay = [c.name, c.host, ...c.tags].join(" ").toLowerCase();
  return terms.every((t) => hay.includes(t));
}

/**
 * The tree narrowed to `query` (design review 2026-11, M3): the matching connections, plus every
 * folder on the way to one of them (and folders whose own name matches, with their subtree), so
 * the result keeps its place in the hierarchy. A blank query returns the input unchanged.
 */
export function filterTree(folders: Folder[], connections: ConnectionSummary[], query: string): { folders: Folder[]; connections: ConnectionSummary[] } {
  const q = query.trim().toLowerCase();
  if (!q) return { folders, connections };
  const byId = new Map(folders.map((f) => [f.id, f]));
  const keep = new Set<string>();
  const keepAncestors = (id: string | null) => {
    let cur = id === null ? undefined : byId.get(id);
    while (cur && !keep.has(cur.id)) {
      keep.add(cur.id);
      cur = cur.parentId === null ? undefined : byId.get(cur.parentId);
    }
  };
  // A folder whose name matches brings its whole subtree.
  const matchedFolders = new Set(folders.filter((f) => f.parentId !== null && q.split(/\s+/).every((t) => f.name.toLowerCase().includes(t))).map((f) => f.id));
  const inMatchedFolder = (folderId: string): boolean => {
    let cur = byId.get(folderId);
    while (cur) {
      if (matchedFolders.has(cur.id)) return true;
      cur = cur.parentId === null ? undefined : byId.get(cur.parentId);
    }
    return false;
  };
  const conns = connections.filter((c) => matchesConnection(c, q) || inMatchedFolder(c.folderId));
  for (const c of conns) keepAncestors(c.folderId);
  for (const f of folders) if (inMatchedFolder(f.id)) keepAncestors(f.id);
  return { folders: folders.filter((f) => keep.has(f.id)), connections: conns };
}

/** Number of connections inside each folder, counting sub-folders (the tree's folder count). */
export function subtreeCounts(folders: Folder[], connections: ConnectionSummary[]): Map<string, number> {
  const parent = new Map(folders.map((f) => [f.id, f.parentId]));
  const counts = new Map<string, number>(folders.map((f) => [f.id, 0]));
  for (const c of connections) {
    let id: string | null | undefined = c.folderId;
    const seen = new Set<string>();
    while (id !== null && id !== undefined && !seen.has(id)) {
      seen.add(id);
      counts.set(id, (counts.get(id) ?? 0) + 1);
      id = parent.get(id);
    }
  }
  return counts;
}

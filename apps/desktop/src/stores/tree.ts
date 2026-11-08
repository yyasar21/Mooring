import { create } from "zustand";
import { ipc, type ConnectionFields, type ConnectionHit, type ConnectionSummary, type Folder } from "../lib/ipc";
import { isIpcError } from "../lib/ipc";
import { describeError, errorText } from "./errors";

/** ADR-0025 refusals whose friendly text says what to do; other codes keep Rust's specific message. */
const FRIENDLY_TREE_CODES: ReadonlySet<string> = new Set(["connection.via_invalid", "connection.in_use_as_hop"]);
const treeError = (e: unknown): string => (isIpcError(e) && FRIENDLY_TREE_CODES.has(e.code) ? describeError(e) : errorText(e));

/** A node id in the tree: folders and connections share one selection. */
export type NodeRef = { kind: "folder"; id: string } | { kind: "connection"; id: string };

/** One visible row of the flattened tree, in display order. */
export interface TreeRow {
  ref: NodeRef;
  depth: number;
  parentId: string | null;
}

interface TreeState {
  folders: Folder[];
  connections: ConnectionSummary[];
  loaded: boolean;
  error: string | null;
  selected: NodeRef | null;
  collapsed: Record<string, true>;

  load: () => Promise<void>;
  reset: () => void;
  select: (ref: NodeRef | null) => void;
  toggle: (folderId: string, open?: boolean) => void;
  createFolder: (parentId: string, name: string) => Promise<Folder | null>;
  renameFolder: (id: string, name: string) => Promise<boolean>;
  moveFolder: (id: string, parentId: string) => Promise<boolean>;
  setFolderCredential: (id: string, credentialId: string | null) => Promise<boolean>;
  deleteFolder: (id: string) => Promise<boolean>;
  createConnection: (fields: ConnectionFields) => Promise<ConnectionSummary | null>;
  updateConnection: (id: string, fields: ConnectionFields) => Promise<ConnectionSummary | null>;
  renameConnection: (id: string, name: string) => Promise<boolean>;
  moveConnection: (id: string, folderId: string) => Promise<boolean>;
  deleteConnection: (id: string) => Promise<boolean>;
  search: (query: string, limit?: number) => Promise<ConnectionHit[]>;
}

const EMPTY = {
  folders: [] as Folder[],
  connections: [] as ConnectionSummary[],
  loaded: false,
  error: null,
  selected: null,
  collapsed: {} as Record<string, true>,
};

export const useTree = create<TreeState>((set, get) => {
  /** Run a mutation; on success reload (inheritance can change anywhere below a folder). */
  async function mutate<T>(fn: () => Promise<T>): Promise<T | null> {
    try {
      const out = await fn();
      await get().load();
      return out;
    } catch (e: unknown) {
      set({ error: treeError(e) });
      return null;
    }
  }

  return {
    ...EMPTY,

    load: async () => {
      try {
        const { folders, connections } = await ipc.treeList();
        set({ folders, connections, loaded: true, error: null });
      } catch (e: unknown) {
        set({ error: errorText(e) });
      }
    },

    reset: () => { set({ ...EMPTY, collapsed: {} }); },
    select: (ref) => { set({ selected: ref }); },

    toggle: (folderId, open) => {
      const cur = get().collapsed;
      const next = open ?? folderId in cur;
      const collapsed: Record<string, true> = Object.fromEntries(
        Object.entries(cur).filter(([k]) => k !== folderId),
      );
      if (!next) collapsed[folderId] = true;
      set({ collapsed });
    },

    createFolder: (parentId, name) => mutate(() => ipc.folderCreate({ parentId, name })),
    renameFolder: async (id, name) => (await mutate(() => ipc.folderRename({ id, name }))) !== null,
    moveFolder: async (id, parentId) => (await mutate(() => ipc.folderMove({ id, parentId }))) !== null,
    setFolderCredential: async (id, credentialId) =>
      (await mutate(() => ipc.folderSetDefaultCredential({ id, credentialId }))) !== null,
    deleteFolder: async (id) => {
      const ok = (await mutate(async () => { await ipc.folderDelete({ id }); return true; })) === true;
      if (ok && get().selected?.id === id) set({ selected: null });
      return ok;
    },

    createConnection: (fields) => mutate(() => ipc.connectionCreate(fields)),
    updateConnection: (id, fields) => mutate(() => ipc.connectionUpdate({ id, ...fields })),
    renameConnection: async (id, name) => {
      const c = get().connections.find((x) => x.id === id);
      if (!c) return false;
      return (await mutate(() => ipc.connectionUpdate({ ...connectionFields(c), id, name }))) !== null;
    },
    moveConnection: async (id, folderId) => (await mutate(() => ipc.connectionMove({ id, folderId }))) !== null,
    deleteConnection: async (id) => {
      const ok = (await mutate(async () => { await ipc.connectionDelete({ id }); return true; })) === true;
      if (ok && get().selected?.id === id) set({ selected: null });
      return ok;
    },

    search: async (query, limit = 30) => {
      try {
        return await ipc.connectionSearch({ query, limit });
      } catch (e: unknown) {
        set({ error: errorText(e) });
        return [];
      }
    },
  };
});

/** The editable fields of a connection, as `connection_update` takes them. */
export function connectionFields(c: ConnectionSummary): ConnectionFields {
  return {
    folderId: c.folderId,
    name: c.name,
    protocol: c.protocol,
    host: c.host,
    port: c.port,
    credentialId: c.credentialId,
    usernameOverride: c.usernameOverride,
    domainOverride: c.domainOverride,
    gatewayCredentialId: c.gatewayCredentialId,
    becomeCredentialId: c.becomeCredentialId,
    tags: [...c.tags],
  };
}

/** Connections that use `id` as a jump host (ADR-0025): a delete of `id` is refused while any exist. */
export function hopUsers(connections: ConnectionSummary[], id: string): ConnectionSummary[] {
  return connections.filter((c) => c.id !== id && (c.via ?? []).includes(id));
}

/** "bastion01 → bastion02" for a connection's chain; null when it connects directly. */
export function viaNames(connections: ConnectionSummary[], c: ConnectionSummary): string | null {
  const via = c.via ?? [];
  if (via.length === 0) return null;
  return via.map((id) => connections.find((x) => x.id === id)?.name ?? "missing jump host").join(" → ");
}

/** Root folder (parentId null). */
export function rootFolder(folders: Folder[]): Folder | undefined {
  return folders.find((f) => f.parentId === null);
}

/** Flatten the tree into visible rows: folders first (by sort, name), then connections by name. */
export function visibleRows(folders: Folder[], connections: ConnectionSummary[], collapsed: Record<string, true>): TreeRow[] {
  const root = rootFolder(folders);
  if (!root) return [];
  const rows: TreeRow[] = [];
  const walk = (folder: Folder, depth: number) => {
    rows.push({ ref: { kind: "folder", id: folder.id }, depth, parentId: folder.parentId });
    if (folder.id in collapsed) return;
    folders
      .filter((f) => f.parentId === folder.id)
      .sort((a, b) => a.sort - b.sort || a.name.localeCompare(b.name))
      .forEach((f) => { walk(f, depth + 1); });
    connections
      .filter((c) => c.folderId === folder.id)
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach((c) => rows.push({ ref: { kind: "connection", id: c.id }, depth: depth + 1, parentId: folder.id }));
  };
  walk(root, 0);
  return rows;
}

/** Folder path from the root, e.g. ["Production", "Web tier"] (root excluded). */
export function folderPath(folders: readonly Folder[], id: string | null | undefined): string[] {
  const out: string[] = [];
  const seen = new Set<string>(); // a cycle in hostile synced data must not hang the UI
  let cur = folders.find((f) => f.id === id);
  while (cur && cur.parentId !== null && !seen.has(cur.id)) {
    seen.add(cur.id);
    out.unshift(cur.name);
    const parent = cur.parentId;
    cur = folders.find((f) => f.id === parent);
  }
  return out;
}
